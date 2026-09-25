using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    public class SafeBrowsingService : ISafeBrowsingService
    {
        private readonly HttpClient _httpClient;
        private readonly ISecuritySettingsService _settingsService;
        private readonly ConcurrentDictionary<string, SafeBrowsingMatch?> _urlCache = new(StringComparer.OrdinalIgnoreCase);

        // Official Google Safe Browsing Malware Test URL
        public const string MalwareTestUrl = "http://testsafebrowsing.appspot.com/s/malware.html";

        private static readonly Regex UrlRegex = new(
            @"https?://[a-zA-Z0-9\-\.]+(?::[0-9]+)?(?:/[^\s<>'""\)\}\]]*)?",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public SafeBrowsingService(HttpClient httpClient, ISecuritySettingsService settingsService)
        {
            _httpClient = httpClient;
            _settingsService = settingsService;
            _httpClient.Timeout = TimeSpan.FromSeconds(15);
        }

        public bool IsEnabledAndConfigured()
        {
            var s = _settingsService.GetSettings();
            return s.GoogleSafeBrowsingEnabled && !string.IsNullOrWhiteSpace(s.GoogleSafeBrowsingApiKey);
        }

        public List<string> ExtractUrlsFromContent(byte[] content)
        {
            if (content == null || content.Length == 0) return new List<string>();

            // Inspect up to first 256KB of text
            int inspectLen = Math.Min(content.Length, 256 * 1024);
            string text;
            try
            {
                text = Encoding.UTF8.GetString(content, 0, inspectLen);
            }
            catch
            {
                text = Encoding.ASCII.GetString(content, 0, inspectLen);
            }

            var matches = UrlRegex.Matches(text);
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Match m in matches)
            {
                var clean = m.Value.TrimEnd('.', ',', ';', ':', ')', ']', '}', '\'', '"');
                if (Uri.TryCreate(clean, UriKind.Absolute, out var uri))
                {
                    // Ignore local addresses
                    if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                        uri.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    result.Add(clean);
                }
            }

            return result.Take(25).ToList();
        }

        public async Task<SafeBrowsingReport> CheckUrlsAsync(IEnumerable<string> urls, CancellationToken cancellationToken = default)
        {
            var report = new SafeBrowsingReport();
            var distinctUrls = urls?.Distinct(StringComparer.OrdinalIgnoreCase).ToList() ?? new List<string>();
            report.UrlsChecked = distinctUrls;

            if (distinctUrls.Count == 0) return report;

            var settings = _settingsService.GetSettings();
            if (!settings.GoogleSafeBrowsingEnabled || string.IsNullOrWhiteSpace(settings.GoogleSafeBrowsingApiKey))
            {
                return report;
            }

            var toQuery = new List<string>();
            foreach (var url in distinctUrls)
            {
                if (_urlCache.TryGetValue(url, out var cachedMatch))
                {
                    if (cachedMatch != null) report.Matches.Add(cachedMatch);
                }
                else
                {
                    toQuery.Add(url);
                }
            }

            if (toQuery.Count == 0) return report;

            try
            {
                var payload = new
                {
                    client = new
                    {
                        clientId = "FileAnomalyScanner",
                        clientVersion = "1.0.0"
                    },
                    threatInfo = new
                    {
                        threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION" },
                        platformTypes = new[] { "ANY_PLATFORM" },
                        threatEntryTypes = new[] { "URL" },
                        threatEntries = toQuery.Select(u => new { url = u }).ToArray()
                    }
                };

                var jsonBody = JsonSerializer.Serialize(payload);
                var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                var urlEndpoint = $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GoogleSafeBrowsingApiKey}";
                using var response = await _httpClient.PostAsync(urlEndpoint, content, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    var errText = await response.Content.ReadAsStringAsync(cancellationToken);
                    report.ErrorMessage = $"Google Safe Browsing returned HTTP {(int)response.StatusCode}: {errText}";
                    return report;
                }

                var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(responseJson);

                var matchedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (doc.RootElement.TryGetProperty("matches", out var matchesArr) && matchesArr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var m in matchesArr.EnumerateArray())
                    {
                        var threatType = m.TryGetProperty("threatType", out var tt) ? tt.GetString() ?? "MALWARE" : "MALWARE";
                        var platformType = m.TryGetProperty("platformType", out var pt) ? pt.GetString() ?? "ANY_PLATFORM" : "ANY_PLATFORM";
                        var threatUrl = m.TryGetProperty("threat", out var thr) && thr.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";

                        if (!string.IsNullOrWhiteSpace(threatUrl))
                        {
                            var matchObj = new SafeBrowsingMatch
                            {
                                Url = threatUrl,
                                ThreatType = threatType,
                                PlatformType = platformType
                            };
                            report.Matches.Add(matchObj);
                            _urlCache[threatUrl] = matchObj;
                            matchedUrls.Add(threatUrl);
                        }
                    }
                }

                // Cache clean URLs as null
                foreach (var queried in toQuery)
                {
                    if (!matchedUrls.Contains(queried))
                    {
                        _urlCache[queried] = null;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                report.ErrorMessage = $"Google Safe Browsing query exception: {ex.Message}";
            }

            return report;
        }

        public async Task<TestApiResponse> TestConnectionAsync(string? testApiKey = null, CancellationToken cancellationToken = default)
        {
            var key = !string.IsNullOrWhiteSpace(testApiKey) ? testApiKey.Trim() : _settingsService.GetSettings().GoogleSafeBrowsingApiKey;

            if (string.IsNullOrWhiteSpace(key))
            {
                return new TestApiResponse
                {
                    Success = false,
                    Message = "Please provide a Google Safe Browsing API key to test."
                };
            }

            try
            {
                var payload = new
                {
                    client = new
                    {
                        clientId = "FileAnomalyScanner",
                        clientVersion = "1.0.0"
                    },
                    threatInfo = new
                    {
                        threatTypes = new[] { "MALWARE" },
                        platformTypes = new[] { "ANY_PLATFORM" },
                        threatEntryTypes = new[] { "URL" },
                        threatEntries = new[] { new { url = MalwareTestUrl } }
                    }
                };

                var jsonBody = JsonSerializer.Serialize(payload);
                var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                var urlEndpoint = $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}";
                using var response = await _httpClient.PostAsync(urlEndpoint, content, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                    using var doc = JsonDocument.Parse(responseJson);

                    bool verifiedMatch = false;
                    if (doc.RootElement.TryGetProperty("matches", out var matchesArr) && matchesArr.GetArrayLength() > 0)
                    {
                        verifiedMatch = true;
                    }

                    return new TestApiResponse
                    {
                        Success = true,
                        Message = verifiedMatch
                            ? "Google Safe Browsing API connection verified successfully! Test malware URL triggered positive match."
                            : "Google Safe Browsing API key accepted and online.",
                        Details = "Verified via threatMatches:find endpoint."
                    };
                }

                var errText = await response.Content.ReadAsStringAsync(cancellationToken);
                return new TestApiResponse
                {
                    Success = false,
                    Message = $"Safe Browsing validation failed: HTTP {(int)response.StatusCode}. Verify your API key and that 'Safe Browsing APIs' are enabled in Google Cloud Console."
                };
            }
            catch (Exception ex)
            {
                return new TestApiResponse
                {
                    Success = false,
                    Message = $"Network or connection error while contacting Google Safe Browsing: {ex.Message}"
                };
            }
        }
    }
}
