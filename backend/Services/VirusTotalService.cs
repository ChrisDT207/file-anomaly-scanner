using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    public class VirusTotalService : IVirusTotalService
    {
        private readonly HttpClient _httpClient;
        private readonly ISecuritySettingsService _settingsService;
        private readonly ConcurrentDictionary<string, VirusTotalReport> _cache = new(StringComparer.OrdinalIgnoreCase);

        // Standard EICAR Antivirus Test File SHA-256 for testing connection
        public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        public VirusTotalService(HttpClient httpClient, ISecuritySettingsService settingsService)
        {
            _httpClient = httpClient;
            _settingsService = settingsService;
            _httpClient.Timeout = TimeSpan.FromSeconds(15);
        }

        public bool IsEnabledAndConfigured()
        {
            var s = _settingsService.GetSettings();
            return s.VirusTotalEnabled && !string.IsNullOrWhiteSpace(s.VirusTotalApiKey);
        }

        public async Task<VirusTotalReport> LookupFileHashAsync(string sha256, CancellationToken cancellationToken = default)
        {
            var cleanHash = sha256.Trim().ToLowerInvariant();
            var permalink = $"https://www.virustotal.com/gui/file/{cleanHash}";

            if (_cache.TryGetValue(cleanHash, out var cached))
            {
                return cached;
            }

            var settings = _settingsService.GetSettings();
            if (!settings.VirusTotalEnabled || string.IsNullOrWhiteSpace(settings.VirusTotalApiKey))
            {
                var unconfiguredReport = new VirusTotalReport
                {
                    Sha256 = cleanHash,
                    Status = "NotConfigured",
                    Permalink = permalink,
                    ErrorMessage = "VirusTotal API key is not configured or disabled in settings."
                };
                return unconfiguredReport;
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{cleanHash}");
                request.Headers.Add("x-apikey", settings.VirusTotalApiKey);

                using var response = await _httpClient.SendAsync(request, cancellationToken);

                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    var notFoundReport = new VirusTotalReport
                    {
                        Sha256 = cleanHash,
                        Status = "NotFound",
                        Permalink = permalink,
                        ErrorMessage = "File hash not found in VirusTotal database (unseen/novel or clean unique file)."
                    };
                    _cache[cleanHash] = notFoundReport;
                    return notFoundReport;
                }

                if (response.StatusCode == (HttpStatusCode)429)
                {
                    return new VirusTotalReport
                    {
                        Sha256 = cleanHash,
                        Status = "RateLimited",
                        Permalink = permalink,
                        ErrorMessage = "VirusTotal API rate limit reached (Free public tier limit is 4 requests/min)."
                    };
                }

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    return new VirusTotalReport
                    {
                        Sha256 = cleanHash,
                        Status = "Error",
                        Permalink = permalink,
                        ErrorMessage = "VirusTotal authentication error: Invalid API key or permission denied."
                    };
                }

                if (!response.IsSuccessStatusCode)
                {
                    return new VirusTotalReport
                    {
                        Sha256 = cleanHash,
                        Status = "Error",
                        Permalink = permalink,
                        ErrorMessage = $"VirusTotal query failed with HTTP status {(int)response.StatusCode} ({response.ReasonPhrase})."
                    };
                }

                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                var report = ParseVirusTotalResponse(cleanHash, permalink, content);
                _cache[cleanHash] = report;
                return report;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return new VirusTotalReport
                {
                    Sha256 = cleanHash,
                    Status = "Error",
                    Permalink = permalink,
                    ErrorMessage = $"VirusTotal communication exception: {ex.Message}"
                };
            }
        }

        public async Task<TestApiResponse> TestConnectionAsync(string? testApiKey = null, CancellationToken cancellationToken = default)
        {
            var key = !string.IsNullOrWhiteSpace(testApiKey) ? testApiKey.Trim() : _settingsService.GetSettings().VirusTotalApiKey;

            if (string.IsNullOrWhiteSpace(key))
            {
                return new TestApiResponse
                {
                    Success = false,
                    Message = "Please provide a VirusTotal API key to test."
                };
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{EicarSha256}");
                request.Headers.Add("x-apikey", key);

                using var response = await _httpClient.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync(cancellationToken);
                    using var doc = JsonDocument.Parse(json);
                    int totalEngines = 0;
                    if (doc.RootElement.TryGetProperty("data", out var data) &&
                        data.TryGetProperty("attributes", out var attrs) &&
                        attrs.TryGetProperty("last_analysis_stats", out var stats))
                    {
                        int mal = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
                        int susp = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
                        int undet = stats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0;
                        int harm = stats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0;
                        totalEngines = mal + susp + undet + harm;
                    }

                    return new TestApiResponse
                    {
                        Success = true,
                        Message = $"VirusTotal API connection verified successfully! Query responded with analysis across {totalEngines} antivirus engines.",
                        EnginesCount = totalEngines,
                        Details = "Verified against standard EICAR test signature."
                    };
                }

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    return new TestApiResponse
                    {
                        Success = false,
                        Message = "Authentication failed: The provided VirusTotal API key is invalid or inactive."
                    };
                }

                if ((int)response.StatusCode == 429)
                {
                    return new TestApiResponse
                    {
                        Success = false,
                        Message = "API key accepted, but rate limit has been exceeded (4 queries/min on free tier). Please wait a moment."
                    };
                }

                return new TestApiResponse
                {
                    Success = false,
                    Message = $"VirusTotal returned HTTP {(int)response.StatusCode} ({response.ReasonPhrase})."
                };
            }
            catch (Exception ex)
            {
                return new TestApiResponse
                {
                    Success = false,
                    Message = $"Network or connection error while contacting VirusTotal: {ex.Message}"
                };
            }
        }

        private static VirusTotalReport ParseVirusTotalResponse(string sha256, string permalink, string json)
        {
            var report = new VirusTotalReport
            {
                Sha256 = sha256,
                Permalink = permalink,
                Status = "Clean"
            };

            try
            {
                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("data", out var data) ||
                    !data.TryGetProperty("attributes", out var attrs))
                {
                    report.Status = "Error";
                    report.ErrorMessage = "Unexpected VirusTotal JSON format: missing data.attributes.";
                    return report;
                }

                if (attrs.TryGetProperty("last_analysis_stats", out var stats))
                {
                    report.MaliciousCount = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
                    report.SuspiciousCount = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
                    report.UndetectedCount = stats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0;
                    report.HarmlessCount = stats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0;
                }

                if (attrs.TryGetProperty("reputation", out var rep))
                {
                    report.Reputation = rep.GetInt32();
                }

                if (attrs.TryGetProperty("popular_threat_classification", out var pop) &&
                    pop.TryGetProperty("suggested_threat_label", out var label))
                {
                    report.SuggestedThreatLabel = label.GetString();
                }

                if (attrs.TryGetProperty("last_analysis_results", out var results) && results.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in results.EnumerateObject())
                    {
                        if (prop.Value.TryGetProperty("category", out var cat) &&
                            prop.Value.TryGetProperty("result", out var resVal))
                        {
                            var catStr = cat.GetString();
                            var resStr = resVal.GetString();

                            if ((catStr == "malicious" || catStr == "suspicious") && !string.IsNullOrWhiteSpace(resStr))
                            {
                                report.VendorDetections[prop.Name] = resStr;
                            }
                        }
                    }
                }

                if (report.MaliciousCount > 0)
                {
                    report.Status = "Malicious";
                }
                else if (report.SuspiciousCount > 0)
                {
                    report.Status = "Suspicious";
                }
                else
                {
                    report.Status = "Clean";
                }
            }
            catch (Exception ex)
            {
                report.Status = "Error";
                report.ErrorMessage = $"Error parsing VirusTotal JSON response: {ex.Message}";
            }

            return report;
        }
    }
}
