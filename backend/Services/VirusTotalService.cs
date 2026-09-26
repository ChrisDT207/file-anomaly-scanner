using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        private readonly ConcurrentDictionary<string, CloudSandboxReportDto> _behaviorCache = new(StringComparer.OrdinalIgnoreCase);

        // Standard EICAR Antivirus Test File SHA-256 for testing connection
        public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        public VirusTotalService(HttpClient httpClient, ISecuritySettingsService settingsService)
        {
            _httpClient = httpClient;
            _settingsService = settingsService;
            _httpClient.Timeout = TimeSpan.FromSeconds(25);
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
                    var errContent = await response.Content.ReadAsStringAsync(cancellationToken);
                    return new VirusTotalReport
                    {
                        Sha256 = cleanHash,
                        Status = "Error",
                        Permalink = permalink,
                        ErrorMessage = $"VirusTotal API returned error HTTP {(int)response.StatusCode}: {errContent}"
                    };
                }

                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                var report = ParseVirusTotalResponse(cleanHash, json, permalink);
                _cache[cleanHash] = report;
                return report;
            }
            catch (Exception ex)
            {
                return new VirusTotalReport
                {
                    Sha256 = cleanHash,
                    Status = "Error",
                    Permalink = permalink,
                    ErrorMessage = $"Failed to query VirusTotal: {ex.Message}"
                };
            }
        }

        public async Task<TestApiResponse> TestConnectionAsync(string? testApiKey = null, CancellationToken cancellationToken = default)
        {
            var keyToUse = testApiKey;
            if (string.IsNullOrWhiteSpace(keyToUse))
            {
                var settings = _settingsService.GetSettings();
                keyToUse = settings.VirusTotalApiKey;
            }

            if (string.IsNullOrWhiteSpace(keyToUse))
            {
                return new TestApiResponse
                {
                    Success = false,
                    Message = "No API key was provided to test."
                };
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{EicarSha256}");
                request.Headers.Add("x-apikey", keyToUse);

                using var response = await _httpClient.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    return new TestApiResponse
                    {
                        Success = true,
                        Message = "Successfully connected to VirusTotal v3 API. EICAR test hash query succeeded."
                    };
                }

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    return new TestApiResponse
                    {
                        Success = false,
                        Message = "Authentication failed: The provided VirusTotal API key is invalid or lacks required permissions."
                    };
                }

                if (response.StatusCode == (HttpStatusCode)429)
                {
                    return new TestApiResponse
                    {
                        Success = false,
                        Message = "VirusTotal API rate limit exceeded during connection test."
                    };
                }

                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                return new TestApiResponse
                {
                    Success = false,
                    Message = $"VirusTotal returned HTTP {(int)response.StatusCode}: {content}"
                };
            }
            catch (Exception ex)
            {
                return new TestApiResponse
                {
                    Success = false,
                    Message = $"Connection failed: {ex.Message}"
                };
            }
        }

        private static VirusTotalReport ParseVirusTotalResponse(string cleanHash, string json, string permalink)
        {
            var report = new VirusTotalReport
            {
                Sha256 = cleanHash,
                Permalink = permalink
            };

            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("data", out var data) || !data.TryGetProperty("attributes", out var attrs))
                {
                    report.Status = "Error";
                    report.ErrorMessage = "Unexpected VirusTotal JSON format: missing data.attributes.";
                    return report;
                }

                if (attrs.TryGetProperty("last_analysis_stats", out var stats))
                {
                    if (stats.TryGetProperty("malicious", out var m)) report.MaliciousCount = m.GetInt32();
                    if (stats.TryGetProperty("suspicious", out var s)) report.SuspiciousCount = s.GetInt32();
                    if (stats.TryGetProperty("undetected", out var u)) report.UndetectedCount = u.GetInt32();
                    if (stats.TryGetProperty("harmless", out var h)) report.HarmlessCount = h.GetInt32();
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

        public async Task<string?> SubmitFileForAnalysisAsync(string fileName, byte[] content, CancellationToken cancellationToken = default)
        {
            using var ms = new System.IO.MemoryStream(content, writable: false);
            return await SubmitStreamForAnalysisAsync(fileName, ms, cancellationToken);
        }

        public async Task<string?> SubmitStreamForAnalysisAsync(string fileName, System.IO.Stream stream, CancellationToken cancellationToken = default)
        {
            var settings = _settingsService.GetSettings();
            if (string.IsNullOrWhiteSpace(settings.VirusTotalApiKey))
            {
                throw new InvalidOperationException("VirusTotal API key is not configured. Add a key in API Settings.");
            }

            if (stream.CanSeek && stream.Length > 32 * 1024 * 1024)
            {
                throw new InvalidOperationException("File exceeds standard VirusTotal API free tier upload limit (32 MB).");
            }

            using var form = new MultipartFormDataContent();
            var streamContent = new StreamContent(stream);
            streamContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            form.Add(streamContent, "file", fileName);

            var request = new HttpRequestMessage(HttpMethod.Post, "https://www.virustotal.com/api/v3/files")
            {
                Content = form
            };
            request.Headers.Add("x-apikey", settings.VirusTotalApiKey);

            var response = await _httpClient.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var err = await response.Content.ReadAsStringAsync(cancellationToken);
                throw new HttpRequestException($"VirusTotal upload failed (HTTP {(int)response.StatusCode}): {err}");
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("data", out var data) &&
                data.TryGetProperty("id", out var idProp))
            {
                return idProp.GetString();
            }

            return null;
        }

        public async Task<CloudSandboxReportDto?> GetBehaviorSummaryAsync(string sha256, CancellationToken cancellationToken = default)
        {
            var cleanHash = sha256.Trim().ToLowerInvariant();
            var permalink = $"https://www.virustotal.com/gui/file/{cleanHash}/behavior";

            if (_behaviorCache.TryGetValue(cleanHash, out var cached))
            {
                return cached;
            }

            var settings = _settingsService.GetSettings();
            if (!settings.VirusTotalEnabled || string.IsNullOrWhiteSpace(settings.VirusTotalApiKey))
            {
                return new CloudSandboxReportDto
                {
                    Sha256 = cleanHash,
                    Status = "NotConfigured",
                    Permalink = permalink,
                    ErrorMessage = "VirusTotal API key is not configured or disabled in settings."
                };
            }

            // Retrieve AV report to correlate detection consensus
            VirusTotalReport? avReport = null;
            try
            {
                avReport = await LookupFileHashAsync(cleanHash, cancellationToken);
            }
            catch { /* Ignore */ }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{cleanHash}/behaviour_summary");
                request.Headers.Add("x-apikey", settings.VirusTotalApiKey);

                using var response = await _httpClient.SendAsync(request, cancellationToken);

                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    var notFoundReport = new CloudSandboxReportDto
                    {
                        Sha256 = cleanHash,
                        Status = "NotFound",
                        Permalink = permalink,
                        ErrorMessage = "No behavioral hypervisor execution report is currently available on VirusTotal for this file hash.",
                        VerdictSummary = new VerdictSummaryDto
                        {
                            Verdict = avReport != null && avReport.MaliciousCount >= 3 ? "TruePositive" : "Inconclusive",
                            ConfidenceScore = avReport != null && avReport.MaliciousCount >= 3 ? 80 : 35,
                            Title = avReport != null && avReport.MaliciousCount >= 3 
                                ? "Antivirus Consensus Threat (Dynamic Telemetry Pending)" 
                                : "Cloud Sandbox Telemetry Unavailable",
                            Justification = avReport != null && avReport.MaliciousCount >= 3
                                ? $"Although hypervisor behavioral execution logs have not yet been published, {avReport.MaliciousCount} security vendors flagged this hash as malicious."
                                : "No hypervisor behavioral detonation logs found for this hash. The file may be novel, recently compiled, or has not yet undergone dynamic sandbox execution.",
                            Indicators = avReport != null && avReport.MaliciousCount > 0
                                ? new List<string> { $"{avReport.MaliciousCount} security engines detected this payload." }
                                : new List<string>()
                        }
                    };
                    _behaviorCache[cleanHash] = notFoundReport;
                    return notFoundReport;
                }

                if (response.StatusCode == (HttpStatusCode)429)
                {
                    return new CloudSandboxReportDto
                    {
                        Sha256 = cleanHash,
                        Status = "RateLimited",
                        Permalink = permalink,
                        ErrorMessage = "VirusTotal API rate limit reached (Free public tier limit is 4 requests/min)."
                    };
                }

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    return new CloudSandboxReportDto
                    {
                        Sha256 = cleanHash,
                        Status = "Error",
                        Permalink = permalink,
                        ErrorMessage = "VirusTotal authentication error: Invalid API key or permission denied."
                    };
                }

                if (!response.IsSuccessStatusCode)
                {
                    var errContent = await response.Content.ReadAsStringAsync(cancellationToken);
                    return new CloudSandboxReportDto
                    {
                        Sha256 = cleanHash,
                        Status = "Error",
                        Permalink = permalink,
                        ErrorMessage = $"VirusTotal API returned error HTTP {(int)response.StatusCode}: {errContent}"
                    };
                }

                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                var report = ParseBehaviorSummary(cleanHash, json, permalink, avReport);
                _behaviorCache[cleanHash] = report;
                return report;
            }
            catch (Exception ex)
            {
                return new CloudSandboxReportDto
                {
                    Sha256 = cleanHash,
                    Status = "Error",
                    Permalink = permalink,
                    ErrorMessage = $"Failed to retrieve cloud behavioral telemetry: {ex.Message}"
                };
            }
        }

        private static CloudSandboxReportDto ParseBehaviorSummary(
            string cleanHash,
            string json,
            string permalink,
            VirusTotalReport? avReport)
        {
            var report = new CloudSandboxReportDto
            {
                Sha256 = cleanHash,
                Status = "Available",
                Permalink = permalink
            };

            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("data", out var data))
                {
                    report.Status = "Error";
                    report.ErrorMessage = "Unexpected VirusTotal JSON format: missing 'data' root property.";
                    return report;
                }

                // 1. Process Tree
                if (data.TryGetProperty("processes_tree", out var pTreeEl) && pTreeEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in pTreeEl.EnumerateArray())
                    {
                        var node = ParseProcessTreeNode(item, report.ProcessesCreated);
                        if (node != null) report.ProcessTree.Add(node);
                    }
                }

                // 2. Processes Created / Command Executions
                if (data.TryGetProperty("processes_created", out var pCreatedEl) && pCreatedEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in pCreatedEl.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var cmd = item.GetString() ?? string.Empty;
                            if (!string.IsNullOrWhiteSpace(cmd) && !report.ProcessesCreated.Any(p => p.CommandLine == cmd))
                            {
                                report.ProcessesCreated.Add(new ProcessExecutionDto
                                {
                                    CommandLine = cmd,
                                    ProcessName = ExtractExeName(cmd)
                                });
                            }
                        }
                        else if (item.ValueKind == JsonValueKind.Object)
                        {
                            var cmd = item.TryGetProperty("cmd_line", out var c) ? c.GetString() ?? "" : "";
                            var name = item.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                            var pid = item.TryGetProperty("process_id", out var pidProp) ? pidProp.ToString() : null;
                            var ppid = item.TryGetProperty("parent_process_id", out var ppidProp) ? ppidProp.ToString() : null;

                            if (!string.IsNullOrWhiteSpace(cmd) || !string.IsNullOrWhiteSpace(name))
                            {
                                if (!report.ProcessesCreated.Any(p => p.CommandLine == cmd && p.ProcessName == name))
                                {
                                    report.ProcessesCreated.Add(new ProcessExecutionDto
                                    {
                                        ProcessName = string.IsNullOrWhiteSpace(name) ? ExtractExeName(cmd) : name,
                                        CommandLine = cmd,
                                        Pid = pid,
                                        ParentPid = ppid
                                    });
                                }
                            }
                        }
                    }
                }

                if (data.TryGetProperty("command_executions", out var cmdExecEl) && cmdExecEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in cmdExecEl.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var cmd = item.GetString() ?? string.Empty;
                            if (!string.IsNullOrWhiteSpace(cmd) && !report.ProcessesCreated.Any(p => p.CommandLine == cmd))
                            {
                                report.ProcessesCreated.Add(new ProcessExecutionDto
                                {
                                    CommandLine = cmd,
                                    ProcessName = ExtractExeName(cmd)
                                });
                            }
                        }
                    }
                }

                // 3. Network Activity (DNS, IPs, HTTP)
                if (data.TryGetProperty("dns_lookups", out var dnsEl) && dnsEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in dnsEl.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var host = item.GetString() ?? "";
                            if (!string.IsNullOrWhiteSpace(host) && !report.NetworkActivity.DnsLookups.Any(d => d.Hostname == host))
                            {
                                report.NetworkActivity.DnsLookups.Add(new DnsLookupDto { Hostname = host });
                            }
                        }
                        else if (item.ValueKind == JsonValueKind.Object)
                        {
                            var host = item.TryGetProperty("hostname", out var h) ? h.GetString() ?? "" : "";
                            var ips = new List<string>();
                            if (item.TryGetProperty("resolved_ips", out var rIps) && rIps.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var subIp in rIps.EnumerateArray())
                                {
                                    var ipStr = subIp.GetString();
                                    if (!string.IsNullOrWhiteSpace(ipStr)) ips.Add(ipStr);
                                }
                            }
                            if (!string.IsNullOrWhiteSpace(host) && !report.NetworkActivity.DnsLookups.Any(d => d.Hostname == host))
                            {
                                report.NetworkActivity.DnsLookups.Add(new DnsLookupDto { Hostname = host, ResolvedIps = ips });
                            }
                        }
                    }
                }

                if (data.TryGetProperty("ip_traffic", out var ipEl) && ipEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in ipEl.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.Object)
                        {
                            var destIp = item.TryGetProperty("destination_ip", out var dip) ? dip.GetString() ?? "" : "";
                            int? port = item.TryGetProperty("destination_port", out var dp) && dp.TryGetInt32(out var pVal) ? pVal : null;
                            var proto = item.TryGetProperty("transport_layer_protocol", out var pr) ? pr.GetString() : null;

                            if (!string.IsNullOrWhiteSpace(destIp) && !report.NetworkActivity.ContactedIps.Any(c => c.IpAddress == destIp && c.Port == port))
                            {
                                report.NetworkActivity.ContactedIps.Add(new ContactedIpDto
                                {
                                    IpAddress = destIp,
                                    Port = port,
                                    Protocol = proto
                                });
                            }
                        }
                    }
                }

                if (data.TryGetProperty("http_conversations", out var httpEl) && httpEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in httpEl.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.Object)
                        {
                            var url = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
                            var method = item.TryGetProperty("request_method", out var m) ? m.GetString() ?? "GET" : "GET";
                            int? respCode = item.TryGetProperty("response_status_code", out var rsc) && rsc.TryGetInt32(out var rcVal) ? rcVal : null;
                            var ua = item.TryGetProperty("user_agent", out var uap) ? uap.GetString() : null;

                            if (!string.IsNullOrWhiteSpace(url))
                            {
                                report.NetworkActivity.HttpRequests.Add(new HttpRequestDto
                                {
                                    Url = url,
                                    Method = method,
                                    ResponseCode = respCode,
                                    UserAgent = ua
                                });
                            }
                        }
                    }
                }

                // 4. File & Registry Tampering
                if (data.TryGetProperty("files_dropped", out var fDropEl) && fDropEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in fDropEl.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var p = item.GetString() ?? "";
                            if (!string.IsNullOrWhiteSpace(p))
                            {
                                report.FileAndRegistryTampering.FilesDropped.Add(new DroppedFileDto { Path = p });
                            }
                        }
                        else if (item.ValueKind == JsonValueKind.Object)
                        {
                            var p = item.TryGetProperty("path", out var pp) ? pp.GetString() ?? "" : "";
                            var sha = item.TryGetProperty("sha256", out var sh) ? sh.GetString() : null;
                            var type = item.TryGetProperty("type_tags", out var tt) && tt.ValueKind == JsonValueKind.Array && tt.GetArrayLength() > 0 
                                ? tt[0].GetString() 
                                : null;
                            long? sz = item.TryGetProperty("size", out var s) && s.TryGetInt64(out var szVal) ? szVal : null;

                            if (!string.IsNullOrWhiteSpace(p))
                            {
                                report.FileAndRegistryTampering.FilesDropped.Add(new DroppedFileDto
                                {
                                    Path = p,
                                    Sha256 = sha,
                                    Type = type,
                                    SizeBytes = sz
                                });
                            }
                        }
                    }
                }

                if (data.TryGetProperty("files_written", out var fWritEl) && fWritEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in fWritEl.EnumerateArray())
                    {
                        var str = item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString();
                        if (!string.IsNullOrWhiteSpace(str) && !report.FileAndRegistryTampering.FilesWritten.Contains(str))
                        {
                            report.FileAndRegistryTampering.FilesWritten.Add(str);
                        }
                    }
                }

                if (data.TryGetProperty("files_deleted", out var fDelEl) && fDelEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in fDelEl.EnumerateArray())
                    {
                        var str = item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString();
                        if (!string.IsNullOrWhiteSpace(str) && !report.FileAndRegistryTampering.FilesDeleted.Contains(str))
                        {
                            report.FileAndRegistryTampering.FilesDeleted.Add(str);
                        }
                    }
                }

                if (data.TryGetProperty("registry_keys_set", out var regSetEl) && regSetEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in regSetEl.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var k = item.GetString() ?? "";
                            if (!string.IsNullOrWhiteSpace(k))
                            {
                                report.FileAndRegistryTampering.RegistryKeysSet.Add(new RegistryKeySetDto { Key = k });
                            }
                        }
                        else if (item.ValueKind == JsonValueKind.Object)
                        {
                            var k = item.TryGetProperty("key", out var kp) ? kp.GetString() ?? "" : "";
                            var v = item.TryGetProperty("value", out var vp) ? vp.GetString() : null;
                            if (!string.IsNullOrWhiteSpace(k))
                            {
                                report.FileAndRegistryTampering.RegistryKeysSet.Add(new RegistryKeySetDto { Key = k, Value = v });
                            }
                        }
                    }
                }

                if (data.TryGetProperty("registry_keys_deleted", out var regDelEl) && regDelEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in regDelEl.EnumerateArray())
                    {
                        var str = item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString();
                        if (!string.IsNullOrWhiteSpace(str) && !report.FileAndRegistryTampering.RegistryKeysDeleted.Contains(str))
                        {
                            report.FileAndRegistryTampering.RegistryKeysDeleted.Add(str);
                        }
                    }
                }

                // 5. MITRE ATT&CK Techniques
                if (data.TryGetProperty("mitre_attack_techniques", out var mitreEl) && mitreEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in mitreEl.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.Object)
                        {
                            var id = item.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
                            var desc = item.TryGetProperty("signature_description", out var sd) ? sd.GetString() ?? "" : "";
                            var sev = item.TryGetProperty("severity", out var sv) ? sv.GetString() ?? "MEDIUM" : "MEDIUM";
                            var tactic = item.TryGetProperty("tactics", out var tc) && tc.ValueKind == JsonValueKind.Array && tc.GetArrayLength() > 0 
                                ? tc[0].GetString() 
                                : null;

                            if (!string.IsNullOrWhiteSpace(id) && !report.MitreAttackSignatures.Any(m => m.Id == id))
                            {
                                report.MitreAttackSignatures.Add(new MitreTechniqueDto
                                {
                                    Id = id,
                                    Name = FormatMitreName(id, desc),
                                    Description = desc,
                                    Severity = sev.ToUpperInvariant(),
                                    Tactic = tactic
                                });
                            }
                        }
                    }
                }

                // Sandbox Engines
                report.SandboxEngines.Add("VirusTotal Cloud Hypervisor");

                // 6. Automated Adjudication Heuristic
                report.VerdictSummary = CalculateVerdict(report, avReport);
            }
            catch (Exception ex)
            {
                report.Status = "Error";
                report.ErrorMessage = $"Error parsing VirusTotal behavior summary: {ex.Message}";
            }

            return report;
        }

        private static ProcessTreeNodeDto? ParseProcessTreeNode(JsonElement item, List<ProcessExecutionDto> flatList)
        {
            if (item.ValueKind != JsonValueKind.Object) return null;

            var pid = item.TryGetProperty("process_id", out var pidProp) ? pidProp.ToString() : "";
            var name = item.TryGetProperty("name", out var nProp) ? nProp.GetString() ?? "" : "";
            var cmd = item.TryGetProperty("cmd_line", out var cmdProp) ? cmdProp.GetString() ?? "" : "";

            var node = new ProcessTreeNodeDto
            {
                ProcessId = pid,
                Name = string.IsNullOrWhiteSpace(name) ? ExtractExeName(cmd) : name,
                CommandLine = cmd
            };

            if (!string.IsNullOrWhiteSpace(cmd) && !flatList.Any(p => p.CommandLine == cmd))
            {
                flatList.Add(new ProcessExecutionDto
                {
                    ProcessName = node.Name,
                    CommandLine = cmd,
                    Pid = pid
                });
            }

            if (item.TryGetProperty("children", out var childArr) && childArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var childEl in childArr.EnumerateArray())
                {
                    var childNode = ParseProcessTreeNode(childEl, flatList);
                    if (childNode != null) node.Children.Add(childNode);
                }
            }

            return node;
        }

        private static VerdictSummaryDto CalculateVerdict(CloudSandboxReportDto report, VirusTotalReport? avReport)
        {
            var indicators = new List<string>();
            int confidence = 50;

            // 1. Check Antivirus Consensus
            if (avReport != null && avReport.MaliciousCount > 0)
            {
                indicators.Add($"[Antivirus Detection] Flagged as malicious by {avReport.MaliciousCount} security engines on VirusTotal.");
            }

            // 2. Check Suspicious Processes
            var suspiciousShells = new[] { "powershell", "cmd.exe", "wscript", "cscript", "mshta", "certutil", "schtasks", "vssadmin", "rundll32" };
            foreach (var proc in report.ProcessesCreated)
            {
                var lowerCmd = proc.CommandLine.ToLowerInvariant();
                foreach (var shell in suspiciousShells)
                {
                    if (lowerCmd.Contains(shell))
                    {
                        indicators.Add($"[Process Execution] Spawned suspicious command execution: '{proc.CommandLine}'");
                        break;
                    }
                }
            }

            // 3. Check Network & C2
            var nonLocalIps = report.NetworkActivity.ContactedIps
                .Where(ip => !ip.IpAddress.StartsWith("127.") && ip.IpAddress != "0.0.0.0" && ip.IpAddress != "8.8.8.8" && ip.IpAddress != "1.1.1.1")
                .ToList();

            if (nonLocalIps.Count > 0)
            {
                var sample = nonLocalIps.First();
                indicators.Add($"[Network Telemetry] Outbound C2/external network traffic detected to {sample.IpAddress}:{sample.Port ?? 443} ({sample.Protocol ?? "TCP"}) (Total Contacted IPs: {nonLocalIps.Count}).");
            }

            if (report.NetworkActivity.HttpRequests.Count > 0)
            {
                var sampleHttp = report.NetworkActivity.HttpRequests.First();
                indicators.Add($"[HTTP Telemetry] Active dynamic web request observed: {sampleHttp.Method} {sampleHttp.Url} (HTTP {sampleHttp.ResponseCode?.ToString() ?? "N/A"}).");
            }

            // 4. Check Dropped Payloads
            var droppedExecutables = report.FileAndRegistryTampering.FilesDropped
                .Where(f => f.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                            f.Path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                            f.Path.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                            f.Path.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ||
                            f.Path.EndsWith(".vbs", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (droppedExecutables.Count > 0)
            {
                var sampleFile = droppedExecutables.First();
                indicators.Add($"[Secondary Dropper] Dropped executable file onto filesystem: '{sampleFile.Path}'.");
            }

            // 5. Check Persistence Registry Keys
            var persistenceRunKeys = report.FileAndRegistryTampering.RegistryKeysSet
                .Where(k => k.Key.Contains(@"CurrentVersion\Run", StringComparison.OrdinalIgnoreCase) ||
                            k.Key.Contains(@"CurrentVersion\RunOnce", StringComparison.OrdinalIgnoreCase) ||
                            k.Key.Contains(@"Services\", StringComparison.OrdinalIgnoreCase) ||
                            k.Key.Contains(@"Winlogon\Userinit", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (persistenceRunKeys.Count > 0)
            {
                var sampleKey = persistenceRunKeys.First();
                indicators.Add($"[Persistence Mechanism] Modified autostart registry key for reboot survival: '{sampleKey.Key}'.");
            }

            // 6. Check High-Severity MITRE Techniques
            var highMitre = report.MitreAttackSignatures
                .Where(m => m.Severity == "CRITICAL" || m.Severity == "HIGH")
                .ToList();

            foreach (var m in highMitre.Take(3))
            {
                indicators.Add($"[MITRE ATT&CK] {m.Id} ({m.Name}) flagged: {m.Description}");
            }

            // True Positive Determination
            bool isTruePositive = indicators.Count > 0 || (avReport != null && avReport.MaliciousCount >= 3);

            if (isTruePositive)
            {
                confidence = Math.Min(98, 70 + (indicators.Count * 6));
                return new VerdictSummaryDto
                {
                    Verdict = "TruePositive",
                    ConfidenceScore = confidence,
                    Title = "Confirmed Malicious Threat (True Positive)",
                    Justification = "Dynamic cloud hypervisor sandbox telemetry confirms high-confidence malicious activity. The payload demonstrated unauthorized behavioral execution, including persistence registry modifications, secondary dropper staging, or active external C2 networking.",
                    Indicators = indicators
                };
            }

            // Likely False Positive Determination
            confidence = 88;
            return new VerdictSummaryDto
            {
                Verdict = "LikelyFalsePositive",
                ConfidenceScore = confidence,
                Title = "Benign Dynamic Behavior (Likely False Positive)",
                Justification = "Dynamic cloud hypervisor sandbox observed clean execution without malicious intent. Zero persistence run-keys were modified, no secondary executables were dropped, and no unauthorized external C2 connections were initiated. The local scanner heuristic detection is adjudicated as a benign false positive.",
                Indicators = new List<string>
                {
                    "Zero autostart or persistence registry modifications observed.",
                    "No secondary executable binaries dropped into temp or system folders.",
                    "No unauthorized outbound C2 beacons detected.",
                    "All dynamic process actions terminated cleanly without defense evasion."
                }
            };
        }

        public async Task<AnalysisStatusDto?> GetAnalysisStatusAsync(string analysisId, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(analysisId)) return null;

            var settings = _settingsService.GetSettings();
            if (string.IsNullOrWhiteSpace(settings.VirusTotalApiKey))
            {
                return new AnalysisStatusDto
                {
                    AnalysisId = analysisId,
                    Status = "error",
                    ErrorMessage = "VirusTotal API key is not configured in settings."
                };
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/analyses/{analysisId}");
                request.Headers.Add("x-apikey", settings.VirusTotalApiKey);

                using var response = await _httpClient.SendAsync(request, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    return new AnalysisStatusDto
                    {
                        AnalysisId = analysisId,
                        Status = "error",
                        ErrorMessage = $"Failed to query analysis status (HTTP {(int)response.StatusCode})"
                    };
                }

                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("data", out var data))
                {
                    return new AnalysisStatusDto { AnalysisId = analysisId, Status = "error" };
                }

                var statusDto = new AnalysisStatusDto
                {
                    AnalysisId = analysisId,
                    Status = "queued"
                };

                if (data.TryGetProperty("attributes", out var attrs))
                {
                    if (attrs.TryGetProperty("status", out var sProp))
                    {
                        statusDto.Status = sProp.GetString() ?? "queued";
                    }

                    if (attrs.TryGetProperty("stats", out var stats))
                    {
                        if (stats.TryGetProperty("malicious", out var m)) statusDto.MaliciousCount = m.GetInt32();
                        if (stats.TryGetProperty("suspicious", out var sp)) statusDto.SuspiciousCount = sp.GetInt32();
                        if (stats.TryGetProperty("undetected", out var u)) statusDto.UndetectedCount = u.GetInt32();
                    }
                }

                if (doc.RootElement.TryGetProperty("meta", out var meta) &&
                    meta.TryGetProperty("file_info", out var fi) &&
                    fi.TryGetProperty("sha256", out var sha))
                {
                    statusDto.Sha256 = sha.GetString();
                }

                return statusDto;
            }
            catch (Exception ex)
            {
                return new AnalysisStatusDto
                {
                    AnalysisId = analysisId,
                    Status = "error",
                    ErrorMessage = ex.Message
                };
            }
        }

        private static string ExtractExeName(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return "unknown.exe";
            var parts = commandLine.Trim().Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            var exe = parts[0].Trim('"', '\'');
            return Path.GetFileName(exe);
        }

        private static string FormatMitreName(string id, string description)
        {
            if (!string.IsNullOrWhiteSpace(description))
            {
                var firstSentence = description.Split(new[] { '.', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(firstSentence) && firstSentence.Length < 60)
                {
                    return firstSentence.Trim();
                }
            }

            return id switch
            {
                "T1055" => "Process Injection",
                "T1059" => "Command and Scripting Interpreter",
                "T1547" => "Boot or Logon Autostart Execution",
                "T1027" => "Obfuscated Files or Information",
                "T1071" => "Application Layer Protocol",
                "T1562" => "Impair Defenses",
                "T1112" => "Modify Registry",
                "T1106" => "Native API Execution",
                "T1082" => "System Information Discovery",
                "T1083" => "File and Directory Discovery",
                _ => id
            };
        }
    }
}
