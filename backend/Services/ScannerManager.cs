using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Exceptions;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    public class ScannerManager : IScannerManager
    {
        private readonly IMagicByteValidator _magicByteValidator;
        private readonly IEntropyCalculator _entropyCalculator;
        private readonly IArchiveExtractorService _archiveExtractor;
        private readonly ISuspiciousSignatureManager _signatureManager;
        private readonly IReportGenerator _reportGenerator;
        private readonly IVirusTotalService _virusTotalService;
        private readonly ISafeBrowsingService _safeBrowsingService;
        private readonly ISecuritySettingsService _settingsService;

        public ScannerManager(
            IMagicByteValidator magicByteValidator,
            IEntropyCalculator entropyCalculator,
            IArchiveExtractorService archiveExtractor,
            ISuspiciousSignatureManager signatureManager,
            IReportGenerator reportGenerator,
            IVirusTotalService virusTotalService,
            ISafeBrowsingService safeBrowsingService,
            ISecuritySettingsService settingsService)
        {
            _magicByteValidator = magicByteValidator;
            _entropyCalculator = entropyCalculator;
            _archiveExtractor = archiveExtractor;
            _signatureManager = signatureManager;
            _reportGenerator = reportGenerator;
            _virusTotalService = virusTotalService;
            _safeBrowsingService = safeBrowsingService;
            _settingsService = settingsService;
        }

        public async Task<ScanReportDto> ScanBatchAsync(IEnumerable<FileScanItem> items, CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var consoleLogs = new List<string>();
            var anomalies = new List<FileAnomalyRecord>();
            var filesMetadata = new List<FileScanMetadata>();

            int totalFiles = 0;
            long totalBytes = 0;
            int vtLookupsCount = 0;

            var settings = _settingsService.GetSettings();
            bool vtActive = _virusTotalService.IsEnabledAndConfigured();
            bool sbActive = _safeBrowsingService.IsEnabledAndConfigured();

            Log(consoleLogs, "INITIALIZE", "ScannerManager pipeline initialized. Ready to process batch.");
            if (vtActive)
            {
                Log(consoleLogs, "THREAT INTEL", $"VirusTotal v3 API active (Max batch lookups: {settings.MaxVirusTotalLookupsPerBatch}).");
            }
            else
            {
                Log(consoleLogs, "THREAT INTEL", "VirusTotal unconfigured or disabled. SHA-256 hashes generated with 1-click lookup links.");
            }

            if (sbActive)
            {
                Log(consoleLogs, "THREAT INTEL", "Google Safe Browsing v4 active. Script and document URLs will be verified against Google threat database.");
            }
            else
            {
                Log(consoleLogs, "THREAT INTEL", "Google Safe Browsing unconfigured or disabled. URL threats will not be verified remotely.");
            }

            var itemList = items.ToList();

            foreach (var item in itemList)
            {
                cancellationToken.ThrowIfCancellationRequested();
                totalFiles++;
                totalBytes += item.SizeBytes;

                var displayPath = string.IsNullOrWhiteSpace(item.RelativePath) ? item.FileName : item.RelativePath;
                var ext = Path.GetExtension(item.FileName).ToLowerInvariant();
                string sha256 = HashUtils.ComputeSha256(item.Content);

                Log(consoleLogs, "INSPECT", $"Ingesting [{totalFiles}]: {displayPath} ({item.SizeBytes} bytes | SHA256: {sha256[..12]}...)...");

                double entropy = 0.0;
                string detectedType = "Unknown";
                var fileAnomalies = new List<FileAnomalyRecord>();
                VirusTotalReport? vtReport = null;
                SafeBrowsingReport? sbReport = null;

                try
                {
                    // 1. Calculate and assess Entropy
                    entropy = _entropyCalculator.CalculateEntropy(item.Content);
                    var (isEntropyAnomalous, entropySeverity, entropyDesc) = _entropyCalculator.AssessEntropy(item.FileName, entropy);

                    if (isEntropyAnomalous)
                    {
                        Log(consoleLogs, "WARN", $"Entropy flag on '{displayPath}': {entropy:F2}/8.00 - {entropyDesc}");
                        fileAnomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = displayPath,
                            FileName = item.FileName,
                            FileSizeBytes = item.SizeBytes,
                            Category = "Entropy Anomaly",
                            Title = "Unexpected Entropy Rating",
                            Details = entropyDesc,
                            Severity = entropySeverity,
                            Entropy = entropy,
                            ClaimedExtension = ext,
                            Sha256Hash = sha256
                        });
                    }

                    // 2. Validate Magic Bytes vs File Extension
                    var (isMagicMatch, magicType, magicDetails) = _magicByteValidator.Validate(item.FileName, item.Content);
                    detectedType = magicType;

                    if (!isMagicMatch)
                    {
                        var severity = detectedType.Contains("PE Executable") || detectedType.Contains("ELF Binary")
                            ? AnomalySeverity.Critical
                            : AnomalySeverity.High;

                        Log(consoleLogs, "ALERT", $"Magic byte mismatch on '{displayPath}': Declared '{ext}' vs Detected '{detectedType}'");

                        fileAnomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = displayPath,
                            FileName = item.FileName,
                            FileSizeBytes = item.SizeBytes,
                            Category = "Header / Extension Mismatch",
                            Title = "Spoofed File Extension / Masqueraded Header",
                            Details = magicDetails,
                            Severity = severity,
                            Entropy = entropy,
                            ClaimedExtension = ext,
                            DetectedType = detectedType,
                            IsMagicByteMismatch = true,
                            Sha256Hash = sha256
                        });
                    }

                    // 3. Scan for Suspicious Heuristic Signatures
                    var signatureAnomalies = _signatureManager.ScanForSignatures(displayPath, item.FileName, item.Content, entropy);
                    foreach (var sigAnomaly in signatureAnomalies)
                    {
                        sigAnomaly.Sha256Hash = sha256;
                        Log(consoleLogs, "ALERT", $"Signature anomaly on '{displayPath}': {sigAnomaly.Title}");
                        fileAnomalies.Add(sigAnomaly);
                    }

                    // 4. Container / Archive Inspection
                    if (_archiveExtractor.IsSupportedArchive(item.FileName, item.Content))
                    {
                        Log(consoleLogs, "ARCHIVE", $"Deep inspecting archive container: {displayPath}");
                        var archiveAnomalies = _archiveExtractor.InspectArchive(displayPath, item.FileName, item.Content);
                        foreach (var archAnomaly in archiveAnomalies)
                        {
                            archAnomaly.Sha256Hash = sha256;
                            Log(consoleLogs, "ALERT", $"Archive hazard in '{displayPath}': {archAnomaly.Title} ({archAnomaly.Details})");
                            fileAnomalies.Add(archAnomaly);
                        }
                    }

                    // 5. Threat Intelligence: VirusTotal Antivirus Scan
                    bool isSuspiciousExt = ext is ".exe" or ".dll" or ".scr" or ".ps1" or ".bat" or ".vbs" or ".cmd" or ".jar";
                    bool shouldQueryVt = vtActive && (
                        fileAnomalies.Count > 0 ||
                        isSuspiciousExt ||
                        itemList.Count <= settings.MaxVirusTotalLookupsPerBatch ||
                        vtLookupsCount < settings.MaxVirusTotalLookupsPerBatch
                    );

                    if (shouldQueryVt && vtLookupsCount < settings.MaxVirusTotalLookupsPerBatch)
                    {
                        vtLookupsCount++;
                        Log(consoleLogs, "VIRUSTOTAL", $"Querying VirusTotal v3 for hash {sha256[..12]}... [{vtLookupsCount}/{settings.MaxVirusTotalLookupsPerBatch}]");
                        vtReport = await _virusTotalService.LookupFileHashAsync(sha256, cancellationToken);

                        if (vtReport.MaliciousCount > 0 || vtReport.SuspiciousCount > 0)
                        {
                            var severity = vtReport.MaliciousCount >= 3 ? AnomalySeverity.Critical : AnomalySeverity.High;
                            var topVendors = vtReport.VendorDetections.Take(4).Select(kv => $"{kv.Key}: {kv.Value}");
                            var vendorSummary = string.Join("; ", topVendors);
                            var threatName = !string.IsNullOrWhiteSpace(vtReport.SuggestedThreatLabel) ? vtReport.SuggestedThreatLabel : "Malicious Payload";

                            Log(consoleLogs, "MALWARE", $"[CRITICAL] VirusTotal flagged '{displayPath}': {vtReport.MaliciousCount}/{vtReport.TotalEngines} AV engines detected threat ({threatName})");

                            fileAnomalies.Add(new FileAnomalyRecord
                            {
                                FilePath = displayPath,
                                FileName = item.FileName,
                                FileSizeBytes = item.SizeBytes,
                                Category = "Antivirus Detection (VirusTotal)",
                                Title = $"Flagged by {vtReport.MaliciousCount}/{vtReport.TotalEngines} Antivirus Engines",
                                Details = $"Threat label: {threatName}. Detections include: {vendorSummary}. Community reputation score: {vtReport.Reputation}.",
                                Severity = severity,
                                Entropy = entropy,
                                ClaimedExtension = ext,
                                DetectedType = detectedType,
                                Sha256Hash = sha256,
                                VirusTotalResult = vtReport
                            });
                        }
                        else if (vtReport.Status == "Clean")
                        {
                            Log(consoleLogs, "VIRUSTOTAL", $"[CLEAN] '{displayPath}' verified clean on VirusTotal (0/{vtReport.TotalEngines} detections).");
                        }
                        else if (vtReport.Status == "NotFound")
                        {
                            Log(consoleLogs, "VIRUSTOTAL", $"'{displayPath}' not found in VirusTotal database (novel or unsubmitted file).");
                        }
                        else if (vtReport.Status == "RateLimited")
                        {
                            Log(consoleLogs, "VIRUSTOTAL", $"[WARN] VirusTotal rate limit reached. Manual lookup link available in report.");
                        }
                    }
                    else if (!vtActive)
                    {
                        vtReport = new VirusTotalReport
                        {
                            Sha256 = sha256,
                            Status = "NotConfigured",
                            Permalink = $"https://www.virustotal.com/gui/file/{sha256}",
                            ErrorMessage = "VirusTotal API key not configured."
                        };
                    }

                    // 6. Threat Intelligence: Google Safe Browsing URL Scan
                    if (sbActive && settings.CheckEmbeddedUrlsWithSafeBrowsing)
                    {
                        var extractedUrls = _safeBrowsingService.ExtractUrlsFromContent(item.Content);
                        if (extractedUrls.Count > 0)
                        {
                            Log(consoleLogs, "SAFEBROWSING", $"Extracted {extractedUrls.Count} URL(s) from '{displayPath}'. Checking Google Safe Browsing...");
                            sbReport = await _safeBrowsingService.CheckUrlsAsync(extractedUrls, cancellationToken);

                            if (sbReport.HasThreats)
                            {
                                foreach (var match in sbReport.Matches)
                                {
                                    Log(consoleLogs, "ALERT", $"[CRITICAL] Google Safe Browsing flagged URL in '{displayPath}': {match.Url} (Threat: {match.ThreatType})");
                                    fileAnomalies.Add(new FileAnomalyRecord
                                    {
                                        FilePath = displayPath,
                                        FileName = item.FileName,
                                        FileSizeBytes = item.SizeBytes,
                                        Category = "Malicious URL (Google Safe Browsing)",
                                        Title = $"Blacklisted {match.ThreatType} Link Detected",
                                        Details = $"URL '{match.Url}' is blacklisted by Google Safe Browsing as {match.ThreatType} ({match.PlatformType}). Potential C2 server or phishing drop site.",
                                        Severity = AnomalySeverity.Critical,
                                        Entropy = entropy,
                                        ClaimedExtension = ext,
                                        Sha256Hash = sha256,
                                        SafeBrowsingMatch = match
                                    });
                                }
                            }
                            else
                            {
                                Log(consoleLogs, "SAFEBROWSING", $"All {extractedUrls.Count} URL(s) in '{displayPath}' passed Google Safe Browsing.");
                            }
                        }
                    }

                    // Determine overall file status
                    string fileStatus = "Clean";
                    AnomalySeverity highestSev = AnomalySeverity.Info;

                    if (fileAnomalies.Any(a => a.Severity == AnomalySeverity.Critical))
                    {
                        fileStatus = "Malicious / Critical";
                        highestSev = AnomalySeverity.Critical;
                    }
                    else if (fileAnomalies.Any(a => a.Severity == AnomalySeverity.High))
                    {
                        fileStatus = "High Risk";
                        highestSev = AnomalySeverity.High;
                    }
                    else if (fileAnomalies.Any(a => a.Severity == AnomalySeverity.Medium))
                    {
                        fileStatus = "Suspicious";
                        highestSev = AnomalySeverity.Medium;
                    }
                    else if (fileAnomalies.Count > 0)
                    {
                        fileStatus = "Anomalous";
                        highestSev = AnomalySeverity.Low;
                    }

                    filesMetadata.Add(new FileScanMetadata
                    {
                        FileName = item.FileName,
                        FilePath = displayPath,
                        SizeBytes = item.SizeBytes,
                        Sha256 = sha256,
                        Entropy = entropy,
                        DetectedType = detectedType,
                        VirusTotal = vtReport,
                        SafeBrowsing = sbReport,
                        AnomalyCount = fileAnomalies.Count,
                        HighestSeverity = highestSev,
                        Status = fileStatus
                    });

                    anomalies.AddRange(fileAnomalies);
                }
                catch (FileAnomalyException faEx)
                {
                    Log(consoleLogs, "ERROR", $"Structural anomaly exception on '{displayPath}': {faEx.Message}");
                    anomalies.Add(new FileAnomalyRecord
                    {
                        FilePath = displayPath,
                        FileName = item.FileName,
                        FileSizeBytes = item.SizeBytes,
                        Category = faEx.AnomalyType,
                        Title = "Critical Structural Malformation",
                        Details = faEx.Message,
                        Severity = faEx.Severity,
                        ClaimedExtension = ext,
                        Sha256Hash = sha256
                    });
                }
                catch (Exception ex)
                {
                    Log(consoleLogs, "ERROR", $"Unhandled scan error on '{displayPath}': {ex.Message}");
                    anomalies.Add(new FileAnomalyRecord
                    {
                        FilePath = displayPath,
                        FileName = item.FileName,
                        FileSizeBytes = item.SizeBytes,
                        Category = "Processing Error",
                        Title = "Scan Analysis Exception",
                        Details = ex.Message,
                        Severity = AnomalySeverity.Low,
                        ClaimedExtension = ext,
                        Sha256Hash = sha256
                    });
                }
            }

            stopwatch.Stop();
            var report = _reportGenerator.GenerateReport(
                anomalies,
                consoleLogs,
                totalFiles,
                totalBytes,
                stopwatch.Elapsed.TotalMilliseconds,
                filesMetadata);

            return report;
        }

        private static void Log(List<string> logs, string tag, string message)
        {
            var timestamp = DateTime.UtcNow.ToString("HH:mm:ss.fff");
            logs.Add($"[{timestamp}] [{tag}] {message}");
        }
    }
}
