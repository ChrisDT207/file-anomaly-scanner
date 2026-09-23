using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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

        public ScannerManager(
            IMagicByteValidator magicByteValidator,
            IEntropyCalculator entropyCalculator,
            IArchiveExtractorService archiveExtractor,
            ISuspiciousSignatureManager signatureManager,
            IReportGenerator reportGenerator)
        {
            _magicByteValidator = magicByteValidator;
            _entropyCalculator = entropyCalculator;
            _archiveExtractor = archiveExtractor;
            _signatureManager = signatureManager;
            _reportGenerator = reportGenerator;
        }

        public Task<ScanReportDto> ScanBatchAsync(IEnumerable<FileScanItem> items, CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var consoleLogs = new List<string>();
            var anomalies = new List<FileAnomalyRecord>();

            int totalFiles = 0;
            long totalBytes = 0;

            Log(consoleLogs, "INITIALIZE", "ScannerManager pipeline initialized. Ready to process batch.");

            foreach (var item in items)
            {
                cancellationToken.ThrowIfCancellationRequested();
                totalFiles++;
                totalBytes += item.SizeBytes;

                var displayPath = string.IsNullOrWhiteSpace(item.RelativePath) ? item.FileName : item.RelativePath;
                var ext = Path.GetExtension(item.FileName).ToLowerInvariant();

                Log(consoleLogs, "INSPECT", $"Ingesting [{totalFiles}]: {displayPath} ({item.SizeBytes} bytes)...");

                try
                {
                    double entropy = _entropyCalculator.CalculateEntropy(item.Content);
                    var (isEntropyAnomalous, entropySeverity, entropyDesc) = _entropyCalculator.AssessEntropy(item.FileName, entropy);

                    if (isEntropyAnomalous)
                    {
                        Log(consoleLogs, "WARN", $"Entropy flag on '{displayPath}': {entropy:F2}/8.00 - {entropyDesc}");
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = displayPath,
                            FileName = item.FileName,
                            FileSizeBytes = item.SizeBytes,
                            Category = "Entropy Anomaly",
                            Title = "Unexpected Entropy Rating",
                            Details = entropyDesc,
                            Severity = entropySeverity,
                            Entropy = entropy,
                            ClaimedExtension = ext
                        });
                    }

                    var (isMagicMatch, detectedType, magicDetails) = _magicByteValidator.Validate(item.FileName, item.Content);
                    if (!isMagicMatch)
                    {
                        var severity = detectedType.Contains("PE Executable") || detectedType.Contains("ELF Binary")
                            ? AnomalySeverity.Critical
                            : AnomalySeverity.High;

                        Log(consoleLogs, "ALERT", $"Magic byte mismatch on '{displayPath}': Declared '{ext}' vs Detected '{detectedType}'");

                        anomalies.Add(new FileAnomalyRecord
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
                            IsMagicByteMismatch = true
                        });
                    }

                    var signatureAnomalies = _signatureManager.ScanForSignatures(displayPath, item.FileName, item.Content, entropy);
                    foreach (var sigAnomaly in signatureAnomalies)
                    {
                        Log(consoleLogs, "ALERT", $"Signature anomaly on '{displayPath}': {sigAnomaly.Title}");
                        anomalies.Add(sigAnomaly);
                    }

                    if (_archiveExtractor.IsSupportedArchive(item.FileName, item.Content))
                    {
                        Log(consoleLogs, "ARCHIVE", $"Deep inspecting archive container: {displayPath}");
                        var archiveAnomalies = _archiveExtractor.InspectArchive(displayPath, item.FileName, item.Content);
                        foreach (var archAnomaly in archiveAnomalies)
                        {
                            Log(consoleLogs, "ALERT", $"Archive hazard in '{displayPath}': {archAnomaly.Title} ({archAnomaly.Details})");
                            anomalies.Add(archAnomaly);
                        }
                    }
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
                        ClaimedExtension = ext
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
                        ClaimedExtension = ext
                    });
                }
            }

            stopwatch.Stop();
            var report = _reportGenerator.GenerateReport(anomalies, consoleLogs, totalFiles, totalBytes, stopwatch.Elapsed.TotalMilliseconds);
            return Task.FromResult(report);
        }

        private static void Log(List<string> logs, string tag, string message)
        {
            var timestamp = DateTime.UtcNow.ToString("HH:mm:ss.fff");
            logs.Add($"[{timestamp}] [{tag}] {message}");
        }
    }
}
