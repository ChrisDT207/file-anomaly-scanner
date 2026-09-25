using System;
using System.Collections.Generic;
using System.Linq;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    public class ReportGenerator : IReportGenerator
    {
        public ScanReportDto GenerateReport(
            List<FileAnomalyRecord> anomalies,
            List<string> consoleLogs,
            int totalFiles,
            long totalBytes,
            double durationMs,
            List<FileScanMetadata>? files = null)
        {
            var vtFlagged = anomalies.Count(a => a.Category.Contains("VirusTotal", StringComparison.OrdinalIgnoreCase));
            var sbThreats = anomalies.Count(a => a.Category.Contains("Safe Browsing", StringComparison.OrdinalIgnoreCase));
            var zeroDayCount = files?.Count(f => f.IsNovelZeroDaySuspicion) ?? 0;

            var summary = new ScanSummaryDto
            {
                TotalFilesScanned = totalFiles,
                TotalBytesScanned = totalBytes,
                TotalAnomaliesFound = anomalies.Count,
                CriticalCount = anomalies.Count(a => a.Severity == AnomalySeverity.Critical),
                HighCount = anomalies.Count(a => a.Severity == AnomalySeverity.High),
                MediumCount = anomalies.Count(a => a.Severity == AnomalySeverity.Medium),
                LowCount = anomalies.Count(a => a.Severity == AnomalySeverity.Low),
                InfoCount = anomalies.Count(a => a.Severity == AnomalySeverity.Info),
                VirusTotalFlaggedCount = vtFlagged,
                SafeBrowsingThreatCount = sbThreats,
                NovelZeroDayThreatCount = zeroDayCount,
                DurationMs = Math.Round(durationMs, 2),
                ScanCompletedAt = DateTime.UtcNow
            };

            var timestamp = DateTime.UtcNow.ToString("HH:mm:ss.fff");
            consoleLogs.Add($"[{timestamp}] [REPORT] Scan completed in {durationMs:F1}ms.");
            consoleLogs.Add($"[{timestamp}] [REPORT] Total Files: {totalFiles} | Total Data: {FormatBytes(totalBytes)}.");
            consoleLogs.Add($"[{timestamp}] [REPORT] Anomalies Flagged: {anomalies.Count} (Critical: {summary.CriticalCount}, High: {summary.HighCount}, Medium: {summary.MediumCount}, Low: {summary.LowCount}).");

            if (vtFlagged > 0)
            {
                consoleLogs.Add($"[{timestamp}] [THREAT INTEL] [ALERT] VirusTotal identified malware detections on {vtFlagged} file(s).");
            }
            if (sbThreats > 0)
            {
                consoleLogs.Add($"[{timestamp}] [THREAT INTEL] [ALERT] Google Safe Browsing identified {sbThreats} blacklisted URL threat(s).");
            }
            if (zeroDayCount > 0)
            {
                consoleLogs.Add($"[{timestamp}] [THREAT INTEL] [WARN] Identified {zeroDayCount} unseen zero-day candidate(s) with high local anomaly scores.");
            }

            if (anomalies.Count == 0)
            {
                consoleLogs.Add($"[{timestamp}] [REPORT] STATUS: CLEAN. No structural, virus, or heuristic anomalies detected.");
            }
            else
            {
                consoleLogs.Add($"[{timestamp}] [REPORT] STATUS: ATTENTION REQUIRED. Detected {anomalies.Count} security anomaly/anomalies.");
            }

            return new ScanReportDto
            {
                Summary = summary,
                Anomalies = anomalies,
                Files = files ?? new List<FileScanMetadata>(),
                ConsoleLogs = consoleLogs,
                Success = true
            };
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{(bytes / 1024.0):F2} KB";
            return $"{(bytes / (1024.0 * 1024.0)):F2} MB";
        }
    }
}
