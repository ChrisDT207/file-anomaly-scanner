using System.Collections.Generic;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface IReportGenerator
    {
        ScanReportDto GenerateReport(
            List<FileAnomalyRecord> anomalies,
            List<string> consoleLogs,
            int totalFiles,
            long totalBytes,
            double durationMs);
    }
}
