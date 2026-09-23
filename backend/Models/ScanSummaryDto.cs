using System;

namespace FileAnomalyScanner.Models
{
    public class ScanSummaryDto
    {
        public int TotalFilesScanned { get; set; }
        public long TotalBytesScanned { get; set; }
        public int TotalAnomaliesFound { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int InfoCount { get; set; }
        public double DurationMs { get; set; }
        public DateTime ScanCompletedAt { get; set; } = DateTime.UtcNow;
    }
}
