using System;

namespace FileAnomalyScanner.Models
{
    public class FileAnomalyRecord
    {
        public string FilePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public long FileSizeBytes { get; set; }
        public string Category { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public AnomalySeverity Severity { get; set; }
        public double Entropy { get; set; }
        public string ClaimedExtension { get; set; } = string.Empty;
        public string DetectedType { get; set; } = string.Empty;
        public bool IsMagicByteMismatch { get; set; }
        public string Sha256Hash { get; set; } = string.Empty;
        public VirusTotalReport? VirusTotalResult { get; set; }
        public SafeBrowsingMatch? SafeBrowsingMatch { get; set; }
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }
}
