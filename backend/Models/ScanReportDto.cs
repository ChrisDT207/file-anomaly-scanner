using System;
using System.Collections.Generic;

namespace FileAnomalyScanner.Models
{
    public class ScanReportDto
    {
        public string ScanId { get; set; } = Guid.NewGuid().ToString("N");
        public ScanSummaryDto Summary { get; set; } = new();
        public List<FileAnomalyRecord> Anomalies { get; set; } = new();
        public List<FileScanMetadata> Files { get; set; } = new();
        public List<string> ConsoleLogs { get; set; } = new();
        public bool Success { get; set; } = true;
        public string? ErrorMessage { get; set; }
    }
}
