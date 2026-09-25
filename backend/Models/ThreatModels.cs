using System;
using System.Collections.Generic;

namespace FileAnomalyScanner.Models
{
    public class VirusTotalReport
    {
        public string Sha256 { get; set; } = string.Empty;
        public string Status { get; set; } = "NotChecked"; // Clean, Malicious, Suspicious, NotFound, RateLimited, Error, NotConfigured
        public int MaliciousCount { get; set; }
        public int SuspiciousCount { get; set; }
        public int UndetectedCount { get; set; }
        public int HarmlessCount { get; set; }
        public int TotalEngines => MaliciousCount + SuspiciousCount + UndetectedCount + HarmlessCount;
        public string? SuggestedThreatLabel { get; set; }
        public int Reputation { get; set; }
        public Dictionary<string, string> VendorDetections { get; set; } = new();
        public string Permalink { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
    }

    public class SafeBrowsingMatch
    {
        public string Url { get; set; } = string.Empty;
        public string ThreatType { get; set; } = string.Empty;
        public string PlatformType { get; set; } = string.Empty;
    }

    public class SafeBrowsingReport
    {
        public List<string> UrlsChecked { get; set; } = new();
        public List<SafeBrowsingMatch> Matches { get; set; } = new();
        public bool HasThreats => Matches.Count > 0;
        public string? ErrorMessage { get; set; }
    }

    public class FileScanMetadata
    {
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public string Sha256 { get; set; } = string.Empty;
        public double Entropy { get; set; }
        public string DetectedType { get; set; } = string.Empty;
        public VirusTotalReport? VirusTotal { get; set; }
        public SafeBrowsingReport? SafeBrowsing { get; set; }
        public int AnomalyCount { get; set; }
        public AnomalySeverity HighestSeverity { get; set; } = AnomalySeverity.Info;
        public string Status { get; set; } = "Clean"; // Clean, Suspicious, Malicious, Anomalous
    }
}
