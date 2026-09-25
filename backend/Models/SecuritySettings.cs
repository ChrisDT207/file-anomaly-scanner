using System;

namespace FileAnomalyScanner.Models
{
    public class SecuritySettings
    {
        public string VirusTotalApiKey { get; set; } = string.Empty;
        public bool VirusTotalEnabled { get; set; } = true;
        public string GoogleSafeBrowsingApiKey { get; set; } = string.Empty;
        public bool GoogleSafeBrowsingEnabled { get; set; } = true;
        public int MaxVirusTotalLookupsPerBatch { get; set; } = 5;
        public bool CheckEmbeddedUrlsWithSafeBrowsing { get; set; } = true;
    }

    public class SecuritySettingsDto
    {
        public bool VirusTotalConfigured { get; set; }
        public string MaskedVirusTotalApiKey { get; set; } = string.Empty;
        public bool VirusTotalEnabled { get; set; }
        public bool SafeBrowsingConfigured { get; set; }
        public string MaskedSafeBrowsingApiKey { get; set; } = string.Empty;
        public bool SafeBrowsingEnabled { get; set; }
        public int MaxVirusTotalLookupsPerBatch { get; set; }
        public bool CheckEmbeddedUrlsWithSafeBrowsing { get; set; }
    }

    public class UpdateSecuritySettingsRequest
    {
        public string? VirusTotalApiKey { get; set; }
        public bool? VirusTotalEnabled { get; set; }
        public string? GoogleSafeBrowsingApiKey { get; set; }
        public bool? GoogleSafeBrowsingEnabled { get; set; }
        public int? MaxVirusTotalLookupsPerBatch { get; set; }
        public bool? CheckEmbeddedUrlsWithSafeBrowsing { get; set; }
    }

    public class TestApiRequest
    {
        public string? ApiKey { get; set; }
    }

    public class TestApiResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public int? EnginesCount { get; set; }
        public string? Details { get; set; }
    }
}
