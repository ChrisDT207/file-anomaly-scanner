using System;
using System.Collections.Generic;

namespace FileAnomalyScanner.Models
{
    public class CloudSandboxReportDto
    {
        public string Sha256 { get; set; } = string.Empty;
        public string Status { get; set; } = "Available"; // Available, NotFound, Pending, RateLimited, Error, NotConfigured
        public List<string> SandboxEngines { get; set; } = new();
        public List<ProcessExecutionDto> ProcessesCreated { get; set; } = new();
        public List<ProcessTreeNodeDto> ProcessTree { get; set; } = new();
        public NetworkActivityDto NetworkActivity { get; set; } = new();
        public TamperingActivityDto FileAndRegistryTampering { get; set; } = new();
        public List<MitreTechniqueDto> MitreAttackSignatures { get; set; } = new();
        public VerdictSummaryDto VerdictSummary { get; set; } = new();
        public string? AnalysisId { get; set; }
        public DateTime? LastAnalysisDate { get; set; }
        public string? ErrorMessage { get; set; }
        public string Permalink { get; set; } = string.Empty;
    }

    public class ProcessExecutionDto
    {
        public string ProcessName { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
        public string? Pid { get; set; }
        public string? ParentPid { get; set; }
    }

    public class ProcessTreeNodeDto
    {
        public string ProcessId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
        public List<ProcessTreeNodeDto> Children { get; set; } = new();
    }

    public class DnsLookupDto
    {
        public string Hostname { get; set; } = string.Empty;
        public List<string> ResolvedIps { get; set; } = new();
    }

    public class ContactedIpDto
    {
        public string IpAddress { get; set; } = string.Empty;
        public int? Port { get; set; }
        public string? Protocol { get; set; }
    }

    public class HttpRequestDto
    {
        public string Url { get; set; } = string.Empty;
        public string Method { get; set; } = "GET";
        public int? ResponseCode { get; set; }
        public string? UserAgent { get; set; }
    }

    public class NetworkActivityDto
    {
        public List<DnsLookupDto> DnsLookups { get; set; } = new();
        public List<ContactedIpDto> ContactedIps { get; set; } = new();
        public List<HttpRequestDto> HttpRequests { get; set; } = new();
    }

    public class DroppedFileDto
    {
        public string Path { get; set; } = string.Empty;
        public string? Sha256 { get; set; }
        public string? Type { get; set; }
        public long? SizeBytes { get; set; }
    }

    public class RegistryKeySetDto
    {
        public string Key { get; set; } = string.Empty;
        public string? Value { get; set; }
    }

    public class TamperingActivityDto
    {
        public List<DroppedFileDto> FilesDropped { get; set; } = new();
        public List<string> FilesWritten { get; set; } = new();
        public List<string> FilesDeleted { get; set; } = new();
        public List<RegistryKeySetDto> RegistryKeysSet { get; set; } = new();
        public List<string> RegistryKeysDeleted { get; set; } = new();
    }

    public class MitreTechniqueDto
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string? Tactic { get; set; }
        public string Severity { get; set; } = "INFO"; // CRITICAL, HIGH, MEDIUM, LOW, INFO
        public string Description { get; set; } = string.Empty;
    }

    public class VerdictSummaryDto
    {
        public string Verdict { get; set; } = "LikelyFalsePositive"; // TruePositive, LikelyFalsePositive, Suspicious, Inconclusive
        public int ConfidenceScore { get; set; } = 50; // 0 - 100
        public string Title { get; set; } = string.Empty;
        public string Justification { get; set; } = string.Empty;
        public List<string> Indicators { get; set; } = new();
        public bool IsTruePositive => Verdict == "TruePositive";
        public bool IsLikelyFalsePositive => Verdict == "LikelyFalsePositive";
    }

    public class RemediationRequestDto
    {
        public string FilePath { get; set; } = string.Empty;
        public string? Sha256 { get; set; }
    }

    public class RemediationReceiptDto
    {
        public bool Success { get; set; }
        public string RemediatedPath { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string ShredMethod { get; set; } = "Cryptographic Overwrite (Random + Zero Fill + Truncate + Unlink)";
        public long BytesOverwritten { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
    }

    public class AnalysisStatusDto
    {
        public string AnalysisId { get; set; } = string.Empty;
        public string Status { get; set; } = "queued"; // queued, in-progress, completed, error
        public string? Sha256 { get; set; }
        public int MaliciousCount { get; set; }
        public int SuspiciousCount { get; set; }
        public int UndetectedCount { get; set; }
        public string? ErrorMessage { get; set; }
    }
}
