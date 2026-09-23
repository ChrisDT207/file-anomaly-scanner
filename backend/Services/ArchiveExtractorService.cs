using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using FileAnomalyScanner.Exceptions;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    /// <summary>
    /// Safely inspects archive payloads in-memory, detecting Zip-Slip traversal, Zip-Bomb amplification, and embedded high-risk files.
    /// </summary>
    public class ArchiveExtractorService : IArchiveExtractorService
    {
        private const long MaxAllowedUncompressedBytes = 100 * 1024 * 1024; // 100 MB safety threshold
        private const double MaxAllowedCompressionRatio = 100.0;
        private const int MaxEntryCount = 5000;

        private static readonly HashSet<string> DangerousNestedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".wsh", ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".msh", ".msh1", ".msh2",
            ".mshxml", ".msh1xml", ".msh2xml", ".dll", ".sys", ".hta", ".cpl", ".inf", ".reg"
        };

        public bool IsSupportedArchive(string fileName, byte[] content)
        {
            if (content == null || content.Length < 4) return false;

            var ext = Path.GetExtension(fileName).ToLowerInvariant();
            if (ext is ".zip" or ".jar" or ".war" or ".apk" or ".nupkg" or ".docx" or ".xlsx" or ".pptx")
            {
                return true;
            }

            // Check PK header magic bytes (50 4B 03 04)
            return content[0] == 0x50 && content[1] == 0x4B && content[2] == 0x03 && content[3] == 0x04;
        }

        public List<FileAnomalyRecord> InspectArchive(string parentPath, string fileName, byte[] content)
        {
            var anomalies = new List<FileAnomalyRecord>();

            if (!IsSupportedArchive(fileName, content))
            {
                return anomalies;
            }

            try
            {
                using var memoryStream = new MemoryStream(content, writable: false);
                using var archive = new ZipArchive(memoryStream, ZipArchiveMode.Read, leaveOpen: false);

                if (archive.Entries.Count > MaxEntryCount)
                {
                    anomalies.Add(new FileAnomalyRecord
                    {
                        FilePath = parentPath,
                        FileName = fileName,
                        FileSizeBytes = content.Length,
                        Category = "Archive Hazard (Bomb/Flood)",
                        Title = "Excessive Archive Entry Count",
                        Details = $"Archive contains {archive.Entries.Count} entries, exceeding safe limit ({MaxEntryCount}). Potential denial-of-service vector.",
                        Severity = AnomalySeverity.High
                    });
                    return anomalies;
                }

                long totalUncompressedSize = 0;

                foreach (var entry in archive.Entries)
                {
                    var entryName = entry.FullName;

                    // 1. Directory Traversal / Zip-Slip Detection
                    if (entryName.Contains("../") || entryName.Contains(@"..\") ||
                        entryName.StartsWith("/") || entryName.StartsWith(@"\"))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = $"{parentPath} -> {entryName}",
                            FileName = Path.GetFileName(entryName),
                            FileSizeBytes = entry.CompressedLength,
                            Category = "Archive Hazard (Zip-Slip)",
                            Title = "Zip-Slip Path Traversal Detected",
                            Details = $"Malicious path traversal sequence detected in archive entry: '{entryName}'. Extraction would write outside target directory.",
                            Severity = AnomalySeverity.Critical
                        });
                    }

                    // 2. Compression Ratio / Zip-Bomb Check
                    totalUncompressedSize += entry.Length;
                    if (entry.CompressedLength > 0)
                    {
                        double ratio = (double)entry.Length / entry.CompressedLength;
                        if (ratio > MaxAllowedCompressionRatio && entry.Length > 10 * 1024 * 1024)
                        {
                            anomalies.Add(new FileAnomalyRecord
                            {
                                FilePath = $"{parentPath} -> {entryName}",
                                FileName = Path.GetFileName(entryName),
                                FileSizeBytes = entry.CompressedLength,
                                Category = "Archive Hazard (Zip-Bomb)",
                                Title = "Abnormal Compression Amplification Ratio",
                                Details = $"Entry '{entryName}' has an abnormal compression ratio of {ratio:F1}:1 (Uncompressed: {entry.Length / 1024 / 1024} MB, Compressed: {entry.CompressedLength / 1024} KB).",
                                Severity = AnomalySeverity.High
                            });
                        }
                    }

                    // 3. Dangerous Executable or Script Embedded in Archive
                    var innerExt = Path.GetExtension(entry.Name).ToLowerInvariant();
                    if (DangerousNestedExtensions.Contains(innerExt))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = $"{parentPath} -> {entryName}",
                            FileName = entry.Name,
                            FileSizeBytes = entry.Length,
                            Category = "High-Risk Embedded Payload",
                            Title = "Executable/Script Inside Archive",
                            Details = $"Archive contains executable or script payload '{entry.Name}' with extension '{innerExt}'. Often employed in spear-phishing or delivery attachments.",
                            Severity = AnomalySeverity.High,
                            ClaimedExtension = innerExt
                        });
                    }
                }

                if (totalUncompressedSize > MaxAllowedUncompressedBytes)
                {
                    anomalies.Add(new FileAnomalyRecord
                    {
                        FilePath = parentPath,
                        FileName = fileName,
                        FileSizeBytes = content.Length,
                        Category = "Archive Hazard (Zip-Bomb)",
                        Title = "Cumulative Decompression Size Exceeded",
                        Details = $"Cumulative uncompressed size ({totalUncompressedSize / 1024 / 1024} MB) exceeds maximum safe analysis ceiling ({MaxAllowedUncompressedBytes / 1024 / 1024} MB).",
                        Severity = AnomalySeverity.High
                    });
                }
            }
            catch (InvalidDataException ex)
            {
                anomalies.Add(new FileAnomalyRecord
                {
                    FilePath = parentPath,
                    FileName = fileName,
                    FileSizeBytes = content.Length,
                    Category = "Malformed Archive",
                    Title = "Corrupted or Tampered Archive Headers",
                    Details = $"Failed to parse archive structure: {ex.Message}. Archive headers may be tampered or intentionally corrupted.",
                    Severity = AnomalySeverity.Medium
                });
            }
            catch (Exception ex)
            {
                anomalies.Add(new FileAnomalyRecord
                {
                    FilePath = parentPath,
                    FileName = fileName,
                    FileSizeBytes = content.Length,
                    Category = "Archive Analysis Failure",
                    Title = "Exception During Archive Traversal",
                    Details = $"Archive inspection interrupted: {ex.Message}",
                    Severity = AnomalySeverity.Low
                });
            }

            return anomalies;
        }
    }
}
