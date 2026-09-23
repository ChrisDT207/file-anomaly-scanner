using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    public class SuspiciousSignatureManager : ISuspiciousSignatureManager
    {
        private static readonly string[] DangerousEndExtensions =
        {
            ".exe", ".scr", ".vbs", ".js", ".jse", ".bat", ".cmd", ".ps1", ".hta", ".pif", ".cpl", ".jar", ".wsf"
        };

        private static readonly string[] DocumentOrMediaExtensions =
        {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip"
        };

        private static readonly byte[] DosStubBytes = Encoding.ASCII.GetBytes("This program cannot be run in DOS mode");
        private static readonly byte[] MzBytes = new byte[] { 0x4D, 0x5A };

        public List<FileAnomalyRecord> ScanForSignatures(string relativePath, string fileName, byte[] content, double entropy)
        {
            var anomalies = new List<FileAnomalyRecord>();

            if (fileName.Contains('\u202E') || relativePath.Contains('\u202E'))
            {
                anomalies.Add(new FileAnomalyRecord
                {
                    FilePath = relativePath,
                    FileName = fileName,
                    FileSizeBytes = content.Length,
                    Category = "Evasive Naming (RTLO Spoofing)",
                    Title = "Unicode Right-to-Left Override Character Detected",
                    Details = "Filename incorporates Unicode U+202E (RTLO) character. This technique disguises the true executable file extension in Windows Explorer.",
                    Severity = AnomalySeverity.Critical,
                    Entropy = entropy
                });
            }

            var lowerName = fileName.ToLowerInvariant();
            foreach (var docExt in DocumentOrMediaExtensions)
            {
                foreach (var dangerExt in DangerousEndExtensions)
                {
                    if (lowerName.EndsWith(docExt + dangerExt))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = relativePath,
                            FileName = fileName,
                            FileSizeBytes = content.Length,
                            Category = "Evasive Naming (Double Extension)",
                            Title = "Deceptive Double Extension Pattern",
                            Details = $"File masquerades as a safe document/media '{docExt}' but concludes with executable extension '{dangerExt}'.",
                            Severity = AnomalySeverity.High,
                            Entropy = entropy,
                            ClaimedExtension = dangerExt
                        });
                        break;
                    }
                }
            }

            var ext = Path.GetExtension(fileName).ToLowerInvariant();
            bool isDeclaredExecutable = ext is ".exe" or ".dll" or ".sys" or ".scr";

            if (!isDeclaredExecutable && content.Length > 128)
            {
                int dosIndex = IndexOfSubArray(content, DosStubBytes);
                if (dosIndex >= 0)
                {
                    anomalies.Add(new FileAnomalyRecord
                    {
                        FilePath = relativePath,
                        FileName = fileName,
                        FileSizeBytes = content.Length,
                        Category = "Polyglot / Embedded PE Binary",
                        Title = "Embedded Windows PE Header Located",
                        Details = $"Detected embedded DOS execution stub at byte offset {dosIndex}. This non-executable file appears to be a weaponized polyglot payload.",
                        Severity = AnomalySeverity.Critical,
                        Entropy = entropy,
                        ClaimedExtension = ext,
                        DetectedType = "Embedded Portable Executable (PE)"
                    });
                }
                else
                {
                    int mzIndex = IndexOfSubArray(content, MzBytes, startIndex: 4);
                    if (mzIndex >= 4 && mzIndex < 2048)
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = relativePath,
                            FileName = fileName,
                            FileSizeBytes = content.Length,
                            Category = "Polyglot / Embedded Binary",
                            Title = "Secondary MZ Magic Header Detected",
                            Details = $"Found secondary 'MZ' executable signature at offset {mzIndex} inside file declared as '{ext}'.",
                            Severity = AnomalySeverity.Medium,
                            Entropy = entropy,
                            ClaimedExtension = ext
                        });
                    }
                }
            }

            if (content.Length > 0 && content.Length <= 5 * 1024 * 1024) 
            {
                string textSnippet;
                try
                {
                    textSnippet = Encoding.UTF8.GetString(content, 0, Math.Min(content.Length, 32768));
                }
                catch
                {
                    textSnippet = string.Empty;
                }

                if (!string.IsNullOrEmpty(textSnippet))
                {
                    if (Regex.IsMatch(textSnippet, @"powershell(\.exe)?\s+(-[a-zA-Z]+\s+)*(-enc|-encodedcommand|-e)\s+[A-Za-z0-9+/=]{20,}", RegexOptions.IgnoreCase))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = relativePath,
                            FileName = fileName,
                            FileSizeBytes = content.Length,
                            Category = "Malicious Script Indicator",
                            Title = "Encoded PowerShell Command Execution",
                            Details = "Detected base64-encoded PowerShell execution pattern with stealth invocation flags.",
                            Severity = AnomalySeverity.Critical,
                            Entropy = entropy
                        });
                    }
                    else if (Regex.IsMatch(textSnippet, @"(DownloadString|DownloadFile|IEX\s*\(|Invoke-Expression|Net\.WebClient)", RegexOptions.IgnoreCase))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = relativePath,
                            FileName = fileName,
                            FileSizeBytes = content.Length,
                            Category = "Malicious Script Indicator",
                            Title = "Remote Download / Dynamic Execution Cradle",
                            Details = "Detected cradle syntax (Net.WebClient / DownloadString / Invoke-Expression) used to pull remote stages.",
                            Severity = AnomalySeverity.High,
                            Entropy = entropy
                        });
                    }

                    if (Regex.IsMatch(textSnippet, @"(eval\s*\(\s*base64_decode|passthru\s*\(|shell_exec\s*\(|system\s*\(\s*\$_(GET|POST|REQUEST))", RegexOptions.IgnoreCase))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = relativePath,
                            FileName = fileName,
                            FileSizeBytes = content.Length,
                            Category = "Webshell / Backdoor Signature",
                            Title = "Arbitrary Command Execution / PHP Webshell",
                            Details = "Detected classic web-shell arbitrary code execution primitives (eval(base64_decode) / passthru / system).",
                            Severity = AnomalySeverity.Critical,
                            Entropy = entropy
                        });
                    }
                }
            }

            return anomalies;
        }

        public IReadOnlyList<string> GetActiveRules()
        {
            return new List<string>
            {
                "RTLO (Right-to-Left Override) Unicode evasion check (U+202E)",
                "Double file extension deception (.doc.exe, .pdf.scr, etc.)",
                "Embedded PE header & DOS stub detection in non-executables (Polyglot)",
                "Encoded PowerShell execution cradles (-EncodedCommand / IEX)",
                "Web shell arbitrary code execution triggers (eval, passthru, system)",
                "Abnormal Shannon entropy thresholding per file type"
            };
        }

        private static int IndexOfSubArray(byte[] source, byte[] pattern, int startIndex = 0)
        {
            if (pattern.Length == 0 || source.Length < pattern.Length + startIndex)
                return -1;

            int limit = source.Length - pattern.Length;
            for (int i = startIndex; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (source[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }

            return -1;
        }
    }
}
