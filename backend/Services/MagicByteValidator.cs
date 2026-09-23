using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using FileAnomalyScanner.Interfaces;

namespace FileAnomalyScanner.Services
{
    public class MagicByteValidator : IMagicByteValidator
    {
        private class SignatureEntry
        {
            public string FileType { get; set; } = string.Empty;
            public byte[] MagicBytes { get; set; } = Array.Empty<byte>();
            public int Offset { get; set; } = 0;
            public string[] ValidExtensions { get; set; } = Array.Empty<string>();
            public bool IsExecutableOrBinary { get; set; }
        }

        private readonly List<SignatureEntry> _signatures = new()
        {
            new SignatureEntry
            {
                FileType = "Windows PE Executable / DLL",
                MagicBytes = new byte[] { 0x4D, 0x5A },
                Offset = 0,
                ValidExtensions = new[] { ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx" },
                IsExecutableOrBinary = true
            },
            new SignatureEntry
            {
                FileType = "Linux ELF Binary",
                MagicBytes = new byte[] { 0x7F, 0x45, 0x4C, 0x46 },
                Offset = 0,
                ValidExtensions = new[] { ".elf", ".so", ".bin", "" },
                IsExecutableOrBinary = true
            },
            new SignatureEntry
            {
                FileType = "PDF Document",
                MagicBytes = new byte[] { 0x25, 0x50, 0x44, 0x46 },
                Offset = 0,
                ValidExtensions = new[] { ".pdf" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "PNG Image",
                MagicBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A },
                Offset = 0,
                ValidExtensions = new[] { ".png" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "JPEG Image",
                MagicBytes = new byte[] { 0xFF, 0xD8, 0xFF },
                Offset = 0,
                ValidExtensions = new[] { ".jpg", ".jpeg", ".jpe" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "GIF Image",
                MagicBytes = new byte[] { 0x47, 0x49, 0x46, 0x38 },
                Offset = 0,
                ValidExtensions = new[] { ".gif" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "ZIP Archive / OpenXML Document",
                MagicBytes = new byte[] { 0x50, 0x4B, 0x03, 0x04 },
                Offset = 0,
                ValidExtensions = new[] { ".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".nupkg" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "GZIP Compressed File",
                MagicBytes = new byte[] { 0x1F, 0x8B },
                Offset = 0,
                ValidExtensions = new[] { ".gz", ".tgz" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "7-Zip Archive",
                MagicBytes = new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C },
                Offset = 0,
                ValidExtensions = new[] { ".7z" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "BMP Image",
                MagicBytes = new byte[] { 0x42, 0x4D },
                Offset = 0,
                ValidExtensions = new[] { ".bmp" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "RIFF Container (WEBP/WAV/AVI)",
                MagicBytes = new byte[] { 0x52, 0x49, 0x46, 0x46 },
                Offset = 0,
                ValidExtensions = new[] { ".webp", ".wav", ".avi" },
                IsExecutableOrBinary = false
            },
            new SignatureEntry
            {
                FileType = "Shell Script (Shebang)",
                MagicBytes = new byte[] { 0x23, 0x21 },
                Offset = 0,
                ValidExtensions = new[] { ".sh", ".bash", ".zsh", ".py", ".pl", ".rb", "" },
                IsExecutableOrBinary = false
            }
        };

        private readonly HashSet<string> _plainTextExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".txt", ".log", ".json", ".xml", ".csv", ".tsv", ".md", ".html", ".htm",
            ".css", ".js", ".jsx", ".ts", ".tsx", ".yaml", ".yml", ".ini", ".cfg",
            ".conf", ".sql", ".cs", ".java", ".py", ".c", ".cpp", ".h"
        };

        public (bool IsMatch, string DetectedType, string Details) Validate(string fileName, byte[] content)
        {
            if (content == null || content.Length == 0)
            {
                return (true, "Empty File", "File content is zero bytes.");
            }

            var extension = Path.GetExtension(fileName).ToLowerInvariant();

            // Check against known binary signatures
            foreach (var sig in _signatures)
            {
                if (MatchesSignature(content, sig))
                {
                    bool validExtension = sig.ValidExtensions.Contains(extension);

                    if (validExtension)
                    {
                        return (true, sig.FileType, $"Header matches declared extension '{extension}'.");
                    }

                    // Dangerous mismatch: Claiming to be text/image/doc but has executable/binary header
                    if (sig.IsExecutableOrBinary)
                    {
                        return (false, sig.FileType,
                            $"CRITICAL: File claims extension '{extension}', but magic bytes match '{sig.FileType}' ({FormatHex(sig.MagicBytes)}). Possible malware disguise.");
                    }

                    return (false, sig.FileType,
                        $"File claims extension '{extension}', but header magic bytes match '{sig.FileType}'. Expected one of: {string.Join(", ", sig.ValidExtensions)}.");
                }
            }

            // If file claims to be plain text, ensure it doesn't contain high density of null/binary control bytes
            if (_plainTextExtensions.Contains(extension))
            {
                int sampleLength = Math.Min(content.Length, 512);
                int nullCount = 0;
                for (int i = 0; i < sampleLength; i++)
                {
                    if (content[i] == 0x00)
                    {
                        nullCount++;
                    }
                }

                if (nullCount > 2)
                {
                    return (false, "Binary / Unknown Format",
                        $"File claims to be plain text ({extension}), but contains embedded binary null bytes in first {sampleLength} bytes.");
                }

                return (true, "Plain Text / Source Code", "File content conforms to plain text encoding.");
            }

            return (true, "Generic Binary / Unindexed Signature",
                $"No conflicting signature identified for extension '{extension}'.");
        }

        public IReadOnlyDictionary<string, string> GetSupportedSignatures()
        {
            var dict = new Dictionary<string, string>();
            foreach (var sig in _signatures)
            {
                dict[sig.FileType] = FormatHex(sig.MagicBytes);
            }
            return dict;
        }

        private static bool MatchesSignature(byte[] content, SignatureEntry sig)
        {
            if (content.Length < sig.Offset + sig.MagicBytes.Length)
            {
                return false;
            }

            for (int i = 0; i < sig.MagicBytes.Length; i++)
            {
                if (content[sig.Offset + i] != sig.MagicBytes[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static string FormatHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", " ");
        }
    }
}
