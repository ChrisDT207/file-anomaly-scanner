using System.IO;

namespace FileAnomalyScanner.Models
{
    public class FileScanItem
    {
        public string RelativePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public byte[] Content { get; set; } = Array.Empty<byte>();
    }
}
