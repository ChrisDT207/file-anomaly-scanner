using System.Collections.Generic;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface ISuspiciousSignatureManager
    {
        List<FileAnomalyRecord> ScanForSignatures(string relativePath, string fileName, byte[] content, double entropy);

        IReadOnlyList<string> GetActiveRules();
    }
}
