using System.Collections.Generic;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface IMagicByteValidator
    {
        (bool IsMatch, string DetectedType, string Details) Validate(string fileName, byte[] content);

        IReadOnlyDictionary<string, string> GetSupportedSignatures();
    }
}
