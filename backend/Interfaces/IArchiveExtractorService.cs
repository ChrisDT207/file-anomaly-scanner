using System.Collections.Generic;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface IArchiveExtractorService
    {
        List<FileAnomalyRecord> InspectArchive(string parentPath, string fileName, byte[] content);

        bool IsSupportedArchive(string fileName, byte[] content);
    }
}
