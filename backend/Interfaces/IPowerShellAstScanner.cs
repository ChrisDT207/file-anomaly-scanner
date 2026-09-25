using System.Collections.Generic;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface IPowerShellAstScanner
    {
        bool IsPowerShellTarget(string fileName, string? textSnippet = null);
        List<FileAnomalyRecord> AnalyzeScript(string filePath, string fileName, string scriptText);
    }
}
