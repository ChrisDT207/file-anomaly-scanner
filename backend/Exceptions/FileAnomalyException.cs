using System;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Exceptions
{
    public class FileAnomalyException : Exception
    {
        public string FileName { get; }
        public string AnomalyType { get; }
        public AnomalySeverity Severity { get; }
        public string? PayloadSnippet { get; }

        public FileAnomalyException(string message, string fileName, string anomalyType, AnomalySeverity severity = AnomalySeverity.High, string? payloadSnippet = null)
            : base(message)
        {
            FileName = fileName;
            AnomalyType = anomalyType;
            Severity = severity;
            PayloadSnippet = payloadSnippet;
        }

        public FileAnomalyException(string message, Exception innerException, string fileName, string anomalyType, AnomalySeverity severity = AnomalySeverity.High)
            : base(message, innerException)
        {
            FileName = fileName;
            AnomalyType = anomalyType;
            Severity = severity;
        }
    }
}
