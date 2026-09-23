using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface IEntropyCalculator
    {
        double CalculateEntropy(byte[] data);

        (bool IsAnomalous, AnomalySeverity Severity, string Description) AssessEntropy(string fileName, double entropy);
    }
}
