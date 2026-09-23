using System;
using System.IO;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    public class EntropyCalculator : IEntropyCalculator
    {
        public double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return 0.0;
            }

            var counts = new int[256];
            for (int i = 0; i < data.Length; i++)
            {
                counts[data[i]]++;
            }

            double entropy = 0.0;
            double len = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;

                double p = counts[i] / len;
                entropy -= p * Math.Log2(p);
            }

            return Math.Round(entropy, 4);
        }

        public (bool IsAnomalous, AnomalySeverity Severity, string Description) AssessEntropy(string fileName, double entropy)
        {
            var ext = Path.GetExtension(fileName).ToLowerInvariant();

            bool isTextType = ext is ".txt" or ".csv" or ".tsv" or ".log" or ".json" or ".xml" or ".yml" or ".yaml" or ".md" or ".sql";

            if (isTextType && entropy >= 7.1)
            {
                return (true, AnomalySeverity.High,
                    $"Abnormally high entropy ({entropy:F2}/8.00) in text document '{ext}'. Normal text typically scores between 3.0 and 5.2. Potential base64/encrypted payload.");
            }

            if (isTextType && entropy >= 6.4)
            {
                return (true, AnomalySeverity.Medium,
                    $"Elevated entropy ({entropy:F2}/8.00) in text document '{ext}'. May contain encoded strings, large hexadecimal blobs, or compressed tokens.");
            }

            bool isBinary = ext is ".exe" or ".dll" or ".sys" or ".bin" or ".so" or ".elf";
            if (isBinary && entropy >= 7.80)
            {
                return (true, AnomalySeverity.High,
                    $"Excessive entropy ({entropy:F2}/8.00) in executable binary. Indicates packed, obfuscated, or encrypted payload sections (common in crypters/ransomware).");
            }

            bool isImage = ext is ".bmp" or ".gif";
            if (isImage && entropy >= 7.70)
            {
                return (true, AnomalySeverity.Medium,
                    $"Unusually high entropy ({entropy:F2}/8.00) for standard uncompressed/lightly-compressed image format. Potential steganographic carrier or payload container.");
            }

            return (false, AnomalySeverity.Info, $"Entropy ({entropy:F2}/8.00) is within normal variance for '{ext}'.");
        }
    }
}
