using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Interfaces;

namespace FileAnomalyScanner.Services
{
    public class StreamingFileInspector : IStreamingFileInspector
    {
        private const int ChunkSize = 64 * 1024; // 64 KB rented buffer
        private const int HeaderCaptureSize = 16 * 1024; // 16 KB header capture for magic bytes & PE stubs
        private const int TextSnippetCaptureSize = 64 * 1024; // 64 KB for text/script snippet extraction

        public async Task<StreamingScanResult> InspectStreamAsync(
            Stream stream, 
            CancellationToken cancellationToken = default)
        {
            var byteCounts = new long[256];
            byte[] headerBuffer = new byte[HeaderCaptureSize];
            int headerBytesCaptured = 0;

            byte[] textSnippetBuffer = new byte[TextSnippetCaptureSize];
            int textSnippetBytesCaptured = 0;

            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] rentedBuffer = ArrayPool<byte>.Shared.Rent(ChunkSize);

            long totalBytes = 0;
            double peakBlockEntropy = 0.0;
            bool hasHighEntropyBlock = false;

            try
            {
                int bytesRead;
                while ((bytesRead = await stream.ReadAsync(rentedBuffer.AsMemory(0, ChunkSize), cancellationToken)) > 0)
                {
                    totalBytes += bytesRead;

                    // 1. Incrementally hash without storing bytes in memory
                    sha256.AppendData(rentedBuffer, 0, bytesRead);

                    // 2. Capture header bytes for MagicByteValidator and PE checks
                    if (headerBytesCaptured < HeaderCaptureSize)
                    {
                        int toCopy = Math.Min(bytesRead, HeaderCaptureSize - headerBytesCaptured);
                        Buffer.BlockCopy(rentedBuffer, 0, headerBuffer, headerBytesCaptured, toCopy);
                        headerBytesCaptured += toCopy;
                    }

                    // 3. Capture text snippet for AST / URL inspection
                    if (textSnippetBytesCaptured < TextSnippetCaptureSize)
                    {
                        int toCopy = Math.Min(bytesRead, TextSnippetCaptureSize - textSnippetBytesCaptured);
                        Buffer.BlockCopy(rentedBuffer, 0, textSnippetBuffer, textSnippetBytesCaptured, toCopy);
                        textSnippetBytesCaptured += toCopy;
                    }

                    // 4. Update frequency histogram and calculate local chunk entropy
                    var blockCounts = new int[256];
                    for (int i = 0; i < bytesRead; i++)
                    {
                        byte b = rentedBuffer[i];
                        byteCounts[b]++;
                        blockCounts[b]++;
                    }

                    // Sliding/stepped window entropy
                    if (bytesRead >= 256)
                    {
                        double blockEntropy = CalculateLocalEntropy(blockCounts, bytesRead);
                        if (blockEntropy > peakBlockEntropy)
                        {
                            peakBlockEntropy = blockEntropy;
                        }

                        // Packed or encrypted payload sections (common in crypters and ransomware overlays)
                        if (blockEntropy >= 7.85)
                        {
                            hasHighEntropyBlock = true;
                        }
                    }
                }

                // Compute overall Shannon Entropy from histogram
                double overallEntropy = CalculateEntropyFromHistogram(byteCounts, totalBytes);
                string hashString = Convert.ToHexString(sha256.GetHashAndReset()).ToLowerInvariant();

                // Format actual captured header
                byte[] actualHeader = new byte[headerBytesCaptured];
                Buffer.BlockCopy(headerBuffer, 0, actualHeader, 0, headerBytesCaptured);

                // Decode text snippet
                string textSnippet = string.Empty;
                if (textSnippetBytesCaptured > 0)
                {
                    try
                    {
                        textSnippet = Encoding.UTF8.GetString(textSnippetBuffer, 0, textSnippetBytesCaptured);
                    }
                    catch
                    {
                        textSnippet = Encoding.ASCII.GetString(textSnippetBuffer, 0, textSnippetBytesCaptured);
                    }
                }

                return new StreamingScanResult(
                    hashString,
                    Math.Round(overallEntropy, 4),
                    Math.Round(peakBlockEntropy, 4),
                    actualHeader,
                    totalBytes,
                    hasHighEntropyBlock,
                    textSnippet
                );
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rentedBuffer);
            }
        }

        public async Task<StreamingScanResult> InspectBytesAsync(
            byte[] bytes, 
            CancellationToken cancellationToken = default)
        {
            using var ms = new MemoryStream(bytes, writable: false);
            return await InspectStreamAsync(ms, cancellationToken);
        }

        private static double CalculateEntropyFromHistogram(long[] counts, long total)
        {
            if (total == 0) return 0.0;
            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / total;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }

        private static double CalculateLocalEntropy(int[] counts, int total)
        {
            if (total == 0) return 0.0;
            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / total;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }
    }
}
