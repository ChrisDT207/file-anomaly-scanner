using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FileAnomalyScanner.Interfaces
{
    public record StreamingScanResult(
        string Sha256,
        double OverallEntropy,
        double PeakBlockEntropy,
        byte[] HeaderBytes,
        long TotalBytesRead,
        bool HasSuspiciousHighEntropySection,
        string TextSnippet
    );

    public interface IStreamingFileInspector
    {
        Task<StreamingScanResult> InspectStreamAsync(
            Stream stream, 
            CancellationToken cancellationToken = default);

        Task<StreamingScanResult> InspectBytesAsync(
            byte[] bytes, 
            CancellationToken cancellationToken = default);
    }
}
