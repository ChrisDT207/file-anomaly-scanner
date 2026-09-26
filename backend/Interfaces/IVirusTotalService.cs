using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface IVirusTotalService
    {
        bool IsEnabledAndConfigured();
        Task<VirusTotalReport> LookupFileHashAsync(string sha256, CancellationToken cancellationToken = default);
        Task<TestApiResponse> TestConnectionAsync(string? testApiKey = null, CancellationToken cancellationToken = default);
        Task<string?> SubmitFileForAnalysisAsync(string fileName, byte[] content, CancellationToken cancellationToken = default);
        Task<string?> SubmitStreamForAnalysisAsync(string fileName, System.IO.Stream stream, CancellationToken cancellationToken = default);
        Task<CloudSandboxReportDto?> GetBehaviorSummaryAsync(string sha256, CancellationToken cancellationToken = default);
        Task<AnalysisStatusDto?> GetAnalysisStatusAsync(string analysisId, CancellationToken cancellationToken = default);
    }
}
