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
    }
}
