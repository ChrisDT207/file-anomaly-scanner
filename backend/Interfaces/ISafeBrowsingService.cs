using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface ISafeBrowsingService
    {
        bool IsEnabledAndConfigured();
        List<string> ExtractUrlsFromContent(byte[] content);
        Task<SafeBrowsingReport> CheckUrlsAsync(IEnumerable<string> urls, CancellationToken cancellationToken = default);
        Task<TestApiResponse> TestConnectionAsync(string? testApiKey = null, CancellationToken cancellationToken = default);
    }
}
