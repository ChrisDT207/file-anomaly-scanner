using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface IFileRemediationService
    {
        Task<RemediationReceiptDto> EradicateFileAsync(string filePath, string? expectedSha256 = null, CancellationToken cancellationToken = default);
    }
}
