using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FileAnomalyScanner.Interfaces
{
    public record SandboxDetonationResult(
        bool Success,
        string Message,
        string? WsbConfigPath = null,
        string? StagingDirectory = null
    );

    public interface ISandboxDetonationService
    {
        bool IsWindowsSandboxAvailable();
        Task<SandboxDetonationResult> LaunchFileInSandboxAsync(string filePath, CancellationToken cancellationToken = default);
        Task<SandboxDetonationResult> LaunchBytesInSandboxAsync(string fileName, byte[] content, CancellationToken cancellationToken = default);
        Task<SandboxDetonationResult> LaunchStreamInSandboxAsync(string fileName, Stream stream, CancellationToken cancellationToken = default);
    }
}
