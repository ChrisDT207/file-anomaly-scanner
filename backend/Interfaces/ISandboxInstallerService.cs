using System.Threading;
using System.Threading.Tasks;

namespace FileAnomalyScanner.Interfaces
{
    public record SandboxInstallationResult(
        bool Success,
        int ExitCode,
        string Message,
        bool RebootRequired = false,
        bool CancelledByUser = false
    );

    public interface ISandboxInstallerService
    {
        /// <summary>
        /// Dynamically synthesizes and executes an elevated DISM batch script
        /// to unhide and install the Windows Containers and Sandbox (DisposableClientVM)
        /// servicing packages on Windows Home and Pro editions.
        /// </summary>
        Task<SandboxInstallationResult> ForceInstallSandboxPackagesAsync(CancellationToken cancellationToken = default);
    }
}
