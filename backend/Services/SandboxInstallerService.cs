using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using FileAnomalyScanner.Interfaces;

namespace FileAnomalyScanner.Services
{
    public class SandboxInstallerService : ISandboxInstallerService
    {
        private readonly ILogger<SandboxInstallerService> _logger;

        // Windows DISM standard exit codes
        private const int ErrorSuccess = 0;
        private const int ErrorSuccessRebootRequired = 3010;
        private const int ErrorCancelled = 1223; // UAC elevation declined by user

        public SandboxInstallerService(ILogger<SandboxInstallerService> logger)
        {
            _logger = logger;
        }

        public async Task<SandboxInstallationResult> ForceInstallSandboxPackagesAsync(CancellationToken cancellationToken = default)
        {
            if (!OperatingSystem.IsWindows())
            {
                return new SandboxInstallationResult(
                    Success: false,
                    ExitCode: -1,
                    Message: "Windows Sandbox is only supported on Windows operating systems."
                );
            }

            var tempDir = Path.GetTempPath();
            var batchFileName = $"EnableSandbox_{Guid.NewGuid():N}.bat";
            var batchPath = Path.Combine(tempDir, batchFileName);
            var sandboxListPath = Path.Combine(tempDir, "sandbox.txt");

            // Exact batch script required to enumerate, stage, and enable hidden Sandbox packages on Windows Home
            var batchScript = new StringBuilder();
            batchScript.AppendLine("@echo off");
            batchScript.AppendLine("dir /b %SystemRoot%\\servicing\\Packages\\*Containers*.mum >sandbox.txt");
            batchScript.AppendLine("for /f %%i in ('findstr /i . sandbox.txt 2^>nul') do dism /online /norestart /add-package:\"%SystemRoot%\\servicing\\Packages\\%%i\"");
            batchScript.AppendLine("del sandbox.txt");
            batchScript.AppendLine("Dism /online /enable-feature /featurename:Containers-DisposableClientVM /LimitAccess /ALL");

            try
            {
                await File.WriteAllTextAsync(batchPath, batchScript.ToString(), Encoding.ASCII, cancellationToken);
                _logger.LogInformation("Generated elevated Sandbox installer batch script at '{BatchPath}'", batchPath);

                var startInfo = new ProcessStartInfo
                {
                    FileName = batchPath,
                    UseShellExecute = true,
                    Verb = "runas", // Triggers Administrator UAC elevation
                    WorkingDirectory = tempDir,
                    WindowStyle = ProcessWindowStyle.Normal // Display DISM progress in elevated console
                };

                using var process = Process.Start(startInfo);
                if (process == null)
                {
                    return new SandboxInstallationResult(
                        Success: false,
                        ExitCode: -1,
                        Message: "Failed to initialize elevated DISM installer process."
                    );
                }

                _logger.LogInformation("Awaiting DISM execution for Windows Sandbox packages (PID: {Pid})...", process.Id);
                await process.WaitForExitAsync(cancellationToken);

                var exitCode = process.ExitCode;
                _logger.LogInformation("Sandbox installer script finished with exit code {ExitCode}", exitCode);

                bool isSuccess = (exitCode == ErrorSuccess || exitCode == ErrorSuccessRebootRequired);
                bool rebootRequired = (exitCode == ErrorSuccessRebootRequired || isSuccess);

                if (isSuccess)
                {
                    return new SandboxInstallationResult(
                        Success: true,
                        ExitCode: exitCode,
                        Message: "Windows Sandbox packages staged successfully. A system restart is required to finalize feature activation.",
                        RebootRequired: rebootRequired
                    );
                }

                return new SandboxInstallationResult(
                    Success: false,
                    ExitCode: exitCode,
                    Message: $"DISM package installation failed with exit code {exitCode}. Ensure virtualization is enabled in BIOS/UEFI.",
                    RebootRequired: false
                );
            }
            catch (Win32Exception win32Ex) when (win32Ex.NativeErrorCode == ErrorCancelled)
            {
                _logger.LogWarning("Windows Sandbox installation cancelled by user at UAC prompt.");
                return new SandboxInstallationResult(
                    Success: false,
                    ExitCode: ErrorCancelled,
                    Message: "Administrator elevation was cancelled by the user at the UAC prompt.",
                    CancelledByUser: true
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error executing Sandbox installation script.");
                return new SandboxInstallationResult(
                    Success: false,
                    ExitCode: -1,
                    Message: $"Installation execution error: {ex.Message}"
                );
            }
            finally
            {
                // Clean up generated batch script and temporary artifacts
                try
                {
                    if (File.Exists(batchPath))
                    {
                        File.Delete(batchPath);
                    }
                    if (File.Exists(sandboxListPath))
                    {
                        File.Delete(sandboxListPath);
                    }
                }
                catch (Exception cleanupEx)
                {
                    _logger.LogDebug(cleanupEx, "Failed to delete temporary installer artifacts.");
                }
            }
        }
    }
}
