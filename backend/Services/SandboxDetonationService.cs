using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using FileAnomalyScanner.Interfaces;

namespace FileAnomalyScanner.Services
{
    public class SandboxDetonationService : ISandboxDetonationService
    {
        private static readonly string System32SandboxPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsSandbox.exe");

        public bool IsWindowsSandboxAvailable()
        {
            if (!OperatingSystem.IsWindows()) return false;
            return File.Exists(System32SandboxPath);
        }

        public async Task<SandboxDetonationResult> LaunchFileInSandboxAsync(
            string filePath, 
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                return new SandboxDetonationResult(false, "No file path was provided for sandbox detonation.");
            }

            if (!File.Exists(filePath))
            {
                return new SandboxDetonationResult(false, $"Target file '{filePath}' was not found on host filesystem.");
            }

            // Stage file into an isolated folder so host directories are not exposed
            var stagingDir = CreateIsolatedStagingDirectory();
            var fileName = Path.GetFileName(filePath);
            var stagedFilePath = Path.Combine(stagingDir, fileName);

            try
            {
                File.Copy(filePath, stagedFilePath, overwrite: true);
                return await LaunchFromStagingDirectoryAsync(stagingDir, fileName, cancellationToken);
            }
            catch (Exception ex)
            {
                return new SandboxDetonationResult(
                    false,
                    $"Failed to stage file for sandbox detonation: {ex.Message}",
                    StagingDirectory: stagingDir);
            }
        }

        public async Task<SandboxDetonationResult> LaunchBytesInSandboxAsync(
            string fileName, 
            byte[] content, 
            CancellationToken cancellationToken = default)
        {
            var stagingDir = CreateIsolatedStagingDirectory();
            var safeFileName = string.IsNullOrWhiteSpace(fileName) ? "suspicious_payload.bin" : Path.GetFileName(fileName);
            var stagedFilePath = Path.Combine(stagingDir, safeFileName);

            try
            {
                await File.WriteAllBytesAsync(stagedFilePath, content, cancellationToken);
                return await LaunchFromStagingDirectoryAsync(stagingDir, safeFileName, cancellationToken);
            }
            catch (Exception ex)
            {
                return new SandboxDetonationResult(
                    false,
                    $"Failed to write payload to sandbox staging directory: {ex.Message}",
                    StagingDirectory: stagingDir);
            }
        }

        public async Task<SandboxDetonationResult> LaunchStreamInSandboxAsync(
            string fileName, 
            Stream stream, 
            CancellationToken cancellationToken = default)
        {
            var stagingDir = CreateIsolatedStagingDirectory();
            var safeFileName = string.IsNullOrWhiteSpace(fileName) ? "suspicious_payload.bin" : Path.GetFileName(fileName);
            var stagedFilePath = Path.Combine(stagingDir, safeFileName);

            try
            {
                using (var fs = new FileStream(stagedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await stream.CopyToAsync(fs, cancellationToken);
                }

                return await LaunchFromStagingDirectoryAsync(stagingDir, safeFileName, cancellationToken);
            }
            catch (Exception ex)
            {
                return new SandboxDetonationResult(
                    false,
                    $"Failed to stream payload to sandbox staging directory: {ex.Message}",
                    StagingDirectory: stagingDir);
            }
        }

        private Task<SandboxDetonationResult> LaunchFromStagingDirectoryAsync(
            string stagingDir, 
            string fileName, 
            CancellationToken cancellationToken)
        {
            if (!OperatingSystem.IsWindows())
            {
                return Task.FromResult(new SandboxDetonationResult(
                    false, 
                    "Windows Sandbox is only supported on Windows operating systems."));
            }

            // Check if Windows Sandbox binary exists
            if (!IsWindowsSandboxAvailable())
            {
                return Task.FromResult(new SandboxDetonationResult(
                    false,
                    "Windows Sandbox feature is not enabled on this machine. " +
                    "To use this feature, ensure you are running Windows 10/11 Pro or Enterprise with CPU virtualization enabled, " +
                    "then enable 'Windows Sandbox' in 'Turn Windows features on or off'."));
            }

            try
            {
                // Generate the .wsb XML configuration
                var wsbConfigPath = Path.Combine(stagingDir, "IsolatedInspection.wsb");
                var wsbXml = GenerateWsbXml(stagingDir);
                File.WriteAllText(wsbConfigPath, wsbXml, Encoding.UTF8);

                // Launch Windows Sandbox via shell association
                var psi = new ProcessStartInfo
                {
                    FileName = wsbConfigPath,
                    UseShellExecute = true
                };

                using var process = Process.Start(psi);

                return Task.FromResult(new SandboxDetonationResult(
                    true,
                    $"Windows Sandbox successfully initiated with isolated, read-only mapped folder. " +
                    $"Network access is disabled to prevent command-and-control communication.",
                    WsbConfigPath: wsbConfigPath,
                    StagingDirectory: stagingDir));
            }
            catch (Win32Exception w32Ex)
            {
                return Task.FromResult(new SandboxDetonationResult(
                    false,
                    $"Unable to launch Windows Sandbox (.wsb file association error): {w32Ex.Message}. " +
                    $"Verify Windows Sandbox is enabled in Windows Features.",
                    StagingDirectory: stagingDir));
            }
            catch (PlatformNotSupportedException pnsEx)
            {
                return Task.FromResult(new SandboxDetonationResult(
                    false,
                    $"Windows Sandbox platform not supported: {pnsEx.Message}",
                    StagingDirectory: stagingDir));
            }
            catch (Exception ex)
            {
                return Task.FromResult(new SandboxDetonationResult(
                    false,
                    $"Unexpected error launching Windows Sandbox: {ex.Message}",
                    StagingDirectory: stagingDir));
            }
        }

        private static string CreateIsolatedStagingDirectory()
        {
            // Use CommonApplicationData (C:\ProgramData) rather than user-profile Temp directory
            // because ProgramData allows read traversal across security principals and virtual accounts
            string basePath;
            try
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                basePath = string.IsNullOrWhiteSpace(appData) 
                    ? Path.Combine(Path.GetTempPath(), "FileAnomalyScanner_Sandbox")
                    : Path.Combine(appData, "FileAnomalyScanner_Sandbox");
            }
            catch
            {
                basePath = Path.Combine(Path.GetTempPath(), "FileAnomalyScanner_Sandbox");
            }

            var uniqueDir = Path.Combine(basePath, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(uniqueDir);
            return uniqueDir;
        }

        private static string GenerateWsbXml(string hostFolderPath)
        {
            // Use a clean root sandbox directory rather than hardcoding WDAGUtilityAccount profile paths,
            // avoiding Windows Sandbox account-name/SID resolution errors (0x80070534)
            const string sandboxTargetFolder = @"C:\ThreatSample";

            var doc = new XDocument(
                new XElement("Configuration",
                    new XElement("Networking", "Disable"),
                    new XElement("MappedFolders",
                        new XElement("MappedFolder",
                            new XElement("HostFolder", hostFolderPath),
                            new XElement("SandboxFolder", sandboxTargetFolder),
                            new XElement("ReadOnly", "true")
                        )
                    ),
                    new XElement("LogonCommand",
                        new XElement("Command", $@"explorer.exe {sandboxTargetFolder}")
                    )
                )
            );

            return doc.ToString();
        }
    }
}
