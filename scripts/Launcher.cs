using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace FileAnomalyScannerLauncher
{
    static class Program
    {
        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool IsIconic(IntPtr hWnd);

        private const int SW_RESTORE = 9;

        [STAThread]
        static void Main()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;

                // 1. Resolve candidate paths for the compiled scanner backend
                string[] candidatePaths = new string[]
                {
                    Path.Combine(baseDir, "backend", "bin", "Release", "net8.0-windows", "publish", "FileAnomalyScanner.exe"),
                    Path.Combine(baseDir, "backend", "bin", "Release", "net8.0-windows", "FileAnomalyScanner.exe"),
                    Path.Combine(baseDir, "backend", "bin", "Debug", "net8.0-windows", "FileAnomalyScanner.exe")
                };

                string targetExe = null;
                foreach (string candidate in candidatePaths)
                {
                    if (File.Exists(candidate))
                    {
                        targetExe = candidate;
                        break;
                    }
                }

                // If not found, build it on the fly with dotnet publish
                if (targetExe == null)
                {
                    string backendProj = Path.Combine(baseDir, "backend", "FileAnomalyScanner.csproj");
                    if (File.Exists(backendProj))
                    {
                        ProcessStartInfo buildPsi = new ProcessStartInfo
                        {
                            FileName = "dotnet",
                            Arguments = "publish -c Release",
                            WorkingDirectory = Path.Combine(baseDir, "backend"),
                            CreateNoWindow = true,
                            UseShellExecute = false
                        };

                        using (Process buildProc = Process.Start(buildPsi))
                        {
                            if (buildProc != null)
                            {
                                buildProc.WaitForExit();
                            }
                        }

                        if (File.Exists(candidatePaths[0]))
                        {
                            targetExe = candidatePaths[0];
                        }
                    }
                }

                if (targetExe == null || !File.Exists(targetExe))
                {
                    MessageBox.Show(
                        "Unable to find or build FileAnomalyScanner.exe.\nPlease ensure .NET 8 SDK is installed on your computer.",
                        "File Anomaly Scanner",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }

                // 2. Check if the backend application is ALREADY running
                int currentId = Process.GetCurrentProcess().Id;
                Process[] runningProcs = Process.GetProcessesByName("FileAnomalyScanner");
                foreach (Process p in runningProcs)
                {
                    if (p.Id == currentId) continue;

                    try
                    {
                        string procPath = p.MainModule.FileName;
                        if (string.Equals(procPath, targetExe, StringComparison.OrdinalIgnoreCase))
                        {
                            if (p.MainWindowHandle != IntPtr.Zero)
                            {
                                if (IsIconic(p.MainWindowHandle))
                                {
                                    ShowWindow(p.MainWindowHandle, SW_RESTORE);
                                }
                                SetForegroundWindow(p.MainWindowHandle);
                            }
                            return; // Already running, brought to front
                        }
                    }
                    catch
                    {
                        // Ignore access restrictions on other processes
                    }
                }

                // 3. Launch the desktop application
                ProcessStartInfo startPsi = new ProcessStartInfo
                {
                    FileName = targetExe,
                    WorkingDirectory = Path.GetDirectoryName(targetExe),
                    UseShellExecute = true
                };

                Process.Start(startPsi);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Failed to launch File Anomaly Scanner:\n" + ex.Message,
                    "File Anomaly Scanner",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }
    }
}
