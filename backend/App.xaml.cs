using System;
using System.Windows;
using FileAnomalyScanner.Services;

namespace FileAnomalyScanner
{
    public partial class App : Application
    {
        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            try
            {
                await DesktopHost.StartAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to start in-process file anomaly scanning engine:\n{ex.Message}",
                    "Scanner Engine Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        protected override async void OnExit(ExitEventArgs e)
        {
            try
            {
                await DesktopHost.StopAsync();
            }
            catch
            {
            }

            base.OnExit(e);
        }
    }
}
