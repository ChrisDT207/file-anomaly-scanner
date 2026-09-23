using System;
using System.Threading.Tasks;
using System.Windows;
using FileAnomalyScanner.Services;

namespace FileAnomalyScanner
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            this.WindowStyle = WindowStyle.SingleBorderWindow;
            this.ResizeMode = ResizeMode.CanResize;
            AdjustWindowToWorkArea();
            Loaded += MainWindow_Loaded;
        }

        private void AdjustWindowToWorkArea()
        {
            var workArea = SystemParameters.WorkArea;

            // Constrain maximum size so it never spills outside current display
            this.MaxWidth = workArea.Width;
            this.MaxHeight = workArea.Height;

            if (this.Height > workArea.Height * 0.92)
            {
                this.Height = Math.Max(this.MinHeight, workArea.Height * 0.88);
            }
            if (this.Width > workArea.Width * 0.95)
            {
                this.Width = Math.Max(this.MinWidth, workArea.Width * 0.92);
            }

            // Ensure window title bar is never pushed off-screen (Top >= workArea.Top)
            this.Left = Math.Max(workArea.Left, workArea.Left + (workArea.Width - this.Width) / 2);
            this.Top = Math.Max(workArea.Top, workArea.Top + (workArea.Height - this.Height) / 2);
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                await ScannerWebView.EnsureCoreWebView2Async();

                ScannerWebView.Source = new Uri(DesktopHost.BaseUrl);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Error initializing WebView2 browser engine:\n{ex.Message}\n\nPlease ensure Microsoft Edge WebView2 Runtime is installed.",
                    "WebView2 Initialization Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }
}
