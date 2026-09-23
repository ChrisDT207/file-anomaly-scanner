using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Services;

namespace FileAnomalyScanner.Services
{
    public static class DesktopHost
    {
        private static WebApplication? _app;
        private static CancellationTokenSource? _cts;

        public static string BaseUrl { get; } = "http://127.0.0.1:5000";

        public static async Task StartAsync()
        {
            if (_app != null) return;

            _cts = new CancellationTokenSource();

            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                ContentRootPath = AppContext.BaseDirectory,
                WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot")
            });

            builder.WebHost.UseUrls(BaseUrl);

            builder.Services.Configure<FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = 100 * 1024 * 1024;
                options.ValueLengthLimit = int.MaxValue;
                options.MultipartHeadersLengthLimit = int.MaxValue;
            });

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", policy =>
                {
                    policy.AllowAnyOrigin()
                          .AllowAnyMethod()
                          .AllowAnyHeader();
                });
            });

            builder.Services.AddSingleton<IMagicByteValidator, MagicByteValidator>();
            builder.Services.AddSingleton<IEntropyCalculator, EntropyCalculator>();
            builder.Services.AddSingleton<IArchiveExtractorService, ArchiveExtractorService>();
            builder.Services.AddSingleton<ISuspiciousSignatureManager, SuspiciousSignatureManager>();
            builder.Services.AddSingleton<IReportGenerator, ReportGenerator>();
            builder.Services.AddScoped<IScannerManager, ScannerManager>();

            builder.Services.AddControllers();

            _app = builder.Build();

            _app.UseCors("AllowAll");

            var wwwrootDir = Path.Combine(AppContext.BaseDirectory, "wwwroot");
            if (Directory.Exists(wwwrootDir))
            {
                _app.UseDefaultFiles();
                _app.UseStaticFiles(new StaticFileOptions
                {
                    FileProvider = new PhysicalFileProvider(wwwrootDir)
                });
            }

            _app.MapControllers();

            if (Directory.Exists(wwwrootDir))
            {
                _app.MapFallbackToFile("index.html");
            }

            await _app.StartAsync(_cts.Token);
        }

        public static async Task StopAsync()
        {
            if (_app != null)
            {
                _cts?.Cancel();
                await _app.StopAsync();
                await _app.DisposeAsync();
                _app = null;
            }
        }
    }
}
