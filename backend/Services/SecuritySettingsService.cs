using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    public class SecuritySettingsService : ISecuritySettingsService
    {
        private readonly string _settingsFilePath;
        private readonly SemaphoreSlim _lock = new(1, 1);
        private SecuritySettings _cachedSettings;

        public SecuritySettingsService()
        {
            _settingsFilePath = Path.Combine(AppContext.BaseDirectory, "security-settings.json");
            _cachedSettings = LoadSettingsInternal();
        }

        public SecuritySettings GetSettings()
        {
            return _cachedSettings;
        }

        public SecuritySettingsDto GetSettingsDto()
        {
            var s = _cachedSettings;
            return new SecuritySettingsDto
            {
                VirusTotalConfigured = !string.IsNullOrWhiteSpace(s.VirusTotalApiKey),
                MaskedVirusTotalApiKey = MaskKey(s.VirusTotalApiKey),
                VirusTotalEnabled = s.VirusTotalEnabled,
                SafeBrowsingConfigured = !string.IsNullOrWhiteSpace(s.GoogleSafeBrowsingApiKey),
                MaskedSafeBrowsingApiKey = MaskKey(s.GoogleSafeBrowsingApiKey),
                SafeBrowsingEnabled = s.GoogleSafeBrowsingEnabled,
                MaxVirusTotalLookupsPerBatch = s.MaxVirusTotalLookupsPerBatch,
                CheckEmbeddedUrlsWithSafeBrowsing = s.CheckEmbeddedUrlsWithSafeBrowsing
            };
        }

        public async Task UpdateSettingsAsync(UpdateSecuritySettingsRequest request)
        {
            await _lock.WaitAsync();
            try
            {
                if (request.VirusTotalApiKey != null)
                {
                    _cachedSettings.VirusTotalApiKey = request.VirusTotalApiKey.Trim();
                }
                if (request.VirusTotalEnabled.HasValue)
                {
                    _cachedSettings.VirusTotalEnabled = request.VirusTotalEnabled.Value;
                }
                if (request.GoogleSafeBrowsingApiKey != null)
                {
                    _cachedSettings.GoogleSafeBrowsingApiKey = request.GoogleSafeBrowsingApiKey.Trim();
                }
                if (request.GoogleSafeBrowsingEnabled.HasValue)
                {
                    _cachedSettings.GoogleSafeBrowsingEnabled = request.GoogleSafeBrowsingEnabled.Value;
                }
                if (request.MaxVirusTotalLookupsPerBatch.HasValue && request.MaxVirusTotalLookupsPerBatch.Value > 0)
                {
                    _cachedSettings.MaxVirusTotalLookupsPerBatch = Math.Min(request.MaxVirusTotalLookupsPerBatch.Value, 50);
                }
                if (request.CheckEmbeddedUrlsWithSafeBrowsing.HasValue)
                {
                    _cachedSettings.CheckEmbeddedUrlsWithSafeBrowsing = request.CheckEmbeddedUrlsWithSafeBrowsing.Value;
                }

                var json = JsonSerializer.Serialize(_cachedSettings, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_settingsFilePath, json);
            }
            finally
            {
                _lock.Release();
            }
        }

        private SecuritySettings LoadSettingsInternal()
        {
            try
            {
                if (File.Exists(_settingsFilePath))
                {
                    var json = File.ReadAllText(_settingsFilePath);
                    var loaded = JsonSerializer.Deserialize<SecuritySettings>(json);
                    if (loaded != null)
                    {
                        // Check environment variables as fallback if empty
                        if (string.IsNullOrWhiteSpace(loaded.VirusTotalApiKey))
                        {
                            var envVt = Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY");
                            if (!string.IsNullOrWhiteSpace(envVt)) loaded.VirusTotalApiKey = envVt.Trim();
                        }
                        if (string.IsNullOrWhiteSpace(loaded.GoogleSafeBrowsingApiKey))
                        {
                            var envSb = Environment.GetEnvironmentVariable("GOOGLE_SAFE_BROWSING_API_KEY");
                            if (!string.IsNullOrWhiteSpace(envSb)) loaded.GoogleSafeBrowsingApiKey = envSb.Trim();
                        }
                        return loaded;
                    }
                }
            }
            catch
            {
                // Fall back to default
            }

            var defaults = new SecuritySettings();
            var vtFromEnv = Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY");
            if (!string.IsNullOrWhiteSpace(vtFromEnv)) defaults.VirusTotalApiKey = vtFromEnv.Trim();
            var sbFromEnv = Environment.GetEnvironmentVariable("GOOGLE_SAFE_BROWSING_API_KEY");
            if (!string.IsNullOrWhiteSpace(sbFromEnv)) defaults.GoogleSafeBrowsingApiKey = sbFromEnv.Trim();
            return defaults;
        }

        private static string MaskKey(string? key)
        {
            if (string.IsNullOrWhiteSpace(key)) return string.Empty;
            if (key.Length <= 8) return "••••" + key[^Math.Min(3, key.Length)..];
            return string.Concat(key.AsSpan(0, 4), "••••••••", key.AsSpan(key.Length - 4, 4));
        }
    }
}
