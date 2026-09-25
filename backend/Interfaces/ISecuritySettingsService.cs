using System.Threading.Tasks;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface ISecuritySettingsService
    {
        SecuritySettings GetSettings();
        SecuritySettingsDto GetSettingsDto();
        Task UpdateSettingsAsync(UpdateSecuritySettingsRequest request);
    }
}
