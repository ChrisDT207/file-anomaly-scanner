using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface IScannerManager
    {
        Task<ScanReportDto> ScanBatchAsync(IEnumerable<FileScanItem> items, CancellationToken cancellationToken = default);
    }
}
