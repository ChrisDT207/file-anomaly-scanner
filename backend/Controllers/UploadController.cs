using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UploadController : ControllerBase
    {
        private readonly IScannerManager _scannerManager;
        private readonly IMagicByteValidator _magicByteValidator;
        private readonly ISuspiciousSignatureManager _signatureManager;
        private readonly IVirusTotalService _virusTotalService;

        public UploadController(
            IScannerManager scannerManager,
            IMagicByteValidator magicByteValidator,
            ISuspiciousSignatureManager signatureManager,
            IVirusTotalService virusTotalService)
        {
            _scannerManager = scannerManager;
            _magicByteValidator = magicByteValidator;
            _signatureManager = signatureManager;
            _virusTotalService = virusTotalService;
        }

        [HttpPost("scan")]
        [RequestSizeLimit(100 * 1024 * 1024)] 
        public async Task<ActionResult<ScanReportDto>> ScanFiles(
            [FromForm] List<IFormFile> files,
            [FromForm] List<string>? paths = null,
            CancellationToken cancellationToken = default)
        {
            if (files == null || files.Count == 0)
            {
                return BadRequest(new ScanReportDto
                {
                    Success = false,
                    ErrorMessage = "No files were received in the upload request."
                });
            }

            var items = new List<FileScanItem>();

            for (int i = 0; i < files.Count; i++)
            {
                var formFile = files[i];
                var relativePath = (paths != null && i < paths.Count && !string.IsNullOrWhiteSpace(paths[i]))
                    ? paths[i]
                    : formFile.FileName;

                byte[] fileBytes;
                using (var ms = new MemoryStream())
                {
                    await formFile.CopyToAsync(ms, cancellationToken);
                    fileBytes = ms.ToArray();
                }

                items.Add(new FileScanItem
                {
                    FileName = formFile.FileName,
                    RelativePath = relativePath,
                    SizeBytes = formFile.Length,
                    Content = fileBytes
                });
            }

            var report = await _scannerManager.ScanBatchAsync(items, cancellationToken);
            return Ok(report);
        }

        [HttpGet("health")]
        public IActionResult GetHealth()
        {
            return Ok(new
            {
                Status = "Healthy",
                Service = "FileAnomalyScanner Web API",
                Timestamp = DateTime.UtcNow
            });
        }

        [HttpGet("signatures")]
        public IActionResult GetSignatures()
        {
            return Ok(new
            {
                MagicByteSignatures = _magicByteValidator.GetSupportedSignatures(),
                ActiveHeuristicRules = _signatureManager.GetActiveRules()
            });
        }

        [HttpPost("submit-virustotal")]
        [RequestSizeLimit(35 * 1024 * 1024)]
        public async Task<IActionResult> SubmitToVirusTotal(
            IFormFile file,
            CancellationToken cancellationToken = default)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest(new { success = false, message = "No file provided for VirusTotal submission." });
            }

            if (!_virusTotalService.IsEnabledAndConfigured())
            {
                return BadRequest(new { success = false, message = "VirusTotal API key is not configured or disabled in settings." });
            }

            try
            {
                using var stream = file.OpenReadStream();
                var analysisId = await _virusTotalService.SubmitStreamForAnalysisAsync(file.FileName, stream, cancellationToken);
                return Ok(new
                {
                    success = true,
                    message = "File submitted to VirusTotal for multi-engine analysis.",
                    analysisId = analysisId
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new
                {
                    success = false,
                    message = $"Error submitting file to VirusTotal: {ex.Message}"
                });
            }
        }
    }
}
