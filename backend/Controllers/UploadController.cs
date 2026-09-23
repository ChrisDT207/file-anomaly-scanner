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

        public UploadController(
            IScannerManager scannerManager,
            IMagicByteValidator magicByteValidator,
            ISuspiciousSignatureManager signatureManager)
        {
            _scannerManager = scannerManager;
            _magicByteValidator = magicByteValidator;
            _signatureManager = signatureManager;
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
    }
}
