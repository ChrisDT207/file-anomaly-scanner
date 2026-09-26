using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Controllers
{
    [ApiController]
    [Route("api/sandbox")]
    public class CloudSandboxController : ControllerBase
    {
        private readonly IVirusTotalService _virusTotalService;
        private readonly IFileRemediationService _remediationService;
        private readonly ILogger<CloudSandboxController> _logger;

        public CloudSandboxController(
            IVirusTotalService virusTotalService,
            IFileRemediationService remediationService,
            ILogger<CloudSandboxController> logger)
        {
            _virusTotalService = virusTotalService;
            _remediationService = remediationService;
            _logger = logger;
        }

        /// <summary>
        /// Retrieves cloud sandbox status and capability.
        /// </summary>
        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            var isConfigured = _virusTotalService.IsEnabledAndConfigured();
            return Ok(new
            {
                available = true,
                type = "CloudSandbox",
                provider = "VirusTotal v3 Behavioral Telemetry",
                configured = isConfigured,
                message = isConfigured
                    ? "Cloud Sandbox Behavioral Telemetry is active and configured."
                    : "VirusTotal API key is not configured in settings."
            });
        }

        /// <summary>
        /// Retrieves real-time behavioral telemetry execution summary from VirusTotal cloud hypervisors.
        /// </summary>
        [HttpGet("behavior/{sha256}")]
        public async Task<IActionResult> GetBehaviorSummary(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sha256) || sha256.Trim().Length < 32)
            {
                return BadRequest(new { message = "A valid file hash (SHA-256 or MD5) must be provided." });
            }

            _logger.LogInformation("Querying cloud sandbox behavioral telemetry for hash: {Hash}", sha256);
            var report = await _virusTotalService.GetBehaviorSummaryAsync(sha256, cancellationToken);
            if (report == null)
            {
                return NotFound(new { message = "Behavioral telemetry could not be retrieved." });
            }

            return Ok(report);
        }

        /// <summary>
        /// Securely shreds and eradicates a confirmed malicious payload from the host filesystem.
        /// Performs multi-pass cryptographic overwrite, zero-fill, metadata obfuscation, and permanent deletion.
        /// </summary>
        [HttpPost("remediate")]
        public async Task<IActionResult> RemediateFile(
            [FromBody] RemediationRequestDto request,
            CancellationToken cancellationToken = default)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.FilePath))
            {
                return BadRequest(new RemediationReceiptDto
                {
                    Success = false,
                    ErrorMessage = "A valid 'filePath' must be supplied in the request body."
                });
            }

            _logger.LogWarning("Initiating file eradication request for: {Path}", request.FilePath);
            var receipt = await _remediationService.EradicateFileAsync(request.FilePath, request.Sha256, cancellationToken);

            if (!receipt.Success)
            {
                _logger.LogError("File eradication failed for: {Path}. Reason: {Error}", request.FilePath, receipt.ErrorMessage);
                return BadRequest(receipt);
            }

            _logger.LogInformation("File successfully eradicated: {Path}", request.FilePath);
            return Ok(receipt);
        }

        /// <summary>
        /// Polls dynamic analysis status for a previously submitted zero-day file upload.
        /// </summary>
        [HttpGet("analysis/{analysisId}")]
        public async Task<IActionResult> GetAnalysisStatus(
            string analysisId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(analysisId))
            {
                return BadRequest(new { message = "A valid analysisId must be provided." });
            }

            var status = await _virusTotalService.GetAnalysisStatusAsync(analysisId, cancellationToken);
            if (status == null)
            {
                return NotFound(new { message = "Analysis ID not found." });
            }

            return Ok(status);
        }
    }
}
