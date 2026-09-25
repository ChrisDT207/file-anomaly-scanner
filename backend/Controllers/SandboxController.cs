using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using FileAnomalyScanner.Interfaces;

namespace FileAnomalyScanner.Controllers
{
    public class DetonateRequest
    {
        public string? FilePath { get; set; }
        public string? FileName { get; set; }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class SandboxController : ControllerBase
    {
        private readonly ISandboxDetonationService _sandboxService;
        private readonly ISandboxInstallerService _installerService;

        public SandboxController(
            ISandboxDetonationService sandboxService,
            ISandboxInstallerService installerService)
        {
            _sandboxService = sandboxService;
            _installerService = installerService;
        }

        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            var isAvailable = _sandboxService.IsWindowsSandboxAvailable();
            return Ok(new
            {
                available = isAvailable,
                operatingSystem = Environment.OSVersion.ToString(),
                instructions = isAvailable 
                    ? "Windows Sandbox is ready for isolated dynamic detonation."
                    : "Windows Sandbox is not enabled. Requires Windows 10/11 Pro/Enterprise with virtualization enabled in BIOS."
            });
        }

        [HttpPost("detonate")]
        [RequestSizeLimit(100 * 1024 * 1024)]
        public async Task<IActionResult> Detonate(
            [FromForm] IFormFile? file,
            [FromForm] string? filePath = null,
            CancellationToken cancellationToken = default)
        {
            // Case 1: Direct file upload from client memory
            if (file != null && file.Length > 0)
            {
                using var stream = file.OpenReadStream();
                var result = await _sandboxService.LaunchStreamInSandboxAsync(file.FileName, stream, cancellationToken);
                if (!result.Success)
                {
                    return BadRequest(new { success = false, message = result.Message });
                }

                return Ok(new
                {
                    success = true,
                    message = result.Message,
                    wsbConfig = result.WsbConfigPath
                });
            }

            // Case 2: Local host filesystem path
            if (!string.IsNullOrWhiteSpace(filePath))
            {
                var result = await _sandboxService.LaunchFileInSandboxAsync(filePath, cancellationToken);
                if (!result.Success)
                {
                    return BadRequest(new { success = false, message = result.Message });
                }

                return Ok(new
                {
                    success = true,
                    message = result.Message,
                    wsbConfig = result.WsbConfigPath
                });
            }

            return BadRequest(new
            {
                success = false,
                message = "Either a valid host 'filePath' or an uploaded 'file' must be supplied."
            });
        }

        [HttpPost("detonate-json")]
        public async Task<IActionResult> DetonateJson(
            [FromBody] DetonateRequest request,
            CancellationToken cancellationToken = default)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.FilePath))
            {
                return BadRequest(new { success = false, message = "A valid 'filePath' must be provided in the request body." });
            }

            var result = await _sandboxService.LaunchFileInSandboxAsync(request.FilePath, cancellationToken);
            if (!result.Success)
            {
                return BadRequest(new { success = false, message = result.Message });
            }

            return Ok(new
            {
                success = true,
                message = result.Message,
                wsbConfig = result.WsbConfigPath
            });
        }

        [HttpPost("force-install")]
        public async Task<IActionResult> ForceInstall(CancellationToken cancellationToken = default)
        {
            var result = await _installerService.ForceInstallSandboxPackagesAsync(cancellationToken);
            if (result.CancelledByUser)
            {
                return BadRequest(new
                {
                    success = false,
                    cancelled = true,
                    message = result.Message
                });
            }

            if (!result.Success)
            {
                return StatusCode(500, new
                {
                    success = false,
                    exitCode = result.ExitCode,
                    message = result.Message
                });
            }

            return Ok(new
            {
                success = true,
                exitCode = result.ExitCode,
                rebootRequired = result.RebootRequired,
                message = result.Message
            });
        }
    }
}
