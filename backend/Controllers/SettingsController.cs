using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SettingsController : ControllerBase
    {
        private readonly ISecuritySettingsService _settingsService;
        private readonly IVirusTotalService _virusTotalService;
        private readonly ISafeBrowsingService _safeBrowsingService;

        public SettingsController(
            ISecuritySettingsService settingsService,
            IVirusTotalService virusTotalService,
            ISafeBrowsingService safeBrowsingService)
        {
            _settingsService = settingsService;
            _virusTotalService = virusTotalService;
            _safeBrowsingService = safeBrowsingService;
        }

        [HttpGet]
        public IActionResult GetSettings()
        {
            var dto = _settingsService.GetSettingsDto();
            return Ok(dto);
        }

        [HttpPost]
        public async Task<IActionResult> UpdateSettings([FromBody] UpdateSecuritySettingsRequest request)
        {
            if (request == null)
            {
                return BadRequest(new { message = "Empty payload received." });
            }

            await _settingsService.UpdateSettingsAsync(request);
            var updated = _settingsService.GetSettingsDto();
            return Ok(new
            {
                success = true,
                message = "Threat intelligence settings successfully updated.",
                settings = updated
            });
        }

        [HttpPost("test-virustotal")]
        public async Task<ActionResult<TestApiResponse>> TestVirusTotal(
            [FromBody] TestApiRequest? req,
            CancellationToken cancellationToken = default)
        {
            var result = await _virusTotalService.TestConnectionAsync(req?.ApiKey, cancellationToken);
            return Ok(result);
        }

        [HttpPost("test-safebrowsing")]
        public async Task<ActionResult<TestApiResponse>> TestSafeBrowsing(
            [FromBody] TestApiRequest? req,
            CancellationToken cancellationToken = default)
        {
            var result = await _safeBrowsingService.TestConnectionAsync(req?.ApiKey, cancellationToken);
            return Ok(result);
        }
    }
}
