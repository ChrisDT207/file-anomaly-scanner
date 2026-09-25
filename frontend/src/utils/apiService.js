/**
 * API communication service for ASP.NET Core File Anomaly Scanner.
 */

const API_UPLOAD = '/api/upload';
const API_SETTINGS = '/api/settings';

/**
 * Checks the health status of the backend API.
 * @returns {Promise<boolean>}
 */
export async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_UPLOAD}/health`, { method: 'GET' });
    return res.ok;
  } catch (err) {
    return false;
  }
}

/**
 * Fetches active signatures and heuristics from the backend.
 * @returns {Promise<any>}
 */
export async function fetchSignatures() {
  try {
    const res = await fetch(`${API_UPLOAD}/signatures`);
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.error('Failed to load backend signatures', e);
  }
  return null;
}

/**
 * Fetches current threat intelligence configuration (VirusTotal & Safe Browsing).
 * @returns {Promise<any>}
 */
export async function fetchSecuritySettings() {
  try {
    const res = await fetch(API_SETTINGS, { method: 'GET' });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.error('Failed to load security settings', err);
  }
  return null;
}

/**
 * Updates threat intelligence configuration.
 * @param {object} payload
 * @returns {Promise<any>}
 */
export async function updateSecuritySettings(payload) {
  const res = await fetch(API_SETTINGS, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(err || `Failed to update settings (HTTP ${res.status})`);
  }
  return await res.json();
}

/**
 * Tests connection to VirusTotal API.
 * @param {string|null} apiKey
 * @returns {Promise<any>}
 */
export async function testVirusTotalKey(apiKey = null) {
  const res = await fetch(`${API_SETTINGS}/test-virustotal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey: apiKey || null })
  });
  return await res.json();
}

/**
 * Tests connection to Google Safe Browsing API.
 * @param {string|null} apiKey
 * @returns {Promise<any>}
 */
export async function testSafeBrowsingKey(apiKey = null) {
  const res = await fetch(`${API_SETTINGS}/test-safebrowsing`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey: apiKey || null })
  });
  return await res.json();
}

/**
 * Uploads a list of files with their relative paths to the backend for scanning.
 *
 * @param {Array<{ file: File, relativePath: string }>} fileItems
 * @param {Function} onProgress Callback for tracking batch progress
 * @returns {Promise<any>} Complete ScanReportDto
 */
export async function uploadAndScanFiles(fileItems, onProgress = null) {
  if (!fileItems || fileItems.length === 0) {
    throw new Error('No files provided for scanning.');
  }

  const BATCH_SIZE = 50;
  const totalBatches = Math.ceil(fileItems.length / BATCH_SIZE);

  let aggregatedAnomalies = [];
  let aggregatedFiles = [];
  let aggregatedLogs = [];
  let totalFilesScanned = 0;
  let totalBytesScanned = 0;
  let totalDurationMs = 0;
  let vtFlaggedCount = 0;
  let sbThreatCount = 0;

  for (let batchIndex = 0; batchIndex < totalBatches; batchIndex++) {
    const start = batchIndex * BATCH_SIZE;
    const end = Math.min(start + BATCH_SIZE, fileItems.length);
    const chunk = fileItems.slice(start, end);

    if (onProgress) {
      onProgress({
        currentBatch: batchIndex + 1,
        totalBatches,
        processedFiles: start,
        totalFiles: fileItems.length,
        status: `Processing batch ${batchIndex + 1}/${totalBatches} (${chunk.length} files)...`
      });
    }

    const formData = new FormData();
    for (const item of chunk) {
      formData.append('files', item.file, item.file.name);
      formData.append('paths', item.relativePath);
    }

    const response = await fetch(`${API_UPLOAD}/scan`, {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const errText = await response.text();
      let errorMsg = `Server error HTTP ${response.status}`;
      try {
        const parsed = JSON.parse(errText);
        if (parsed.errorMessage) errorMsg = parsed.errorMessage;
      } catch {
        if (errText) errorMsg = errText;
      }
      throw new Error(errorMsg);
    }

    const batchReport = await response.json();

    if (batchReport.anomalies) {
      aggregatedAnomalies.push(...batchReport.anomalies);
    }
    if (batchReport.files) {
      aggregatedFiles.push(...batchReport.files);
    }
    if (batchReport.consoleLogs) {
      aggregatedLogs.push(...batchReport.consoleLogs);
    }
    if (batchReport.summary) {
      totalFilesScanned += batchReport.summary.totalFilesScanned || chunk.length;
      totalBytesScanned += batchReport.summary.totalBytesScanned || 0;
      totalDurationMs += batchReport.summary.durationMs || 0;
      vtFlaggedCount += batchReport.summary.virusTotalFlaggedCount || 0;
      sbThreatCount += batchReport.summary.safeBrowsingThreatCount || 0;
    }
  }

  // Calculate severity counts
  const criticalCount = aggregatedAnomalies.filter((a) => a.severity === 4).length;
  const highCount = aggregatedAnomalies.filter((a) => a.severity === 3).length;
  const mediumCount = aggregatedAnomalies.filter((a) => a.severity === 2).length;
  const lowCount = aggregatedAnomalies.filter((a) => a.severity === 1).length;
  const infoCount = aggregatedAnomalies.filter((a) => a.severity === 0).length;

  return {
    success: true,
    summary: {
      totalFilesScanned,
      totalBytesScanned,
      totalAnomaliesFound: aggregatedAnomalies.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      virusTotalFlaggedCount: vtFlaggedCount,
      safeBrowsingThreatCount: sbThreatCount,
      durationMs: totalDurationMs,
      scanCompletedAt: new Date().toISOString()
    },
    anomalies: aggregatedAnomalies,
    files: aggregatedFiles,
    consoleLogs: aggregatedLogs
  };
}
