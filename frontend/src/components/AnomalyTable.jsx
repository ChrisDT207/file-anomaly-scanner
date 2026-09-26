import React, { useState } from 'react';
import VendorDetectionsModal from './VendorDetectionsModal';
import UploadConsentModal from './UploadConsentModal';
import CloudSandboxModal from './CloudSandboxModal';

export default function AnomalyTable({ anomalies, summary, files, fileItems = [], onLog }) {
  const [activeTab, setActiveTab] = useState('threats'); // 'threats' | 'allFiles'
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedVtItem, setSelectedVtItem] = useState(null);
  const [consentUploadItem, setConsentUploadItem] = useState(null);
  const [selectedCloudSandboxItem, setSelectedCloudSandboxItem] = useState(null);
  const [eradicatedPaths, setEradicatedPaths] = useState(new Set());
  const [dismissedItems, setDismissedItems] = useState(new Set());
  const [copiedHash, setCopiedHash] = useState(null);

  const getFileObject = (item) => {
    if (!fileItems || fileItems.length === 0 || !item) return null;
    const match = fileItems.find(
      (f) => f.relativePath === item.filePath || f.file?.name === item.fileName
    );
    return match ? match.file : null;
  };

  const severityLabels = {
    4: 'CRITICAL',
    3: 'HIGH',
    2: 'MEDIUM',
    1: 'LOW',
    0: 'INFO'
  };

  const copyHash = (hash) => {
    if (!hash) return;
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredAnomalies = (anomalies || []).filter((item) => {
    if (severityFilter !== 'ALL') {
      const targetSeverity = parseInt(severityFilter, 10);
      if (item.severity !== targetSeverity) return false;
    }

    if (categoryFilter !== 'ALL') {
      if (categoryFilter === 'VIRUSTOTAL' && !item.category.includes('VirusTotal')) return false;
      if (categoryFilter === 'SAFEBROWSING' && !item.category.includes('Safe Browsing')) return false;
      if (categoryFilter === 'HEURISTIC' && (item.category.includes('VirusTotal') || item.category.includes('Safe Browsing'))) return false;
    }

    if (searchTerm.trim() !== '') {
      const term = searchTerm.toLowerCase();
      const inPath = (item.filePath || '').toLowerCase().includes(term);
      const inCat = (item.category || '').toLowerCase().includes(term);
      const inDetails = (item.details || '').toLowerCase().includes(term);
      const inTitle = (item.title || '').toLowerCase().includes(term);
      const inHash = (item.sha256Hash || '').toLowerCase().includes(term);
      if (!inPath && !inCat && !inDetails && !inTitle && !inHash) return false;
    }

    return true;
  });

  const filteredFiles = (files || []).filter((file) => {
    if (searchTerm.trim() !== '') {
      const term = searchTerm.toLowerCase();
      const inPath = (file.filePath || '').toLowerCase().includes(term);
      const inName = (file.fileName || '').toLowerCase().includes(term);
      const inHash = (file.sha256 || '').toLowerCase().includes(term);
      const inStatus = (file.status || '').toLowerCase().includes(term);
      if (!inPath && !inName && !inHash && !inStatus) return false;
    }
    return true;
  });

  const exportReportJson = () => {
    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify({ summary, anomalies, files }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `SecurityThreatReport_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const renderVtBadge = (item) => {
    const vt = item.virusTotalResult || item.virusTotal;
    const sha = item.sha256Hash || item.sha256 || (vt && vt.sha256);
    const vtUrl = vt?.permalink || (sha ? `https://www.virustotal.com/gui/file/${sha}` : null);

    if (vt && (vt.maliciousCount > 0 || vt.suspiciousCount > 0)) {
      return (
        <button
          type="button"
          className="badge-threat-btn vt-malicious-badge"
          onClick={() => setSelectedVtItem(item)}
          title="Click to view detailed Antivirus engine detections"
        >
          🦠 {vt.maliciousCount}/{vt.totalEngines} AV MALICIOUS
        </button>
      );
    }

    if (vt && vt.status === 'Clean') {
      return (
        <span className="badge-pass" title={`Clean across ${vt.totalEngines} engines`}>
          ✓ 0/{vt.totalEngines} CLEAN
        </span>
      );
    }

    if (vt && vt.status === 'NotFound') {
      const isZeroDay = item.isNovelZeroDaySuspicion || 
                        item.localRiskScore >= 35 || 
                        item.status?.includes('Zero-Day') ||
                        (item.highestSeverity && item.highestSeverity >= 3);

      if (isZeroDay) {
        return (
          <div className="zero-day-cell-badge">
            <span className="badge-flag zero-day-badge" title="Novel hash unseen on VirusTotal with high local anomaly score. Suspected Zero-Day.">
              ⚠️ ZERO-DAY SUSPICION
            </span>
            <button
              type="button"
              className="btn-vt-upload"
              onClick={() => setConsentUploadItem(item)}
              title="Submit binary for cloud multi-engine analysis"
            >
              ☁️ Upload
            </button>
          </div>
        );
      }

      return (
        <a
          href={vtUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="badge-link badge-unknown"
          title="Hash not found in VirusTotal database. Click to view or submit."
        >
          ○ UNKNOWN (VT) ↗
        </a>
      );
    }

    if (vt && vt.status === 'RateLimited') {
      return (
        <a
          href={vtUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="badge-link badge-ratelimit"
          title="Rate limited. Click for manual lookup on VirusTotal."
        >
          ⏱ VT RATE LIMIT ↗
        </a>
      );
    }

    if (sha) {
      return (
        <a
          href={vtUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="badge-link badge-vt-ready"
          title="Click to lookup hash on VirusTotal"
        >
          🔍 VT HASH LOOKUP ↗
        </a>
      );
    }

    return <span className="badge-disabled">—</span>;
  };

  const renderSafeBrowsingBadge = (item) => {
    const sbMatch = item.safeBrowsingMatch;
    const sbReport = item.safeBrowsing;

    if (sbMatch || (sbReport && sbReport.hasThreats)) {
      const threatType = sbMatch ? sbMatch.threatType : sbReport.matches[0]?.threatType || 'MALWARE';
      return (
        <span className="badge-flag" title={`Google Safe Browsing Threat: ${threatType}`}>
          🚫 SAFE BROWSING: {threatType}
        </span>
      );
    }

    if (sbReport && sbReport.urlsChecked && sbReport.urlsChecked.length > 0) {
      return (
        <span className="badge-pass" title="All embedded URLs verified safe by Google">
          ✓ {sbReport.urlsChecked.length} URL(s) Clean
        </span>
      );
    }

    return null;
  };

  return (
    <div className="section-card anomaly-section">
      <div className="anomaly-header">
        <div className="table-tabs">
          <button
            type="button"
            className={`tab-btn ${activeTab === 'threats' ? 'active' : ''}`}
            onClick={() => setActiveTab('threats')}
          >
            Threats &amp; Anomalies ({anomalies ? anomalies.length : 0})
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === 'allFiles' ? 'active' : ''}`}
            onClick={() => setActiveTab('allFiles')}
          >
            All Scanned Files &amp; Hashes ({files ? files.length : 0})
          </button>
        </div>

        {summary && (anomalies?.length > 0 || files?.length > 0) && (
          <button type="button" className="btn btn-sm" onClick={exportReportJson}>
            Export Security Report (JSON)
          </button>
        )}
      </div>

      {/* Summary Metrics Bar */}
      {summary && (
        <div className="summary-bar">
          <div className="summary-item">
            <span className="summary-label">Scanned Files:</span>
            <span className="summary-val">{summary.totalFilesScanned}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Total Findings:</span>
            <span className="summary-val font-bold">{summary.totalAnomaliesFound}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Critical:</span>
            <span className="summary-val val-critical">{summary.criticalCount || 0}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">High:</span>
            <span className="summary-val val-high">{summary.highCount || 0}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">VirusTotal Detections:</span>
            <span className={`summary-val ${summary.virusTotalFlaggedCount > 0 ? 'val-critical font-bold' : ''}`}>
              {summary.virusTotalFlaggedCount || 0}
            </span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Safe Browsing Threats:</span>
            <span className={`summary-val ${summary.safeBrowsingThreatCount > 0 ? 'val-critical font-bold' : ''}`}>
              {summary.safeBrowsingThreatCount || 0}
            </span>
          </div>
          {summary.novelZeroDayThreatCount > 0 && (
            <div className="summary-item">
              <span className="summary-label">Zero-Day Suspicion:</span>
              <span className="summary-val val-critical font-bold">
                {summary.novelZeroDayThreatCount}
              </span>
            </div>
          )}
          <div className="summary-item">
            <span className="summary-label">Duration:</span>
            <span className="summary-val">{summary.durationMs} ms</span>
          </div>
        </div>
      )}

      {/* Table Controls */}
      <div className="table-controls">
        {activeTab === 'threats' && (
          <>
            <div className="filter-group">
              <label htmlFor="severitySelect">Severity:</label>
              <select
                id="severitySelect"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="filter-select"
              >
                <option value="ALL">All Severities</option>
                <option value="4">Critical</option>
                <option value="3">High</option>
                <option value="2">Medium</option>
                <option value="1">Low</option>
                <option value="0">Info</option>
              </select>
            </div>

            <div className="filter-group">
              <label htmlFor="categorySelect">Threat Type:</label>
              <select
                id="categorySelect"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="filter-select"
              >
                <option value="ALL">All Types</option>
                <option value="VIRUSTOTAL">VirusTotal Antivirus Flagged</option>
                <option value="SAFEBROWSING">Google Safe Browsing Threats</option>
                <option value="HEURISTIC">Heuristic &amp; Structural Anomalies</option>
              </select>
            </div>
          </>
        )}

        <div className="filter-group filter-grow">
          <label htmlFor="searchInput">Search:</label>
          <input
            id="searchInput"
            type="text"
            className="search-input"
            placeholder="Search by filename, path, SHA-256 hash, or rule..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <div className="filter-count">
          {activeTab === 'threats'
            ? `Showing ${filteredAnomalies.length} of ${anomalies ? anomalies.length : 0} findings`
            : `Showing ${filteredFiles.length} of ${files ? files.length : 0} files`}
        </div>
      </div>

      {/* View: Threats & Anomalies Table */}
      {activeTab === 'threats' && (
        <div className="table-container">
          <table className="anomaly-table">
            <thead>
              <tr>
                <th style={{ width: '90px' }}>Severity</th>
                <th style={{ width: '220px' }}>File Path</th>
                <th style={{ width: '160px' }}>Category</th>
                <th style={{ width: '170px' }}>Threat Intel / AV</th>
                <th style={{ width: '140px' }}>SHA-256 Hash</th>
                <th>Details &amp; Findings</th>
              </tr>
            </thead>
            <tbody>
              {!anomalies || anomalies.length === 0 ? (
                <tr>
                  <td colSpan="6" className="table-empty">
                    No scan performed yet, or all scanned files passed without threats or anomalies.
                  </td>
                </tr>
              ) : filteredAnomalies.length === 0 ? (
                <tr>
                  <td colSpan="6" className="table-empty">
                    No anomalies match the current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredAnomalies.map((item, index) => {
                  const isEradicated = item.filePath && eradicatedPaths.has(item.filePath);
                  const isDismissed = (item.filePath && dismissedItems.has(item.filePath)) ||
                                      (item.sha256Hash && dismissedItems.has(item.sha256Hash));
                  const sevName = severityLabels[item.severity] || 'INFO';
                  const sha = item.sha256Hash || '';
                  const shortSha = sha.length > 14 ? `${sha.slice(0, 10)}...` : sha;
                  return (
                    <tr key={index} className={`row-sev-${item.severity} ${isEradicated ? 'row-eradicated' : ''}`}>
                      <td>
                        {isEradicated ? (
                          <span className="badge badge-eradicated">💥 ERADICATED</span>
                        ) : isDismissed ? (
                          <span className="badge badge-dismissed">✅ MARKED SAFE</span>
                        ) : (
                          <span className={`badge badge-sev-${item.severity}`}>{sevName}</span>
                        )}
                      </td>
                      <td className="cell-filepath" title={item.filePath}>
                        <div className={`font-bold ${isEradicated ? 'text-strikethrough' : ''}`}>
                          {item.fileName}
                        </div>
                        <div className="item-sub-path">{item.filePath}</div>
                      </td>
                      <td>
                        <strong>{item.category}</strong>
                        <div className="item-sub-title">{item.title}</div>
                      </td>
                      <td className="cell-threat-intel">
                        {renderVtBadge(item)}
                        {renderSafeBrowsingBadge(item)}
                        {isEradicated ? (
                          <div className="eradicated-label font-mono">Payload Destroyed</div>
                        ) : (
                          <div style={{ marginTop: '4px' }}>
                            <button
                              type="button"
                              className="btn-cloud-sandbox"
                              onClick={() => setSelectedCloudSandboxItem(item)}
                              title="Inspect cloud hypervisor behavioral telemetry (Process trees, C2 networking, MITRE ATT&CK, 1-click eradication)"
                            >
                              ☁️ Cloud Behavioral Detonation
                            </button>
                          </div>
                        )}
                      </td>
                      <td className="cell-hash font-mono">
                        {sha ? (
                          <div className="hash-wrap">
                            <span title={sha}>{shortSha}</span>
                            <button
                              type="button"
                              className="btn-tiny"
                              onClick={() => copyHash(sha)}
                              title="Copy full SHA-256"
                            >
                              {copiedHash === sha ? '✓' : '📋'}
                            </button>
                            <a
                              href={`https://www.virustotal.com/gui/file/${sha}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="link-icon"
                              title="Search on VirusTotal ↗"
                            >
                              ↗
                            </a>
                          </div>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="cell-details">
                        {item.details}
                        {item.entropy ? (
                          <div className="detail-meta">Entropy: {item.entropy.toFixed(2)}/8.0</div>
                        ) : null}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* View: All Scanned Files & Hashes Table */}
      {activeTab === 'allFiles' && (
        <div className="table-container">
          <table className="anomaly-table">
            <thead>
              <tr>
                <th style={{ width: '110px' }}>Verdict</th>
                <th style={{ width: '220px' }}>File Path</th>
                <th style={{ width: '80px' }}>Size</th>
                <th style={{ width: '160px' }}>SHA-256 Hash</th>
                <th style={{ width: '70px' }}>Entropy</th>
                <th style={{ width: '120px' }}>Type</th>
                <th style={{ width: '160px' }}>VirusTotal AV</th>
                <th>Safe Browsing</th>
              </tr>
            </thead>
            <tbody>
              {!files || files.length === 0 ? (
                <tr>
                  <td colSpan="8" className="table-empty">
                    No files scanned yet. Select or drop a folder to begin.
                  </td>
                </tr>
              ) : filteredFiles.length === 0 ? (
                <tr>
                  <td colSpan="8" className="table-empty">
                    No files match the search criteria.
                  </td>
                </tr>
              ) : (
                filteredFiles.map((file, index) => {
                  const sha = file.sha256 || '';
                  const shortSha = sha.length > 14 ? `${sha.slice(0, 10)}...` : sha;
                  const isMalicious = file.status.includes('Malicious');
                  const isClean = file.status === 'Clean';

                  return (
                    <tr key={index} className={isMalicious ? 'row-sev-4' : ''}>
                      <td>
                        <span
                          className={`badge ${
                            isMalicious
                              ? 'badge-sev-4'
                              : file.status.includes('High')
                              ? 'badge-sev-3'
                              : file.status.includes('Suspicious')
                              ? 'badge-sev-2'
                              : file.anomalyCount > 0
                              ? 'badge-sev-1'
                              : 'badge-sev-0'
                          }`}
                        >
                          {file.status}
                        </span>
                      </td>
                      <td className="cell-filepath" title={file.filePath}>
                        <div className="font-bold">{file.fileName}</div>
                        <div className="item-sub-path">{file.filePath}</div>
                      </td>
                      <td>{formatFileSize(file.sizeBytes)}</td>
                      <td className="cell-hash font-mono">
                        {sha ? (
                          <div className="hash-wrap">
                            <span title={sha}>{shortSha}</span>
                            <button
                              type="button"
                              className="btn-tiny"
                              onClick={() => copyHash(sha)}
                              title="Copy SHA-256"
                            >
                              {copiedHash === sha ? '✓' : '📋'}
                            </button>
                            <a
                              href={`https://www.virustotal.com/gui/file/${sha}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="link-icon"
                              title="Lookup on VirusTotal ↗"
                            >
                              ↗
                            </a>
                          </div>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="cell-entropy">{file.entropy ? `${file.entropy.toFixed(2)}` : '—'}</td>
                      <td>{file.detectedType || '—'}</td>
                      <td>
                        {renderVtBadge(file)}
                        {(file.highestSeverity >= 3 || file.isNovelZeroDaySuspicion || file.status?.includes('Malicious') || file.status?.includes('High')) && (
                          <div style={{ marginTop: '4px' }}>
                            <button
                              type="button"
                              className="btn-detonate"
                              onClick={() => handleDetonate(file)}
                              disabled={isDetonating}
                              title="Launch in isolated, air-gapped Windows Sandbox VM (Read-Only host filesystem)"
                            >
                              📦 Detonate in Sandbox
                            </button>
                          </div>
                        )}
                      </td>
                      <td>{renderSafeBrowsingBadge(file) || <span className="badge-pass">Clean</span>}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Vendor Detections Breakdown Modal */}
      {selectedVtItem && (
        <VendorDetectionsModal
          item={selectedVtItem}
          onClose={() => setSelectedVtItem(null)}
        />
      )}

      {/* Cloud VirusTotal Submission Consent Modal */}
      {consentUploadItem && (
        <UploadConsentModal
          targetItem={consentUploadItem}
          fileObject={getFileObject(consentUploadItem)}
          onClose={() => setConsentUploadItem(null)}
          onSubmitted={(res) => {
            if (onLog) {
              onLog(`[THREAT INTEL] Submitted '${consentUploadItem.fileName}' to VirusTotal. Analysis ID: ${res.analysisId || 'Queued'}`);
            }
          }}
        />
      )}

      {/* Cloud Sandbox Forensic Telemetry & Remediation Modal */}
      {selectedCloudSandboxItem && (
        <CloudSandboxModal
          targetItem={selectedCloudSandboxItem}
          onClose={() => setSelectedCloudSandboxItem(null)}
          onEradicated={(path, receipt) => {
            setEradicatedPaths((prev) => new Set(prev).add(path));
            if (onLog) {
              onLog(`[ERADICATION] Marked '${path}' as permanently eradicated.`);
            }
          }}
          onDismiss={(path, hash) => {
            setDismissedItems((prev) => {
              const updated = new Set(prev);
              if (path) updated.add(path);
              if (hash) updated.add(hash);
              return updated;
            });
            if (onLog) {
              onLog(`[ADJUDICATION] Marked '${path || hash}' as safe / dismissed.`);
            }
          }}
          onLog={onLog}
        />
      )}
    </div>
  );
}

function formatFileSize(bytes) {
  if (bytes === undefined || bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
