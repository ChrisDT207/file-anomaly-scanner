import React, { useState, useEffect } from 'react';
import { fetchCloudBehavior, eradicateFile } from '../utils/apiService';

export default function CloudSandboxModal({
  targetItem,
  onClose,
  onEradicated,
  onDismiss,
  onLog
}) {
  const [activeTab, setActiveTab] = useState('verdict'); // 'verdict' | 'processes' | 'network' | 'persistence' | 'mitre'
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState(null);
  const [fetchError, setFetchError] = useState(null);
  const [isEradicating, setIsEradicating] = useState(false);
  const [eradicationReceipt, setEradicationReceipt] = useState(null);
  const [eradicationError, setEradicationError] = useState(null);
  const [confirmEradicate, setConfirmEradicate] = useState(false);

  const sha256 = targetItem?.sha256Hash || targetItem?.sha256;
  const filePath = targetItem?.filePath;
  const fileName = targetItem?.fileName || (filePath ? filePath.split(/[\\/]/).pop() : 'Suspicious Payload');

  useEffect(() => {
    let isMounted = true;
    async function loadBehavior() {
      if (!sha256) {
        setFetchError('No SHA-256 hash available for this file.');
        setLoading(false);
        return;
      }

      setLoading(true);
      setFetchError(null);
      try {
        const data = await fetchCloudBehavior(sha256);
        if (isMounted) {
          setReport(data);
          // If true positive, start on verdict or MITRE
          if (data.verdictSummary?.verdict === 'TruePositive') {
            setActiveTab('verdict');
          }
        }
      } catch (err) {
        if (isMounted) {
          setFetchError(err.message || 'Failed to load behavioral telemetry.');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    loadBehavior();
    return () => {
      isMounted = false;
    };
  }, [sha256]);

  const handleEradicate = async () => {
    if (!filePath) {
      setEradicationError('Cannot eradicate: Host file path is unavailable.');
      return;
    }

    setIsEradicating(true);
    setEradicationError(null);

    if (onLog) {
      onLog(`[ERADICATION] Initiating DOD cryptographic shredding on '${filePath}'...`);
    }

    try {
      const receipt = await eradicateFile(filePath, sha256);
      setEradicationReceipt(receipt);
      setConfirmEradicate(false);

      if (onLog) {
        onLog(`[ERADICATION] [SUCCESS] ${receipt.message} (${receipt.bytesOverwritten} bytes zeroed).`);
      }

      if (onEradicated) {
        onEradicated(filePath, receipt);
      }
    } catch (err) {
      setEradicationError(err.message || 'Failed to eradicate file.');
      if (onLog) {
        onLog(`[ERADICATION] [ERROR] ${err.message}`);
      }
    } finally {
      setIsEradicating(false);
    }
  };

  const handleDismiss = () => {
    if (onLog) {
      onLog(`[ADJUDICATION] File '${fileName}' marked as Safe / False Positive by operator.`);
    }
    if (onDismiss) {
      onDismiss(filePath, sha256);
    }
    onClose();
  };

  const verdict = report?.verdictSummary;
  const isTruePositive = verdict?.verdict === 'TruePositive';
  const isLikelyFalsePositive = verdict?.verdict === 'LikelyFalsePositive';

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-content cloud-sandbox-modal"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <div className="cs-modal-header">
          <div className="cs-header-title">
            <span className="cs-header-icon">☁️</span>
            <div>
              <h3>Cloud Sandbox Behavioral Telemetry</h3>
              <div className="cs-header-subtitle">
                <span className="cs-target-name">{fileName}</span>
                {sha256 && (
                  <span className="cs-target-hash font-mono" title={sha256}>
                    SHA-256: {sha256.slice(0, 16)}...
                  </span>
                )}
              </div>
            </div>
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close">
            &times;
          </button>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="cs-loading-panel">
            <div className="cs-radar-spinner"></div>
            <h4>Extracting Hypervisor Dynamic Execution Telemetry...</h4>
            <p>Correlating process trees, C2 network connections, and MITRE ATT&CK techniques via VirusTotal Cloud Hypervisors.</p>
          </div>
        )}

        {/* Error / Offline State */}
        {!loading && fetchError && (
          <div className="cs-error-panel">
            <div className="cs-error-icon">⚠️</div>
            <h4>Cloud Telemetry Unavailable</h4>
            <p>{fetchError}</p>
            {report?.permalink && (
              <a
                href={report.permalink}
                target="_blank"
                rel="noopener noreferrer"
                className="cs-link-btn"
              >
                Inspect on VirusTotal ↗
              </a>
            )}
          </div>
        )}

        {/* Loaded Telemetry Content */}
        {!loading && !fetchError && report && (
          <div className="cs-body">
            {/* Verdict Banner */}
            <div
              className={`cs-verdict-banner ${
                isTruePositive
                  ? 'verdict-true-positive'
                  : isLikelyFalsePositive
                  ? 'verdict-false-positive'
                  : 'verdict-inconclusive'
              }`}
            >
              <div className="cs-verdict-icon">
                {isTruePositive ? '🔴' : isLikelyFalsePositive ? '🟢' : '🟡'}
              </div>
              <div className="cs-verdict-info">
                <div className="cs-verdict-top-row">
                  <span className="cs-verdict-badge">
                    {isTruePositive
                      ? 'CONFIRMED THREAT (TRUE POSITIVE)'
                      : isLikelyFalsePositive
                      ? 'BENIGN DYNAMIC BEHAVIOR (LIKELY FALSE POSITIVE)'
                      : 'DYNAMIC TELEMETRY INCONCLUSIVE'}
                  </span>
                  {verdict?.confidenceScore && (
                    <span className="cs-confidence-pill">
                      Confidence: {verdict.confidenceScore}%
                    </span>
                  )}
                </div>
                <h4 className="cs-verdict-title">{verdict?.title || 'Dynamic Execution Verdict'}</h4>
                <p className="cs-verdict-desc">{verdict?.justification}</p>

                {verdict?.indicators && verdict.indicators.length > 0 && (
                  <div className="cs-indicators-box">
                    <strong>Adjudication Signals:</strong>
                    <ul>
                      {verdict.indicators.map((ind, idx) => (
                        <li key={idx}>{ind}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="cs-tabs">
              <button
                type="button"
                className={`cs-tab-btn ${activeTab === 'verdict' ? 'active' : ''}`}
                onClick={() => setActiveTab('verdict')}
              >
                ⚖️ Adjudication Overview
              </button>
              <button
                type="button"
                className={`cs-tab-btn ${activeTab === 'processes' ? 'active' : ''}`}
                onClick={() => setActiveTab('processes')}
              >
                🌳 Process Tree &amp; Execution ({report.processesCreated?.length || 0})
              </button>
              <button
                type="button"
                className={`cs-tab-btn ${activeTab === 'network' ? 'active' : ''}`}
                onClick={() => setActiveTab('network')}
              >
                🌐 Network &amp; C2 (
                {(report.networkActivity?.contactedIps?.length || 0) +
                  (report.networkActivity?.dnsLookups?.length || 0) +
                  (report.networkActivity?.httpRequests?.length || 0)}
                )
              </button>
              <button
                type="button"
                className={`cs-tab-btn ${activeTab === 'persistence' ? 'active' : ''}`}
                onClick={() => setActiveTab('persistence')}
              >
                💾 Persistence &amp; Filesystem (
                {(report.fileAndRegistryTampering?.filesDropped?.length || 0) +
                  (report.fileAndRegistryTampering?.registryKeysSet?.length || 0)}
                )
              </button>
              <button
                type="button"
                className={`cs-tab-btn ${activeTab === 'mitre' ? 'active' : ''}`}
                onClick={() => setActiveTab('mitre')}
              >
                🛡️ MITRE ATT&amp;CK ({report.mitreAttackSignatures?.length || 0})
              </button>
            </div>

            {/* Tab Contents */}
            <div className="cs-tab-content">
              {/* Tab: Overview */}
              {activeTab === 'verdict' && (
                <div className="cs-tab-pane">
                  <div className="cs-summary-grid">
                    <div className="cs-stat-card">
                      <div className="cs-stat-label">Processes Spawned</div>
                      <div className="cs-stat-val">{report.processesCreated?.length || 0}</div>
                      <div className="cs-stat-sub">Child processes executed</div>
                    </div>
                    <div className="cs-stat-card">
                      <div className="cs-stat-label">External IPs Contacted</div>
                      <div className="cs-stat-val">{report.networkActivity?.contactedIps?.length || 0}</div>
                      <div className="cs-stat-sub">Outbound network endpoints</div>
                    </div>
                    <div className="cs-stat-card">
                      <div className="cs-stat-label">Files Dropped / Modified</div>
                      <div className="cs-stat-val">
                        {(report.fileAndRegistryTampering?.filesDropped?.length || 0) +
                          (report.fileAndRegistryTampering?.filesWritten?.length || 0)}
                      </div>
                      <div className="cs-stat-sub">Secondary payloads written</div>
                    </div>
                    <div className="cs-stat-card">
                      <div className="cs-stat-label">MITRE ATT&amp;CK Flags</div>
                      <div className={`cs-stat-val ${report.mitreAttackSignatures?.length > 0 ? 'text-danger' : ''}`}>
                        {report.mitreAttackSignatures?.length || 0}
                      </div>
                      <div className="cs-stat-sub">Matched adversarial techniques</div>
                    </div>
                  </div>

                  <div className="cs-forensic-notes">
                    <h4>Principal Engineer Forensics Guide:</h4>
                    <ul>
                      <li>
                        <strong>Benign False Positive Indicators:</strong> Clean process exit codes, no network calls outside local loopback, no registry Run keys, no dropped files in <code>%TEMP%</code> or <code>System32</code>.
                      </li>
                      <li>
                        <strong>Confirmed Malicious Indicators:</strong> Hidden execution (e.g. <code>powershell -w hidden -enc</code>), beaconing to high-port TCP/UDP, autostart registry creation, credential dumping, or process injection.
                      </li>
                    </ul>
                  </div>
                </div>
              )}

              {/* Tab: Processes */}
              {activeTab === 'processes' && (
                <div className="cs-tab-pane">
                  {(!report.processesCreated || report.processesCreated.length === 0) ? (
                    <div className="cs-empty-state">
                      <span>✓</span> No secondary child processes were spawned during sandbox execution.
                    </div>
                  ) : (
                    <div className="cs-process-list">
                      {report.processesCreated.map((proc, idx) => (
                        <div key={idx} className="cs-process-item">
                          <div className="cs-process-title">
                            <span className="cs-proc-badge">PID {proc.pid || idx + 1}</span>
                            <strong>{proc.processName || 'Execution Command'}</strong>
                          </div>
                          <div className="cs-code-box font-mono">{proc.commandLine}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Network */}
              {activeTab === 'network' && (
                <div className="cs-tab-pane">
                  <h4>Contacted IP Addresses &amp; C2 Channels:</h4>
                  {(!report.networkActivity?.contactedIps || report.networkActivity.contactedIps.length === 0) ? (
                    <div className="cs-empty-state">
                      <span>✓</span> No external outbound IP connections observed during execution.
                    </div>
                  ) : (
                    <table className="cs-telemetry-table">
                      <thead>
                        <tr>
                          <th>Destination IP</th>
                          <th>Port</th>
                          <th>Protocol</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.networkActivity.contactedIps.map((ip, idx) => (
                          <tr key={idx}>
                            <td className="font-mono">{ip.ipAddress}</td>
                            <td>{ip.port || '443'}</td>
                            <td>
                              <span className="cs-proto-badge">{ip.protocol || 'TCP'}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  <h4 style={{ marginTop: '16px' }}>DNS Hostname Lookups:</h4>
                  {(!report.networkActivity?.dnsLookups || report.networkActivity.dnsLookups.length === 0) ? (
                    <div className="cs-empty-state">
                      <span>✓</span> No external DNS queries performed.
                    </div>
                  ) : (
                    <div className="cs-dns-list">
                      {report.networkActivity.dnsLookups.map((dns, idx) => (
                        <div key={idx} className="cs-dns-item font-mono">
                          <span className="dns-host">🌐 {dns.hostname}</span>
                          {dns.resolvedIps && dns.resolvedIps.length > 0 && (
                            <span className="dns-resolved">→ {dns.resolvedIps.join(', ')}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {report.networkActivity?.httpRequests && report.networkActivity.httpRequests.length > 0 && (
                    <>
                      <h4 style={{ marginTop: '16px' }}>HTTP Web Conversations:</h4>
                      <div className="cs-http-list">
                        {report.networkActivity.httpRequests.map((http, idx) => (
                          <div key={idx} className="cs-http-item">
                            <span className="http-method">{http.method}</span>
                            <span className="http-url font-mono">{http.url}</span>
                            {http.responseCode && (
                              <span className="http-status">HTTP {http.responseCode}</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* Tab: Persistence & Filesystem */}
              {activeTab === 'persistence' && (
                <div className="cs-tab-pane">
                  <h4>Autostart &amp; Persistence Registry Keys:</h4>
                  {(!report.fileAndRegistryTampering?.registryKeysSet || report.fileAndRegistryTampering.registryKeysSet.length === 0) ? (
                    <div className="cs-empty-state">
                      <span>✓</span> No autostart or persistence registry keys were written.
                    </div>
                  ) : (
                    <div className="cs-reg-list">
                      {report.fileAndRegistryTampering.registryKeysSet.map((reg, idx) => (
                        <div key={idx} className="cs-reg-item">
                          <div className="reg-key font-mono">🔑 {reg.key}</div>
                          {reg.value && <div className="reg-val font-mono">Value: {reg.value}</div>}
                        </div>
                      ))}
                    </div>
                  )}

                  <h4 style={{ marginTop: '16px' }}>Files Dropped by Payload:</h4>
                  {(!report.fileAndRegistryTampering?.filesDropped || report.fileAndRegistryTampering.filesDropped.length === 0) ? (
                    <div className="cs-empty-state">
                      <span>✓</span> No secondary files dropped to disk.
                    </div>
                  ) : (
                    <table className="cs-telemetry-table">
                      <thead>
                        <tr>
                          <th>Path Dropped</th>
                          <th>Type</th>
                          <th>Payload SHA-256</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.fileAndRegistryTampering.filesDropped.map((file, idx) => (
                          <tr key={idx}>
                            <td className="font-mono">{file.path}</td>
                            <td>{file.type || 'Binary / Data'}</td>
                            <td className="font-mono">{file.sha256 ? `${file.sha256.slice(0, 12)}...` : '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {/* Tab: MITRE ATT&CK */}
              {activeTab === 'mitre' && (
                <div className="cs-tab-pane">
                  {(!report.mitreAttackSignatures || report.mitreAttackSignatures.length === 0) ? (
                    <div className="cs-empty-state">
                      <span>✓</span> Zero adversarial MITRE ATT&amp;CK techniques triggered.
                    </div>
                  ) : (
                    <div className="cs-mitre-grid">
                      {report.mitreAttackSignatures.map((m, idx) => (
                        <div key={idx} className={`cs-mitre-card sev-${(m.severity || 'medium').toLowerCase()}`}>
                          <div className="mitre-header">
                            <span className="mitre-id">{m.id}</span>
                            <span className={`mitre-sev-badge sev-${(m.severity || 'medium').toLowerCase()}`}>
                              {m.severity || 'DETECTED'}
                            </span>
                          </div>
                          <div className="mitre-name">{m.name}</div>
                          {m.tactic && <div className="mitre-tactic">Tactic: {m.tactic}</div>}
                          <div className="mitre-desc">{m.description}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Eradication Receipt Notice */}
            {eradicationReceipt && (
              <div className="cs-receipt-box">
                <div className="receipt-icon">💥</div>
                <div className="receipt-info">
                  <h4>Payload Successfully Eradicated</h4>
                  <p>{eradicationReceipt.message}</p>
                  <div className="receipt-meta font-mono">
                    Method: {eradicationReceipt.shredMethod} | Bytes Overwritten: {eradicationReceipt.bytesOverwritten}
                  </div>
                </div>
              </div>
            )}

            {/* Eradication Error Notice */}
            {eradicationError && (
              <div className="cs-err-notice">
                ⚠️ Eradication Error: {eradicationError}
              </div>
            )}
          </div>
        )}

        {/* Footer Actions */}
        <div className="cs-modal-footer">
          <div className="cs-footer-left">
            {report?.permalink && (
              <a
                href={report.permalink}
                target="_blank"
                rel="noopener noreferrer"
                className="cs-vt-link"
              >
                VirusTotal Cloud Telemetry ↗
              </a>
            )}
          </div>

          <div className="cs-footer-right">
            {/* Mark as Safe / Dismiss Button */}
            {!eradicationReceipt && (
              <button
                type="button"
                className="btn-mark-safe"
                onClick={handleDismiss}
                title="Adjudicate anomaly as a benign false positive and dismiss alert"
              >
                ✅ Mark as Safe / Dismiss
              </button>
            )}

            {/* 1-Click Eradication Button */}
            {filePath && !eradicationReceipt && (
              <>
                {!confirmEradicate ? (
                  <button
                    type="button"
                    className="btn-eradicate"
                    onClick={() => setConfirmEradicate(true)}
                    disabled={isEradicating}
                    title="Execute DOD multi-pass cryptographic overwrite and permanent file destruction"
                  >
                    💥 Neutralize &amp; Eradicate File
                  </button>
                ) : (
                  <div className="cs-confirm-eradicate-wrap">
                    <span className="confirm-text">Permanently shred from disk?</span>
                    <button
                      type="button"
                      className="btn-confirm-shred"
                      onClick={handleEradicate}
                      disabled={isEradicating}
                    >
                      {isEradicating ? 'Shredding...' : 'Confirm Eradication'}
                    </button>
                    <button
                      type="button"
                      className="btn-cancel-shred"
                      onClick={() => setConfirmEradicate(false)}
                      disabled={isEradicating}
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </>
            )}

            <button type="button" className="btn-cs-close" onClick={onClose}>
              {eradicationReceipt ? 'Done' : 'Close'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
