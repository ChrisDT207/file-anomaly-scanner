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
      onLog(`[ERADICATION] Initiating cryptographic shredding on '${filePath}'...`);
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
        className="modal-content modal-lg cloud-sandbox-modal"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title-wrap">
            <div>
              <h2 className="modal-title">Cloud Sandbox Behavioral Telemetry</h2>
              <p className="modal-subtitle">
                Hypervisor execution analysis and adjudication for {fileName}
              </p>
            </div>
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose} title="Close">
            &times;
          </button>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="modal-body modal-loading-body">
            <div className="spinner-ring"></div>
            <h4>Extracting Cloud Sandbox Telemetry...</h4>
            <p>Retrieving hypervisor execution traces, process trees, and network activity.</p>
          </div>
        )}

        {/* Error / Offline State */}
        {!loading && fetchError && (
          <div className="modal-body">
            <div className="alert-box alert-error">
              <strong>Telemetry Unavailable:</strong> {fetchError}
            </div>
            {report?.permalink && (
              <div style={{ marginTop: '12px' }}>
                <a
                  href={report.permalink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-secondary btn-sm"
                >
                  Inspect on VirusTotal
                </a>
              </div>
            )}
          </div>
        )}

        {/* Loaded Telemetry Content */}
        {!loading && !fetchError && report && (
          <div className="modal-body cs-modal-body">
            {/* Target File Info Summary Card */}
            <div className="cs-info-card">
              <div className="cs-info-grid">
                <div className="cs-info-cell">
                  <span className="cs-info-lbl">Target File:</span>
                  <span className="cs-info-val font-bold">{fileName}</span>
                </div>
                <div className="cs-info-cell">
                  <span className="cs-info-lbl">Filesystem Path:</span>
                  <span className="cs-info-val font-mono">{filePath || 'Uploaded File'}</span>
                </div>
                <div className="cs-info-cell">
                  <span className="cs-info-lbl">SHA-256:</span>
                  <span className="cs-info-val font-mono">{sha256}</span>
                </div>
              </div>
            </div>

            {/* Verdict Alert Banner */}
            <div
              className={`cs-verdict-card ${
                isTruePositive
                  ? 'cs-verdict-danger'
                  : isLikelyFalsePositive
                  ? 'cs-verdict-success'
                  : 'cs-verdict-warning'
              }`}
            >
              <div className="cs-verdict-header">
                <span
                  className={`cs-verdict-pill ${
                    isTruePositive
                      ? 'pill-danger'
                      : isLikelyFalsePositive
                      ? 'pill-success'
                      : 'pill-warning'
                  }`}
                >
                  {isTruePositive
                    ? 'CONFIRMED THREAT (TRUE POSITIVE)'
                    : isLikelyFalsePositive
                    ? 'BENIGN DYNAMIC BEHAVIOR (LIKELY FALSE POSITIVE)'
                    : 'TELEMETRY INCONCLUSIVE'}
                </span>
                {verdict?.confidenceScore && (
                  <span className="cs-confidence-tag">
                    Confidence: {verdict.confidenceScore}%
                  </span>
                )}
              </div>
              <h4 className="cs-verdict-title">{verdict?.title || 'Execution Verdict'}</h4>
              <p className="cs-verdict-desc">{verdict?.justification}</p>

              {verdict?.indicators && verdict.indicators.length > 0 && (
                <div className="cs-indicators-list">
                  <strong>Adjudication Signals:</strong>
                  <ul>
                    {verdict.indicators.map((ind, idx) => (
                      <li key={idx}>{ind}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Navigation Tabs */}
            <div className="cs-nav-tabs">
              <button
                type="button"
                className={`cs-nav-tab ${activeTab === 'verdict' ? 'active' : ''}`}
                onClick={() => setActiveTab('verdict')}
              >
                Overview
              </button>
              <button
                type="button"
                className={`cs-nav-tab ${activeTab === 'processes' ? 'active' : ''}`}
                onClick={() => setActiveTab('processes')}
              >
                Processes ({report.processesCreated?.length || 0})
              </button>
              <button
                type="button"
                className={`cs-nav-tab ${activeTab === 'network' ? 'active' : ''}`}
                onClick={() => setActiveTab('network')}
              >
                Network (
                {(report.networkActivity?.contactedIps?.length || 0) +
                  (report.networkActivity?.dnsLookups?.length || 0) +
                  (report.networkActivity?.httpRequests?.length || 0)}
                )
              </button>
              <button
                type="button"
                className={`cs-nav-tab ${activeTab === 'persistence' ? 'active' : ''}`}
                onClick={() => setActiveTab('persistence')}
              >
                Persistence &amp; Filesystem (
                {(report.fileAndRegistryTampering?.filesDropped?.length || 0) +
                  (report.fileAndRegistryTampering?.registryKeysSet?.length || 0)}
                )
              </button>
              <button
                type="button"
                className={`cs-nav-tab ${activeTab === 'mitre' ? 'active' : ''}`}
                onClick={() => setActiveTab('mitre')}
              >
                MITRE ATT&amp;CK ({report.mitreAttackSignatures?.length || 0})
              </button>
            </div>

            {/* Tab Contents */}
            <div className="cs-tab-panel">
              {/* Tab: Overview */}
              {activeTab === 'verdict' && (
                <div className="cs-panel-content">
                  <div className="cs-stat-row">
                    <div className="cs-metric-box">
                      <span className="cs-metric-num">{report.processesCreated?.length || 0}</span>
                      <span className="cs-metric-lbl">Processes Spawned</span>
                    </div>
                    <div className="cs-metric-box">
                      <span className="cs-metric-num">{report.networkActivity?.contactedIps?.length || 0}</span>
                      <span className="cs-metric-lbl">Contacted External IPs</span>
                    </div>
                    <div className="cs-metric-box">
                      <span className="cs-metric-num">
                        {(report.fileAndRegistryTampering?.filesDropped?.length || 0) +
                          (report.fileAndRegistryTampering?.filesWritten?.length || 0)}
                      </span>
                      <span className="cs-metric-lbl">Files Dropped / Written</span>
                    </div>
                    <div className="cs-metric-box">
                      <span className={`cs-metric-num ${report.mitreAttackSignatures?.length > 0 ? 'text-critical' : ''}`}>
                        {report.mitreAttackSignatures?.length || 0}
                      </span>
                      <span className="cs-metric-lbl">MITRE ATT&amp;CK Flags</span>
                    </div>
                  </div>

                  <div className="cs-guidance-box">
                    <strong>Adjudication Guidance:</strong>
                    <ul>
                      <li>
                        <strong>Benign False Positive Signals:</strong> Clean process termination, absence of external network beacons, zero autostart registry Run keys, and no secondary payloads written to temporary folders.
                      </li>
                      <li>
                        <strong>True Positive Signals:</strong> Hidden execution flags, outbound connections to external IPs, creation of reboot survival registry keys, or known adversarial MITRE techniques.
                      </li>
                    </ul>
                  </div>
                </div>
              )}

              {/* Tab: Processes */}
              {activeTab === 'processes' && (
                <div className="cs-panel-content">
                  {(!report.processesCreated || report.processesCreated.length === 0) ? (
                    <div className="cs-empty-msg">
                      No secondary child processes were spawned during sandbox execution.
                    </div>
                  ) : (
                    <div className="cs-process-table-wrap">
                      <table className="anomaly-table">
                        <thead>
                          <tr>
                            <th style={{ width: '100px' }}>PID</th>
                            <th style={{ width: '180px' }}>Process Name</th>
                            <th>Command Line</th>
                          </tr>
                        </thead>
                        <tbody>
                          {report.processesCreated.map((proc, idx) => (
                            <tr key={idx}>
                              <td className="font-mono">{proc.pid || `PID-${idx + 1}`}</td>
                              <td className="font-bold">{proc.processName || 'Execution Command'}</td>
                              <td className="font-mono cs-cmd-cell">{proc.commandLine}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Network */}
              {activeTab === 'network' && (
                <div className="cs-panel-content">
                  <h4 className="cs-section-subtitle">Contacted IP Addresses:</h4>
                  {(!report.networkActivity?.contactedIps || report.networkActivity.contactedIps.length === 0) ? (
                    <div className="cs-empty-msg">
                      No outbound IP connections observed during execution.
                    </div>
                  ) : (
                    <table className="anomaly-table">
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
                            <td className="font-mono font-bold">{ip.ipAddress}</td>
                            <td>{ip.port || 443}</td>
                            <td>{ip.protocol || 'TCP'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  <h4 className="cs-section-subtitle" style={{ marginTop: '16px' }}>DNS Lookups:</h4>
                  {(!report.networkActivity?.dnsLookups || report.networkActivity.dnsLookups.length === 0) ? (
                    <div className="cs-empty-msg">
                      No external DNS lookups observed.
                    </div>
                  ) : (
                    <table className="anomaly-table">
                      <thead>
                        <tr>
                          <th>Hostname</th>
                          <th>Resolved IP Addresses</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.networkActivity.dnsLookups.map((dns, idx) => (
                          <tr key={idx}>
                            <td className="font-mono font-bold">{dns.hostname}</td>
                            <td className="font-mono">{dns.resolvedIps?.join(', ') || 'Unresolved'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  {report.networkActivity?.httpRequests && report.networkActivity.httpRequests.length > 0 && (
                    <>
                      <h4 className="cs-section-subtitle" style={{ marginTop: '16px' }}>HTTP Requests:</h4>
                      <table className="anomaly-table">
                        <thead>
                          <tr>
                            <th style={{ width: '80px' }}>Method</th>
                            <th>URL</th>
                            <th style={{ width: '100px' }}>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {report.networkActivity.httpRequests.map((http, idx) => (
                            <tr key={idx}>
                              <td className="font-bold">{http.method}</td>
                              <td className="font-mono cs-cmd-cell">{http.url}</td>
                              <td>{http.responseCode ? `HTTP ${http.responseCode}` : 'N/A'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </>
                  )}
                </div>
              )}

              {/* Tab: Persistence & Filesystem */}
              {activeTab === 'persistence' && (
                <div className="cs-panel-content">
                  <h4 className="cs-section-subtitle">Persistence Registry Keys:</h4>
                  {(!report.fileAndRegistryTampering?.registryKeysSet || report.fileAndRegistryTampering.registryKeysSet.length === 0) ? (
                    <div className="cs-empty-msg">
                      No autostart or persistence registry keys were written.
                    </div>
                  ) : (
                    <table className="anomaly-table">
                      <thead>
                        <tr>
                          <th>Registry Key</th>
                          <th>Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.fileAndRegistryTampering.registryKeysSet.map((reg, idx) => (
                          <tr key={idx}>
                            <td className="font-mono font-bold text-critical">{reg.key}</td>
                            <td className="font-mono">{reg.value || 'N/A'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  <h4 className="cs-section-subtitle" style={{ marginTop: '16px' }}>Dropped Files:</h4>
                  {(!report.fileAndRegistryTampering?.filesDropped || report.fileAndRegistryTampering.filesDropped.length === 0) ? (
                    <div className="cs-empty-msg">
                      No secondary files were dropped to disk.
                    </div>
                  ) : (
                    <table className="anomaly-table">
                      <thead>
                        <tr>
                          <th>Path Dropped</th>
                          <th>Type</th>
                          <th>SHA-256 Hash</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.fileAndRegistryTampering.filesDropped.map((file, idx) => (
                          <tr key={idx}>
                            <td className="font-mono">{file.path}</td>
                            <td>{file.type || 'Binary / Data'}</td>
                            <td className="font-mono">{file.sha256 ? `${file.sha256.slice(0, 16)}...` : 'N/A'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {/* Tab: MITRE ATT&CK */}
              {activeTab === 'mitre' && (
                <div className="cs-panel-content">
                  {(!report.mitreAttackSignatures || report.mitreAttackSignatures.length === 0) ? (
                    <div className="cs-empty-msg">
                      Zero adversarial MITRE ATT&amp;CK techniques identified.
                    </div>
                  ) : (
                    <table className="anomaly-table">
                      <thead>
                        <tr>
                          <th style={{ width: '90px' }}>ID</th>
                          <th style={{ width: '100px' }}>Severity</th>
                          <th style={{ width: '180px' }}>Technique</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.mitreAttackSignatures.map((m, idx) => (
                          <tr key={idx}>
                            <td className="font-mono font-bold">{m.id}</td>
                            <td>
                              <span
                                className={`badge ${
                                  m.severity === 'CRITICAL'
                                    ? 'badge-sev-4'
                                    : m.severity === 'HIGH'
                                    ? 'badge-sev-3'
                                    : m.severity === 'MEDIUM'
                                    ? 'badge-sev-2'
                                    : 'badge-sev-1'
                                }`}
                              >
                                {m.severity || 'MEDIUM'}
                              </span>
                            </td>
                            <td className="font-bold">{m.name}</td>
                            <td>{m.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </div>

            {/* Eradication Receipt Notice */}
            {eradicationReceipt && (
              <div className="alert-box alert-success cs-receipt-alert">
                <strong>Payload Successfully Eradicated:</strong>
                <div>{eradicationReceipt.message}</div>
                <div className="receipt-sub font-mono">
                  Method: {eradicationReceipt.shredMethod} | Bytes Overwritten: {eradicationReceipt.bytesOverwritten}
                </div>
              </div>
            )}

            {/* Eradication Error Notice */}
            {eradicationError && (
              <div className="alert-box alert-error">
                <strong>Eradication Error:</strong> {eradicationError}
              </div>
            )}
          </div>
        )}

        {/* Modal Footer Actions */}
        <div className="modal-footer cs-modal-footer">
          <div className="cs-footer-links">
            {report?.permalink && (
              <a
                href={report.permalink}
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-secondary btn-sm"
              >
                Open VirusTotal Report
              </a>
            )}
          </div>

          <div className="cs-footer-btns">
            {!eradicationReceipt && (
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleDismiss}
                title="Adjudicate anomaly as a benign false positive and dismiss alert"
              >
                Mark as Safe / Dismiss
              </button>
            )}

            {filePath && !eradicationReceipt && (
              <>
                {!confirmEradicate ? (
                  <button
                    type="button"
                    className="btn btn-danger"
                    onClick={() => setConfirmEradicate(true)}
                    disabled={isEradicating}
                    title="Execute cryptographic multi-pass overwrite and permanent file destruction"
                  >
                    Neutralize &amp; Eradicate File
                  </button>
                ) : (
                  <div className="cs-confirm-shred-box">
                    <span className="cs-confirm-label">Confirm permanent deletion?</span>
                    <button
                      type="button"
                      className="btn btn-danger btn-sm"
                      onClick={handleEradicate}
                      disabled={isEradicating}
                    >
                      {isEradicating ? 'Shredding...' : 'Confirm Eradication'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => setConfirmEradicate(false)}
                      disabled={isEradicating}
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </>
            )}

            <button type="button" className="btn btn-secondary" onClick={onClose}>
              {eradicationReceipt ? 'Done' : 'Close'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
