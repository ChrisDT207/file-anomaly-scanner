import React, { useState } from 'react';

export default function VendorDetectionsModal({ item, onClose }) {
  const [vendorFilter, setVendorFilter] = useState('');
  const [copied, setCopied] = useState(false);

  if (!item) return null;

  const vt = item.virusTotalResult || item.virusTotal;
  const sha = item.sha256Hash || item.sha256 || vt?.sha256 || '';
  const permalink = vt?.permalink || `https://www.virustotal.com/gui/file/${sha}`;

  const copyHash = () => {
    if (sha) {
      navigator.clipboard.writeText(sha);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const vendors = vt?.vendorDetections ? Object.entries(vt.vendorDetections) : [];
  const filteredVendors = vendors.filter(([vendor, detection]) => {
    if (!vendorFilter.trim()) return true;
    const term = vendorFilter.toLowerCase();
    return vendor.toLowerCase().includes(term) || detection.toLowerCase().includes(term);
  });

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content modal-lg" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-wrap">
            <span className="modal-icon">🦠</span>
            <div>
              <h2 className="modal-title">VirusTotal Antivirus Engine Breakdown</h2>
              <p className="modal-subtitle">
                Comprehensive vendor threat classifications for {item.fileName}
              </p>
            </div>
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose} title="Close">
            ✕
          </button>
        </div>

        <div className="modal-body">
          {/* File & Threat Info Header */}
          <div className="vt-report-summary-card">
            <div className="vt-summary-grid">
              <div className="vt-sum-cell">
                <span className="vt-sum-lbl">File:</span>
                <span className="vt-sum-val font-mono">{item.fileName}</span>
              </div>
              <div className="vt-sum-cell">
                <span className="vt-sum-lbl">Path:</span>
                <span className="vt-sum-val font-mono">{item.filePath}</span>
              </div>
              <div className="vt-sum-cell">
                <span className="vt-sum-lbl">SHA-256:</span>
                <span className="vt-sum-val font-mono hash-display">
                  {sha}
                  <button
                    type="button"
                    className="btn-copy"
                    onClick={copyHash}
                    title="Copy SHA-256"
                  >
                    {copied ? '✓ Copied' : '📋 Copy'}
                  </button>
                </span>
              </div>
              {vt?.suggestedThreatLabel && (
                <div className="vt-sum-cell">
                  <span className="vt-sum-lbl">Threat Label:</span>
                  <span className="vt-sum-val threat-label-badge">
                    {vt.suggestedThreatLabel}
                  </span>
                </div>
              )}
            </div>

            {/* Antivirus Stats Bar */}
            {vt && (
              <div className="vt-stats-bar">
                <div className="vt-stat-badge stat-malicious">
                  <span className="stat-num">{vt.maliciousCount}</span>
                  <span className="stat-name">Malicious</span>
                </div>
                <div className="vt-stat-badge stat-suspicious">
                  <span className="stat-num">{vt.suspiciousCount}</span>
                  <span className="stat-name">Suspicious</span>
                </div>
                <div className="vt-stat-badge stat-undetected">
                  <span className="stat-num">{vt.undetectedCount}</span>
                  <span className="stat-name">Undetected</span>
                </div>
                <div className="vt-stat-badge stat-harmless">
                  <span className="stat-num">{vt.harmlessCount}</span>
                  <span className="stat-name">Harmless</span>
                </div>
                <div className="vt-stat-badge stat-total">
                  <span className="stat-num">{vt.totalEngines}</span>
                  <span className="stat-name">Total Engines</span>
                </div>
                {vt.reputation !== undefined && (
                  <div className="vt-stat-badge stat-reputation">
                    <span className="stat-num">{vt.reputation}</span>
                    <span className="stat-name">Reputation</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Search Vendors */}
          <div className="vendor-search-bar">
            <input
              type="text"
              className="search-input"
              placeholder="Search by antivirus vendor (e.g. Microsoft, Kaspersky, CrowdStrike)..."
              value={vendorFilter}
              onChange={(e) => setVendorFilter(e.target.value)}
            />
            <span className="vendor-count">
              Showing {filteredVendors.length} of {vendors.length} vendor detections
            </span>
          </div>

          {/* Vendors Table */}
          <div className="table-container vendor-table-container">
            <table className="anomaly-table">
              <thead>
                <tr>
                  <th style={{ width: '200px' }}>Antivirus Vendor</th>
                  <th>Detection / Malware Signature</th>
                </tr>
              </thead>
              <tbody>
                {filteredVendors.length === 0 ? (
                  <tr>
                    <td colSpan="2" className="table-empty">
                      {vendors.length === 0
                        ? 'No vendor signatures recorded or file was clean.'
                        : 'No antivirus vendor matches search filter.'}
                    </td>
                  </tr>
                ) : (
                  filteredVendors.map(([vendor, signature], idx) => (
                    <tr key={idx}>
                      <td className="font-bold">{vendor}</td>
                      <td>
                        <span className="vendor-detection-sig">{signature}</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="modal-footer">
          <a
            href={permalink}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-primary"
          >
            Open Full VirusTotal Report ↗
          </a>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
