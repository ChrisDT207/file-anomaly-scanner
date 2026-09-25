import React, { useState } from 'react';
import { submitFileToVirusTotal } from '../utils/apiService';

export default function UploadConsentModal({ targetItem, fileObject, onClose, onSubmitted }) {
  const [consentGiven, setConsentGiven] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successInfo, setSuccessInfo] = useState(null);

  if (!targetItem) return null;

  const fileName = targetItem.fileName || targetItem.filePath || 'Selected File';
  const sha256 = targetItem.sha256 || targetItem.sha256Hash || 'N/A';
  const riskScore = targetItem.localRiskScore !== undefined ? targetItem.localRiskScore : 75;

  const handleSubmit = async () => {
    if (!consentGiven) return;
    if (!fileObject) {
      setErrorMsg('Raw file data is not available in memory for upload.');
      return;
    }

    setIsSubmitting(true);
    setErrorMsg(null);

    try {
      const res = await submitFileToVirusTotal(fileObject);
      setSuccessInfo(res);
      if (onSubmitted) {
        onSubmitted(res);
      }
    } catch (err) {
      setErrorMsg(err.message || 'Submission failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-container consent-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-wrap">
            <span className="modal-icon">☁️</span>
            <h3>Submit Novel Binary to VirusTotal</h3>
          </div>
          <button type="button" className="btn-close" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className="zero-day-notice-card">
            <div className="notice-badge">⚠️ ZERO-DAY DETECTION WORKFLOW</div>
            <h4>{fileName}</h4>
            <p className="notice-sub">
              This file was <strong>not found</strong> in VirusTotal's hash registry, but our local heuristic engine flagged it with a <strong>{riskScore}/100 Local Threat Score</strong>.
            </p>
            <div className="meta-grid">
              <div><span className="meta-lbl">SHA-256:</span> <code className="meta-val font-mono">{sha256.slice(0, 16)}...</code></div>
              <div><span className="meta-lbl">Local Risk:</span> <strong className="val-critical">{riskScore}/100</strong></div>
            </div>
          </div>

          <div className="privacy-warning-box">
            <div className="privacy-title">🔒 Privacy &amp; Data Confidentiality Notice</div>
            <p>
              Submitting a physical file to VirusTotal distributes its full binary contents to <strong>over 70 antivirus vendors and threat intelligence partners globally</strong>.
            </p>
            <ul>
              <li><strong>DO NOT</strong> upload internal company documents, accounting files, or databases.</li>
              <li><strong>DO NOT</strong> upload binaries containing hardcoded API keys, passwords, or PII.</li>
              <li>Only submit suspected external malware droppers, novel scripts, or unclassified installers.</li>
            </ul>
          </div>

          {errorMsg && (
            <div className="alert-box alert-error">
              <span>⚠️</span> {errorMsg}
            </div>
          )}

          {successInfo ? (
            <div className="alert-box alert-success">
              <span>✓</span> {successInfo.message}
              <div className="analysis-id font-mono">
                Analysis ID: {successInfo.analysisId || 'Queued'}
              </div>
            </div>
          ) : (
            <div className="consent-checkbox-wrap">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={consentGiven}
                  onChange={(e) => setConsentGiven(e.target.checked)}
                  disabled={isSubmitting}
                />
                <span>
                  I confirm this file contains <strong>no personal data, confidential IP, or private credentials</strong>, and I consent to cloud multi-AV analysis.
                </span>
              </label>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {successInfo ? 'Close' : 'Cancel'}
          </button>
          {!successInfo && (
            <button
              type="button"
              className="btn btn-warning"
              disabled={!consentGiven || isSubmitting || !fileObject}
              onClick={handleSubmit}
            >
              {isSubmitting ? 'Uploading to VirusTotal...' : 'Confirm & Upload to VirusTotal'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
