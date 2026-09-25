import React from 'react';

export default function SandboxAlertModal({ alert, onClose }) {
  if (!alert) return null;

  const isSuccess = alert.type === 'success';

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-container sandbox-alert-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-wrap">
            <span className="modal-icon">{isSuccess ? '📦' : '⚠️'}</span>
            <h3>{alert.title || (isSuccess ? 'Windows Sandbox Launched' : 'Sandbox Unavailable')}</h3>
          </div>
          <button type="button" className="btn-close" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className={`alert-box ${isSuccess ? 'alert-success' : 'alert-error'}`}>
            <span className="alert-symbol">{isSuccess ? '✓' : '✕'}</span>
            <div className="alert-text">{alert.message}</div>
          </div>

          {isSuccess ? (
            <div className="sandbox-info-panel">
              <div className="info-title">🛡️ Isolation &amp; Security Measures Applied</div>
              <ul className="info-list">
                <li><strong>Read-Only Filesystem:</strong> Mapped folder is strictly mounted Read-Only (<code>&lt;ReadOnly&gt;true&lt;/ReadOnly&gt;</code>) to prevent filesystem tampering or ransomware encryption on the host.</li>
                <li><strong>Air-Gapped Networking:</strong> Virtual network adapter disabled (<code>&lt;Networking&gt;Disable&lt;/Networking&gt;</code>) to block command-and-control (C2) or data exfiltration.</li>
                <li><strong>Disposable Container:</strong> All runtime processes, registry changes, and files will be permanently erased upon closing the Sandbox window.</li>
              </ul>
              {alert.wsbConfig && (
                <div className="wsb-path-box">
                  <span className="path-label">Config File:</span>
                  <code className="font-mono">{alert.wsbConfig}</code>
                </div>
              )}
            </div>
          ) : (
            <div className="sandbox-troubleshoot-panel">
              <div className="troubleshoot-title">⚙️ How to Enable Windows Sandbox</div>
              <p>Windows Sandbox provides an isolated, disposable desktop environment built directly into Windows. To enable it:</p>
              <ol className="troubleshoot-steps">
                <li>Ensure you are running <strong>Windows 10/11 Pro, Enterprise, or Education</strong> (Windows Home does not support this feature).</li>
                <li>Ensure <strong>Hardware Virtualization (VT-x / AMD-V)</strong> is enabled in your BIOS/UEFI settings.</li>
                <li>Press <kbd>Win + R</kbd>, type <code>optionalfeatures.exe</code>, and press <strong>Enter</strong>.</li>
                <li>Scroll down, check <strong>Windows Sandbox</strong>, click <strong>OK</strong>, and reboot your computer.</li>
              </ol>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {isSuccess ? 'Acknowledge' : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
}
