import React, { useState } from 'react';
import { forceInstallSandbox } from '../utils/apiService';

export default function SandboxAlertModal({ alert, onClose }) {
  if (!alert) return null;

  const isSuccess = alert.type === 'success';

  // Installation state for Windows Home / Unconfigured OS
  const [installStatus, setInstallStatus] = useState('idle'); // 'idle' | 'installing' | 'success' | 'error'
  const [installError, setInstallError] = useState(null);
  const [installResult, setInstallResult] = useState(null);

  const handleForceInstall = async () => {
    setInstallStatus('installing');
    setInstallError(null);

    try {
      const result = await forceInstallSandbox();
      setInstallResult(result);
      setInstallStatus('success');
    } catch (err) {
      setInstallStatus('error');
      setInstallError(err.message || 'Failed to install Windows Sandbox packages.');
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-container sandbox-alert-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-wrap">
            <span className="modal-icon">
              {isSuccess ? '📦' : installStatus === 'success' ? '🔄' : '⚠️'}
            </span>
            <h3>
              {isSuccess
                ? alert.title || 'Windows Sandbox Launched'
                : installStatus === 'success'
                ? 'System Restart Required'
                : alert.title || 'Sandbox Unavailable'}
            </h3>
          </div>
          <button type="button" className="btn-close" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          {isSuccess ? (
            /* Detonation Success State */
            <>
              <div className="alert-box alert-success">
                <span className="alert-symbol">✓</span>
                <div className="alert-text">{alert.message}</div>
              </div>

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
            </>
          ) : installStatus === 'success' ? (
            /* Post-Install Reboot Required State */
            <div className="sandbox-reboot-panel">
              <div className="reboot-header">
                <span className="reboot-badge-icon">🔄</span>
                <div className="reboot-title-wrap">
                  <h4>Restart Your Computer to Finalize</h4>
                  <span className="reboot-subtitle">Windows Sandbox packages staged successfully via DISM</span>
                </div>
              </div>

              <p className="reboot-desc">
                {installResult?.message ||
                  'Windows Sandbox packages have been extracted and added to your servicing component store. A system restart is required to finalize enabling the Containers-DisposableClientVM feature.'}
              </p>

              <div className="reboot-instruction-box">
                <div className="instruction-heading">Next Steps:</div>
                <ol className="reboot-steps">
                  <li><strong>Restart your PC</strong> so Windows can complete configuring the container virtualization subsystem.</li>
                  <li>After Windows reboots, launch <strong>File Anomaly Scanner</strong> again.</li>
                  <li>Click <strong>Detonate in Sandbox</strong> on any High, Critical, or Zero-Day threat to inspect it in the isolated VM!</li>
                </ol>
              </div>
            </div>
          ) : installStatus === 'installing' ? (
            /* In-Progress Installation State */
            <div className="sandbox-installing-panel">
              <div className="installing-spinner-wrap">
                <div className="spinner-ring"></div>
              </div>
              <div className="installing-text-wrap">
                <h4>Installing Windows Sandbox Packages...</h4>
                <p>Executing elevated DISM script to stage hidden <code>Containers-DisposableClientVM</code> packages.</p>
                <div className="install-uac-warning installing-pulse">
                  <span className="warning-icon">🛡️</span>
                  <span>
                    Please accept the <strong>Windows User Account Control (UAC)</strong> prompt if it appears on your desktop. This operation typically takes <strong>1–2 minutes</strong>.
                  </span>
                </div>
              </div>
            </div>
          ) : (
            /* Fallback State (Sandbox Missing / Windows Home) */
            <>
              <div className="alert-box alert-error">
                <span className="alert-symbol">✕</span>
                <div className="alert-text">{alert.message}</div>
              </div>

              {installStatus === 'error' && (
                <div className="alert-box alert-error install-err-box">
                  <span className="alert-symbol">⚠️</span>
                  <div className="alert-text">
                    <strong>Installation Failed:</strong> {installError}
                  </div>
                </div>
              )}

              {/* Prominent Force Install Action Box */}
              <div className="sandbox-home-installer-box">
                <div className="installer-header">
                  <span className="installer-badge">Windows Home / Unconfigured OS</span>
                  <h4>Automated Windows Sandbox Enabler</h4>
                </div>
                <p className="installer-desc">
                  Windows Home editions hide the Sandbox packages by default. We can automatically unhide and stage the official container packages into your Windows Servicing repository using DISM.
                </p>

                <div className="installer-action-row">
                  <button
                    type="button"
                    className="btn btn-force-install"
                    onClick={handleForceInstall}
                  >
                    ⚡ Force Install Sandbox (Windows Home)
                  </button>
                </div>

                <div className="install-uac-warning">
                  <span className="warning-icon">⚠️</span>
                  <span>
                    <strong>Administrator Elevation Notice:</strong> Clicking this button will launch an elevated batch script with Administrator privileges. You will see a Windows User Account Control (UAC) prompt. The installation takes approximately <strong>1–2 minutes</strong>.
                  </span>
                </div>
              </div>

              {/* Collapsible Manual Instructions & BIOS VT-x Guide */}
              <details className="sandbox-manual-details">
                <summary className="manual-summary">🛠️ Manual Configuration &amp; BIOS Virtualization Guide</summary>
                <div className="sandbox-troubleshoot-panel">
                  <div className="troubleshoot-title">⚙️ Requirements &amp; Settings:</div>
                  <ol className="troubleshoot-steps">
                    <li>
                      <strong>Hardware Virtualization (VT-x / AMD-V):</strong> Must be enabled in your computer's UEFI/BIOS settings (check Task Manager &gt; Performance &gt; CPU &gt; Virtualization: Enabled).
                    </li>
                    <li>
                      <strong>Windows Pro/Enterprise Users:</strong> Press <kbd>Win + R</kbd>, type <code>optionalfeatures.exe</code>, press <strong>Enter</strong>, check <strong>Windows Sandbox</strong>, and click <strong>OK</strong>.
                    </li>
                    <li>
                      <strong>Windows Home Users:</strong> Use the <strong>Force Install Sandbox</strong> button above to install the hidden packages.
                    </li>
                  </ol>
                </div>
              </details>
            </>
          )}
        </div>

        <div className="modal-footer">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
            disabled={installStatus === 'installing'}
          >
            {isSuccess ? 'Acknowledge' : installStatus === 'success' ? 'Understood (Close)' : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
}
