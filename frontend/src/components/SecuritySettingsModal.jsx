import React, { useState, useEffect } from 'react';
import {
  fetchSecuritySettings,
  updateSecuritySettings,
  testVirusTotalKey,
  testSafeBrowsingKey
} from '../utils/apiService';

export default function SecuritySettingsModal({ isOpen, onClose, onSettingsUpdated }) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [settings, setSettings] = useState(null);

  // Form states
  const [vtApiKey, setVtApiKey] = useState('');
  const [vtEnabled, setVtEnabled] = useState(true);
  const [showVtKey, setShowVtKey] = useState(false);
  const [vtMaxBatch, setVtMaxBatch] = useState(5);
  const [vtTestStatus, setVtTestStatus] = useState(null); // { testing: bool, success: bool, message: string }

  const [sbApiKey, setSbApiKey] = useState('');
  const [sbEnabled, setSbEnabled] = useState(true);
  const [showSbKey, setShowSbKey] = useState(false);
  const [sbCheckUrls, setSbCheckUrls] = useState(true);
  const [sbTestStatus, setSbTestStatus] = useState(null);

  const [saveMessage, setSaveMessage] = useState(null);

  useEffect(() => {
    if (isOpen) {
      loadCurrentSettings();
    }
  }, [isOpen]);

  const loadCurrentSettings = async () => {
    setLoading(true);
    setSaveMessage(null);
    setVtTestStatus(null);
    setSbTestStatus(null);
    try {
      const data = await fetchSecuritySettings();
      if (data) {
        setSettings(data);
        setVtEnabled(data.virusTotalEnabled);
        setVtMaxBatch(data.maxVirusTotalLookupsPerBatch || 5);
        setSbEnabled(data.safeBrowsingEnabled);
        setSbCheckUrls(data.checkEmbeddedUrlsWithSafeBrowsing);
        setVtApiKey(''); // keep empty unless user types new key
        setSbApiKey('');
      }
    } catch (e) {
      console.error('Failed to load settings', e);
    } finally {
      setLoading(false);
    }
  };

  const handleTestVirusTotal = async () => {
    setVtTestStatus({ testing: true, message: 'Contacting VirusTotal v3 API...' });
    try {
      const keyToTest = vtApiKey.trim() || null;
      const res = await testVirusTotalKey(keyToTest);
      setVtTestStatus({
        testing: false,
        success: res.success,
        message: res.message
      });
    } catch (e) {
      setVtTestStatus({
        testing: false,
        success: false,
        message: e.message || 'VirusTotal connection test failed.'
      });
    }
  };

  const handleTestSafeBrowsing = async () => {
    setSbTestStatus({ testing: true, message: 'Contacting Google Safe Browsing v4 API...' });
    try {
      const keyToTest = sbApiKey.trim() || null;
      const res = await testSafeBrowsingKey(keyToTest);
      setSbTestStatus({
        testing: false,
        success: res.success,
        message: res.message
      });
    } catch (e) {
      setSbTestStatus({
        testing: false,
        success: false,
        message: e.message || 'Safe Browsing connection test failed.'
      });
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setSaveMessage(null);

    const payload = {
      virusTotalEnabled: vtEnabled,
      maxVirusTotalLookupsPerBatch: parseInt(vtMaxBatch, 10) || 5,
      googleSafeBrowsingEnabled: sbEnabled,
      checkEmbeddedUrlsWithSafeBrowsing: sbCheckUrls
    };

    if (vtApiKey.trim() !== '') {
      payload.virusTotalApiKey = vtApiKey.trim();
    }
    if (sbApiKey.trim() !== '') {
      payload.googleSafeBrowsingApiKey = sbApiKey.trim();
    }

    try {
      const res = await updateSecuritySettings(payload);
      setSaveMessage({ type: 'success', text: 'Settings saved successfully! Active during file scans.' });
      if (res && res.settings) {
        setSettings(res.settings);
        setVtApiKey('');
        setSbApiKey('');
      }
      if (onSettingsUpdated) {
        onSettingsUpdated(res?.settings || payload);
      }
    } catch (err) {
      setSaveMessage({ type: 'error', text: err.message || 'Failed to save settings.' });
    } finally {
      setSaving(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-wrap">
            <span className="modal-icon">🛡️</span>
            <div>
              <h2 className="modal-title">Threat Intelligence &amp; Antivirus APIs</h2>
              <p className="modal-subtitle">
                Configure VirusTotal and Google Safe Browsing for real-time virus detection
              </p>
            </div>
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose} title="Close">
            ✕
          </button>
        </div>

        {loading ? (
          <div className="modal-loading">Loading security configuration...</div>
        ) : (
          <form onSubmit={handleSave}>
            <div className="modal-body">
              {/* Quick Status Bar */}
              <div className="threat-status-cards">
                <div className="threat-card">
                  <div className="threat-card-header">
                    <span className="threat-card-title">VirusTotal v3</span>
                    <span
                      className={`badge ${
                        settings?.virusTotalConfigured && vtEnabled
                          ? 'badge-sev-0'
                          : !settings?.virusTotalConfigured
                          ? 'badge-unconfigured'
                          : 'badge-disabled'
                      }`}
                    >
                      {settings?.virusTotalConfigured && vtEnabled
                        ? '● Online'
                        : !settings?.virusTotalConfigured
                        ? '○ Key Missing'
                        : '○ Disabled'}
                    </span>
                  </div>
                  <div className="threat-card-desc">
                    Checks file SHA-256 against 70+ Antivirus engines (Microsoft Defender, Kaspersky, CrowdStrike, Sophos, etc.).
                  </div>
                </div>

                <div className="threat-card">
                  <div className="threat-card-header">
                    <span className="threat-card-title">Google Safe Browsing</span>
                    <span
                      className={`badge ${
                        settings?.safeBrowsingConfigured && sbEnabled
                          ? 'badge-sev-0'
                          : !settings?.safeBrowsingConfigured
                          ? 'badge-unconfigured'
                          : 'badge-disabled'
                      }`}
                    >
                      {settings?.safeBrowsingConfigured && sbEnabled
                        ? '● Online'
                        : !settings?.safeBrowsingConfigured
                        ? '○ Key Missing'
                        : '○ Disabled'}
                    </span>
                  </div>
                  <div className="threat-card-desc">
                    Scans embedded URLs in scripts &amp; documents against Google's global blacklist of malware &amp; phishing sites.
                  </div>
                </div>
              </div>

              {/* VirusTotal Section */}
              <div className="settings-section">
                <div className="section-head">
                  <div className="section-title-row">
                    <span className="section-badge vt-badge">VirusTotal</span>
                    <label className="switch-label">
                      <input
                        type="checkbox"
                        checked={vtEnabled}
                        onChange={(e) => setVtEnabled(e.target.checked)}
                      />
                      <span>Enable VirusTotal Checks</span>
                    </label>
                  </div>
                </div>

                <div className="form-group">
                  <label htmlFor="vtApiKeyInput">VirusTotal API Key:</label>
                  <div className="input-with-actions">
                    <input
                      id="vtApiKeyInput"
                      type={showVtKey ? 'text' : 'password'}
                      className="form-input"
                      placeholder={
                        settings?.virusTotalConfigured
                          ? `Configured (${settings.maskedVirusTotalApiKey}) — enter to change`
                          : 'Paste your VirusTotal API key (64 hex characters)'
                      }
                      value={vtApiKey}
                      onChange={(e) => setVtApiKey(e.target.value)}
                    />
                    <button
                      type="button"
                      className="btn-icon"
                      onClick={() => setShowVtKey(!showVtKey)}
                      title={showVtKey ? 'Hide key' : 'Show key'}
                    >
                      {showVtKey ? '🙈' : '👁️'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={handleTestVirusTotal}
                      disabled={vtTestStatus?.testing}
                    >
                      {vtTestStatus?.testing ? 'Testing...' : 'Test Key'}
                    </button>
                  </div>

                  {vtTestStatus && (
                    <div
                      className={`test-result-box ${
                        vtTestStatus.success ? 'test-success' : 'test-failure'
                      }`}
                    >
                      {vtTestStatus.success ? '✓ ' : '⚠ '}
                      {vtTestStatus.message}
                    </div>
                  )}

                  <div className="form-hint">
                    Get a free community API key (500 requests/day) at{' '}
                    <a
                      href="https://www.virustotal.com/gui/join-us"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="link"
                    >
                      virustotal.com ↗
                    </a>
                  </div>
                </div>

                <div className="form-group inline-group">
                  <label htmlFor="vtMaxBatchInput">Max VT Lookups per Scan Batch:</label>
                  <input
                    id="vtMaxBatchInput"
                    type="number"
                    min="1"
                    max="50"
                    className="form-input number-input"
                    value={vtMaxBatch}
                    onChange={(e) => setVtMaxBatch(e.target.value)}
                  />
                  <span className="form-hint-inline">
                    (Free tier limit is 4 lookups/min; files with anomalies are prioritized)
                  </span>
                </div>
              </div>

              {/* Google Safe Browsing Section */}
              <div className="settings-section">
                <div className="section-head">
                  <div className="section-title-row">
                    <span className="section-badge gsb-badge">Google Safe Browsing</span>
                    <label className="switch-label">
                      <input
                        type="checkbox"
                        checked={sbEnabled}
                        onChange={(e) => setSbEnabled(e.target.checked)}
                      />
                      <span>Enable Safe Browsing Checks</span>
                    </label>
                  </div>
                </div>

                <div className="form-group">
                  <label htmlFor="sbApiKeyInput">Google Cloud Safe Browsing API Key:</label>
                  <div className="input-with-actions">
                    <input
                      id="sbApiKeyInput"
                      type={showSbKey ? 'text' : 'password'}
                      className="form-input"
                      placeholder={
                        settings?.safeBrowsingConfigured
                          ? `Configured (${settings.maskedSafeBrowsingApiKey}) — enter to change`
                          : 'Paste Google Cloud API key (AIzaSy...)'
                      }
                      value={sbApiKey}
                      onChange={(e) => setSbApiKey(e.target.value)}
                    />
                    <button
                      type="button"
                      className="btn-icon"
                      onClick={() => setShowSbKey(!showSbKey)}
                      title={showSbKey ? 'Hide key' : 'Show key'}
                    >
                      {showSbKey ? '🙈' : '👁️'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={handleTestSafeBrowsing}
                      disabled={sbTestStatus?.testing}
                    >
                      {sbTestStatus?.testing ? 'Testing...' : 'Test Key'}
                    </button>
                  </div>

                  {sbTestStatus && (
                    <div
                      className={`test-result-box ${
                        sbTestStatus.success ? 'test-success' : 'test-failure'
                      }`}
                    >
                      {sbTestStatus.success ? '✓ ' : '⚠ '}
                      {sbTestStatus.message}
                    </div>
                  )}

                  <div className="form-hint">
                    Get an API key with 10,000 requests/day free at{' '}
                    <a
                      href="https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="link"
                    >
                      Google Cloud Console ↗
                    </a>
                  </div>
                </div>

                <div className="form-group">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={sbCheckUrls}
                      onChange={(e) => setSbCheckUrls(e.target.checked)}
                    />
                    <span>
                      Inspect scripts, documents and configs for embedded C2, malware, or phishing URLs
                    </span>
                  </label>
                </div>
              </div>

              {saveMessage && (
                <div
                  className={`save-message ${
                    saveMessage.type === 'success' ? 'msg-success' : 'msg-error'
                  }`}
                >
                  {saveMessage.text}
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Close
              </button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? 'Saving...' : 'Save Settings'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
