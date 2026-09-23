import React, { useState, useEffect, useCallback } from 'react';
import './App.css';
import FolderUploadSection from './components/FolderUploadSection';
import DropZoneOverlay from './components/DropZoneOverlay';
import ConsoleDashboard from './components/ConsoleDashboard';
import AnomalyTable from './components/AnomalyTable';
import { checkBackendHealth, uploadAndScanFiles } from './utils/apiService';

export default function App() {
  const [folderPath, setFolderPath] = useState('');
  const [fileItems, setFileItems] = useState([]);
  const [logs, setLogs] = useState([
    `[${new Date().toLocaleTimeString()}] [SYSTEM] File Anomaly Scanner console initialized.`,
    `[${new Date().toLocaleTimeString()}] [READY] Recursive Directory Entries API and webkitdirectory ready.`
  ]);
  const [report, setReport] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [backendOnline, setBackendOnline] = useState(null);

  const addLog = useCallback((message) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `[${timestamp}] ${message}`]);
  }, []);

  useEffect(() => {
    async function verifyBackend() {
      const isUp = await checkBackendHealth();
      setBackendOnline(isUp);
      if (isUp) {
        addLog('[BACKEND] Connected to ASP.NET Core Web API on http://localhost:5000.');
      } else {
        addLog('[BACKEND] [WARN] Cannot reach backend API. Ensure FileAnomalyScanner is running on port 5000.');
      }
    }
    verifyBackend();
  }, [addLog]);

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
    addLog(`[SCAN] [START] Initiating anomaly scan for ${fileItems.length} file(s)...`);

    try {
      const scanReport = await uploadAndScanFiles(fileItems, (progress) => {
        addLog(`[PROGRESS] ${progress.status}`);
      });

      setReport(scanReport);

      if (scanReport.consoleLogs && scanReport.consoleLogs.length > 0) {
        setLogs((prev) => [...prev, ...scanReport.consoleLogs]);
      }

      addLog(`[SCAN] [COMPLETE] Processed ${scanReport.summary.totalFilesScanned} files. Found ${scanReport.summary.totalAnomaliesFound} anomalies.`);
    } catch (err) {
      addLog(`[SCAN] [ERROR] Scan failed: ${err.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadDemoFolder = () => {
    const cleanText = new File(["This is a legitimate plain text configuration file with normal entropy."], "config.txt", { type: "text/plain" });

    const randomBytes = new Uint8Array(2048);
    window.crypto.getRandomValues(randomBytes);
    const highEntropyText = new File([randomBytes], "audit_notes.txt", { type: "text/plain" });

    const mzPngBytes = new Uint8Array([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
    const disguisedPng = new File([mzPngBytes], "logo_banner.png", { type: "image/png" });

    const doubleExt = new File(["MZ... payload"], "Q3_Financial_Report.pdf.exe", { type: "application/octet-stream" });

    const scriptCradle = new File([
      "powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA="
    ], "deploy_updater.ps1", { type: "text/plain" });

    const demoItems = [
      { file: cleanText, relativePath: "DemoFolder/documents/config.txt" },
      { file: highEntropyText, relativePath: "DemoFolder/documents/audit_notes.txt" },
      { file: disguisedPng, relativePath: "DemoFolder/assets/logo_banner.png" },
      { file: doubleExt, relativePath: "DemoFolder/downloads/Q3_Financial_Report.pdf.exe" },
      { file: scriptCradle, relativePath: "DemoFolder/scripts/deploy_updater.ps1" }
    ];

    setFolderPath("DemoFolder");
    setFileItems(demoItems);
    addLog("[DEMO] Injected 5 synthetic test files into queue (masqueraded PNG, high entropy TXT, double extension, powershell cradle, clean TXT).");
  };

  return (
    <div className="app-container">
      {/* App Header */}
      <header className="app-header">
        <div className="app-title-area">
          <h1>File Anomaly Scanner</h1>
          <div className="app-subtitle">
            Heuristic &amp; Structural File Inspection Dashboard (ASP.NET Core Web API + React)
          </div>
        </div>
        <div className="header-actions">
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
            className="btn btn-sm"
            onClick={handleLoadDemoFolder}
            style={{ marginLeft: '10px' }}
            disabled={isScanning}
          >
            Load Synthetic Test Folder
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

      {/* Anomaly Results Table */}
      <AnomalyTable
        anomalies={report ? report.anomalies : []}
        summary={report ? report.summary : null}
      />
    </div>
  );
}
