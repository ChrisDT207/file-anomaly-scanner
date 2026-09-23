import React, { useRef } from 'react';
import { readInputDirectoryFiles } from '../utils/folderReader';

export default function FolderUploadSection({
  folderPath,
  setFolderPath,
  fileItems,
  setFileItems,
  onStartScan,
  onClear,
  isScanning,
  addLog
}) {
  const fileInputRef = useRef(null);

  const handleBrowseClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
      fileInputRef.current.click();
    }
  };

  const handleFolderSelected = (e) => {
    const selectedFiles = e.target.files;
    if (!selectedFiles || selectedFiles.length === 0) return;

    const { folderName, files } = readInputDirectoryFiles(selectedFiles);
    setFolderPath(folderName || 'Selected Folder');
    setFileItems(files);

    const totalBytes = files.reduce((acc, curr) => acc + curr.file.size, 0);
    const sizeStr = (totalBytes / (1024 * 1024)).toFixed(2);

    addLog(`[BROWSE] Selected directory '${folderName}' with ${files.length} file(s) (${sizeStr} MB).`);
  };

  const totalBytes = fileItems.reduce((acc, curr) => acc + curr.file.size, 0);
  const sizeMb = (totalBytes / (1024 * 1024)).toFixed(2);

  return (
    <div className="section-card upload-section">
      <div className="section-title">Directory Selection & Scan Controls</div>

      {/* Hidden directory selection input */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFolderSelected}
        style={{ display: 'none' }}
        webkitdirectory=""
        directory=""
        multiple
      />

      <div className="input-group">
        <label htmlFor="folderPathInput" className="input-label">
          Folder to scan:
        </label>
        <div className="input-row">
          <input
            id="folderPathInput"
            type="text"
            className="text-input"
            placeholder="No directory selected. Click 'Browse...' or drop a folder below."
            value={folderPath}
            onChange={(e) => setFolderPath(e.target.value)}
            disabled={isScanning}
          />
          <button
            type="button"
            className="btn btn-browse"
            onClick={handleBrowseClick}
            disabled={isScanning}
          >
            Browse...
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={onStartScan}
            disabled={isScanning || fileItems.length === 0}
          >
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClear}
            disabled={isScanning || (fileItems.length === 0 && !folderPath)}
          >
            Clear
          </button>
        </div>
      </div>

      <div className="upload-metadata-bar">
        <span>Files Queued: <strong>{fileItems.length}</strong></span>
        <span>Total Size: <strong>{sizeMb} MB</strong></span>
        <span>Directory API Status: <strong>Ready (webkitdirectory + Entries API enabled)</strong></span>
      </div>
    </div>
  );
}
