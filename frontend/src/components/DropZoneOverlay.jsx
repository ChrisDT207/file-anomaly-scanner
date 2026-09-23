import React, { useState, useEffect } from 'react';
import { readDroppedEntries } from '../utils/folderReader';

export default function DropZoneOverlay({
  onFilesDiscovered,
  isScanning,
  addLog
}) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [traversalProgress, setTraversalProgress] = useState(null);

  useEffect(() => {
    let dragCounter = 0;

    const handleWindowDragEnter = (e) => {
      e.preventDefault();
      dragCounter++;
      if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')) {
        setIsDragOver(true);
      }
    };

    const handleWindowDragLeave = (e) => {
      e.preventDefault();
      dragCounter--;
      if (dragCounter <= 0) {
        setIsDragOver(false);
        dragCounter = 0;
      }
    };

    const handleWindowDragOver = (e) => {
      e.preventDefault();
    };

    const handleWindowDrop = async (e) => {
      e.preventDefault();
      dragCounter = 0;
      setIsDragOver(false);

      if (isScanning) return;
      if (!e.dataTransfer || !e.dataTransfer.items) return;

      addLog('[DROP] Folder/items dropped. Initiating recursive directory traversal...');
      setTraversalProgress('Scanning directory entries...');

      try {
        const { folderName, files } = await readDroppedEntries(
          e.dataTransfer.items,
          (discoveredPath) => {
            setTraversalProgress(`Discovered: ${discoveredPath}`);
          }
        );

        setTraversalProgress(null);

        if (files.length === 0) {
          addLog('[DROP] [WARN] No readable files found in dropped item.');
          return;
        }

        const totalBytes = files.reduce((acc, curr) => acc + curr.file.size, 0);
        const sizeStr = (totalBytes / (1024 * 1024)).toFixed(2);

        addLog(`[DROP] Successfully indexed folder '${folderName}': ${files.length} file(s) (${sizeStr} MB).`);
        onFilesDiscovered(folderName, files);
      } catch (err) {
        setTraversalProgress(null);
        addLog(`[DROP] [ERROR] Failed to traverse dropped directory: ${err.message}`);
      }
    };

    window.addEventListener('dragenter', handleWindowDragEnter);
    window.addEventListener('dragleave', handleWindowDragLeave);
    window.addEventListener('dragover', handleWindowDragOver);
    window.addEventListener('drop', handleWindowDrop);

    return () => {
      window.removeEventListener('dragenter', handleWindowDragEnter);
      window.removeEventListener('dragleave', handleWindowDragLeave);
      window.removeEventListener('dragover', handleWindowDragOver);
      window.removeEventListener('drop', handleWindowDrop);
    };
  }, [isScanning, onFilesDiscovered, addLog]);

  return (
    <div className={`dropzone-container ${isDragOver ? 'drag-over' : ''}`}>
      <div className="dropzone-inner">
        <div className="dropzone-icon">[ FOLDER DROP ZONE ]</div>
        <div className="dropzone-text">
          Drag &amp; Drop a folder anywhere into this window to scan
        </div>
        <div className="dropzone-hint">
          Standard HTML5 File and Directory Entries API will recursively read all nested contents
        </div>
        {traversalProgress && (
          <div className="dropzone-progress">
            <span>{traversalProgress}</span>
          </div>
        )}
      </div>
    </div>
  );
}
