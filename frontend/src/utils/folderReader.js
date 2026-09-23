/**
 * Utility for recursively traversing folder structures using the standard
 * HTML5 File and Directory Entries API (webkitGetAsEntry / FileSystemDirectoryReader).
 */

/**
 * Reads all entries from a FileSystemDirectoryReader in batches.
 * Chrome / Chromium limits readEntries() to ~100 items per call,
 * so we must recurse/loop until an empty array is returned.
 *
 * @param {FileSystemDirectoryReader} reader
 * @returns {Promise<FileSystemEntry[]>}
 */
async function readAllEntriesFromReader(reader) {
  const entries = [];

  while (true) {
    const batch = await new Promise((resolve, reject) => {
      reader.readEntries(resolve, reject);
    });

    if (!batch || batch.length === 0) {
      break;
    }

    entries.push(...batch);
  }

  return entries;
}

/**
 * Recursively traverses a FileSystemEntry (file or directory).
 *
 * @param {FileSystemEntry} entry
 * @param {string} parentPath
 * @param {Function} onProgress
 * @returns {Promise<Array<{ file: File, relativePath: string }>>}
 */
async function traverseEntry(entry, parentPath = '', onProgress = null) {
  const currentPath = parentPath ? `${parentPath}/${entry.name}` : entry.name;

  if (entry.isFile) {
    return new Promise((resolve, reject) => {
      entry.file(
        (file) => {
          if (onProgress) {
            onProgress(currentPath);
          }
          resolve([{ file, relativePath: currentPath }]);
        },
        (error) => {
          console.warn(`Could not read file entry: ${currentPath}`, error);
          resolve([]);
        }
      );
    });
  }

  if (entry.isDirectory) {
    try {
      const reader = entry.createReader();
      const childEntries = await readAllEntriesFromReader(reader);

      const results = [];
      for (const child of childEntries) {
        const childFiles = await traverseEntry(child, currentPath, onProgress);
        results.push(...childFiles);
      }
      return results;
    } catch (err) {
      console.warn(`Error reading directory: ${currentPath}`, err);
      return [];
    }
  }

  return [];
}

/**
 * Ingests items from a DragEvent's dataTransfer.items, extracting all files recursively.
 *
 * @param {DataTransferItemList} dataTransferItems
 * @param {Function} onProgress Optional progress callback (path: string) => void
 * @returns {Promise<{ folderName: string, files: Array<{ file: File, relativePath: string }> }>}
 */
export async function readDroppedEntries(dataTransferItems, onProgress = null) {
  const fileRecords = [];
  let rootFolderName = '';

  const entriesToProcess = [];

  for (let i = 0; i < dataTransferItems.length; i++) {
    const item = dataTransferItems[i];
    if (item.kind !== 'file') continue;

    const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : (item.getAsEntry ? item.getAsEntry() : null);
    if (entry) {
      entriesToProcess.push(entry);
      if (!rootFolderName && entry.isDirectory) {
        rootFolderName = entry.name;
      }
    } else {
      // Fallback if getAsEntry is unsupported
      const file = item.getAsFile();
      if (file) {
        fileRecords.push({ file, relativePath: file.name });
      }
    }
  }

  for (const entry of entriesToProcess) {
    const files = await traverseEntry(entry, '', onProgress);
    fileRecords.push(...files);
  }

  if (!rootFolderName && fileRecords.length > 0) {
    rootFolderName = fileRecords[0].relativePath.split('/')[0] || 'Selected Files';
  }

  return {
    folderName: rootFolderName || 'Dropped Folder',
    files: fileRecords
  };
}

/**
 * Formats files selected via <input type="file" webkitdirectory directory />
 *
 * @param {FileList} fileList
 * @returns {{ folderName: string, files: Array<{ file: File, relativePath: string }> }}
 */
export function readInputDirectoryFiles(fileList) {
  if (!fileList || fileList.length === 0) {
    return { folderName: '', files: [] };
  }

  const files = [];
  let folderName = '';

  for (let i = 0; i < fileList.length; i++) {
    const file = fileList[i];
    const relativePath = file.webkitRelativePath || file.name;
    files.push({ file, relativePath });

    if (!folderName && file.webkitRelativePath) {
      const parts = file.webkitRelativePath.split('/');
      folderName = parts[0];
    }
  }

  return {
    folderName: folderName || 'Selected Folder',
    files
  };
}
