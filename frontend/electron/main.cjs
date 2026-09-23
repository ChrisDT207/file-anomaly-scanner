const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let backendProcess;

function startBackend() {
  const backendDll = path.join(__dirname, '../../backend/bin/Debug/net8.0-windows/FileAnomalyScanner.dll');
  const backendExe = path.join(__dirname, '../../backend/bin/Debug/net8.0-windows/FileAnomalyScanner.exe');

  try {
    backendProcess = spawn(backendExe, [], {
      detached: false,
      stdio: 'ignore'
    });

    backendProcess.on('error', (err) => {
      console.warn('Could not launch backend executable directly, falling back to dotnet:', err);
    });
  } catch (e) {
    console.error('Failed to spawn backend process:', e);
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 720,
    minWidth: 850,
    minHeight: 550,
    center: true,
    title: 'File Anomaly Scanner - Desktop',
    backgroundColor: '#F7F7F7',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  mainWindow.loadURL('http://127.0.0.1:5000');

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (backendProcess) {
    backendProcess.kill();
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
