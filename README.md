# File Anomaly & Virus Threat Scanner

A security analysis desktop & web dashboard that combines **deep heuristic structural file inspection** with **live multi-engine antivirus threat intelligence (VirusTotal API)** and **malicious link detection (Google Safe Browsing API)**. Built with .NET 8 (ASP.NET Core Web API + WPF WebView2) and React.

---

## Major New Features

### 1. VirusTotal v3 Antivirus Engine Integration
The scanner now checks files against **70+ industry-leading antivirus engines** (including Microsoft Defender, Kaspersky, CrowdStrike, Sophos, Bitdefender, Symantec, ESET, and Fortinet) to catch known malware, trojans, ransomware, and exploits:
- **Instant SHA-256 Calculation**: Automatically generates cryptographic SHA-256 hashes for all dropped or selected files.
- **Multi-Engine AV Lookup**: Queries the VirusTotal v3 REST API to retrieve real-time detection ratios (e.g. `58/72 AV Engines Malicious`).
- **Vendor Detections Modal**: Clicking any VirusTotal detection badge opens an interactive breakdown displaying the exact malware signature identified by each antivirus vendor.
- **Smart Rate-Limit Guard & Caching**: Designed for VirusTotal's free community tier (4 queries/min, 500/day). Uses in-memory caching and prioritizes anomalous files so scans never hang.
- **Zero-Key Fallback**: Even without an API key, SHA-256 hashes are computed for every file with a 1-click **"Lookup on VirusTotal ↗"** link to view or submit files on the web.

### 2. Google Safe Browsing v4 Threat Intelligence
Many weaponized files (such as PowerShell droppers, batch files, macros, PDFs, or HTML attachments) do not contain the final binary payload locally; instead, they embed external links to download stages or connect to Command-and-Control (C2) servers:
- **Embedded URL Extractor**: Automatically parses text files, scripts (`.ps1`, `.bat`, `.vbs`, `.js`, `.py`, `.sh`), HTML, documents, and configs for embedded web URLs and endpoints.
- **Real-Time Blacklist Verification**: Queries Google's Safe Browsing v4 API (`threatMatches:find`) across four threat categories:
  - `MALWARE` (malware distribution endpoints)
  - `SOCIAL_ENGINEERING` (phishing & credential harvesting pages)
  - `UNWANTED_SOFTWARE` (adware, spyware, and bundleware)
  - `POTENTIALLY_HARMFUL_APPLICATION`
- **Critical Alerting**: Flags any file containing blacklisted links with Critical severity, isolating the suspicious URL and threat type.

---

## Heuristic & Structural Anomaly Engine
In addition to antivirus APIs, the scanner maintains its core heuristic inspection engine:
- **Header vs. Extension Validation**: Detects file extension spoofing (e.g., Windows PE executables disguised as `.png`, `.jpg`, `.pdf`, `.docx`).
- **Deceptive Naming Detection**: Flags RTLO Unicode override characters (`U+202E`) and double extensions (e.g. `Report.pdf.exe`).
- **Shannon Entropy Analysis**: Detects packed, obfuscated, or encrypted payloads with abnormal entropy ratings.
- **Polyglot & Embedded PE Headers**: Identifies DOS execution stubs and secondary `MZ` headers inside non-executable containers.
- **Malicious Script Signatures**: Detects base64-encoded PowerShell cradles, `DownloadString` / `Invoke-Expression` execution chains, and PHP webshell primitives (`eval(base64_decode)`, `passthru`, `system`).
- **Container & Archive Inspection**: Unpacks and inspects nested `.zip`, `.tar`, and `.gz` archives for directory traversal and zip-bomb hazards.

---

## Threat Intelligence & API Configuration

Click the **⚙️ API Settings** button in the header bar to configure your API keys:

1. **VirusTotal API Key**:
   - Get a free key at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) (Free tier includes 500 lookups/day).
   - Enter your key in the settings modal and click **Test Key** to test with the standard EICAR test signature.
   - Configure the maximum number of automatic VT lookups per scan batch.
2. **Google Safe Browsing API Key**:
   - Get a free key at [Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) (Free tier includes 10,000 lookups/day).
   - Enter your key and click **Test Key** to verify against Google's official malware test domain.
   - Toggle embedded URL extraction on/off.

> **Privacy & Security Note**: All API keys and settings are stored locally on your machine in `security-settings.json` (which is excluded from Git via `.gitignore`). Keys are never shared, logged, or sent anywhere other than official Google and VirusTotal API endpoints.

---

## How to Run

### Option 1: 1-Click Desktop App (Easiest)
Simply double-click:
```
FileAnomalyScanner.exe
```
located directly in the root folder. It immediately launches the native desktop window without requiring terminal commands.

### Option 2: Run via Terminal
1. Open a terminal in the `backend` folder and run:
   ```bash
   dotnet run
   ```
2. Navigate to `http://localhost:5000` in your web browser.

### Option 3: Live Frontend Development (HMR)
1. In `backend`: `dotnet run`
2. In `frontend`: `npm run dev`
3. Open `http://localhost:5173` in your browser.

---

## Built-in Synthetic Test Suite

Click **Load Synthetic Test Folder** in the top bar to test the complete detection pipeline with 7 pre-configured test items:
1. `eicar_antivirus_test.com.txt`: The official EICAR antivirus test file (harmless string recognized across 65+ AV engines on VirusTotal).
2. `updater_c2_test.ps1`: Script containing Google's official Safe Browsing malware test URL.
3. `logo_banner.png`: Masqueraded Windows PE executable disguised with a `.png` image extension.
4. `Q3_Financial_Report.pdf.exe`: Deceptive double-extension executable file.
5. `deploy_updater.ps1`: Base64-encoded stealth PowerShell execution cradle.
6. `audit_notes.txt`: High-entropy packed pseudo-random content.
7. `config.txt`: Legitimate baseline text file with normal entropy.