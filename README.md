# File Anomaly & Virus Threat Scanner

A security analysis desktop application and web dashboard that combines **deep heuristic structural file inspection** with **live multi-engine antivirus threat intelligence (VirusTotal API)**, **malicious link detection (Google Safe Browsing API)**, and **cloud sandbox behavioral telemetry**.

Built with .NET 8 (ASP.NET Core Web API + WPF WebView2) and React.

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                            Desktop Application (WPF)                             |
|  +-----------------------------------------------------------------------------+  |
|  |                   WebView2 Modern Light Frontend (React + Vite)             |  |
|  |  - Anomaly Table & Filters       - Vendor Detections Breakdown Modal        |  |
|  |  - Cloud Sandbox Forensics Modal - Privacy-Preserving Upload Consent Modal  |  |
|  |  - Security Settings Modal       - Live Streaming Security Console Logs     |  |
|  +---------------------------------------+-------------------------------------+  |
|                                          | HTTP / JSON (Port 5000 Loopback)       |
|  +---------------------------------------v-------------------------------------+  |
|  |                 Embedded ASP.NET Core Web API Engine (.NET 8)               |  |
|  |  - DesktopHost (Loopback Daemon)       - UploadController (Batch Streaming) |  |
|  |  - CloudSandboxController              - SettingsController (Config & Keys) |  |
|  +---------------------------------------+-------------------------------------+  |
+------------------------------------------|----------------------------------------+
                                           |
    +--------------------------------------+--------------------------------------+
    |                                      |                                      |
    v                                      v                                      v
+-------------------------+  +--------------------------+  +--------------------------+
|  Local Heuristics & AST |  | VirusTotal v3 Threat API |  |  Google Safe Browsing v4 |
| - Streaming Inspector   |  | - 70+ Antivirus Engines  |  | - Embedded URL Extractor |
| - Shannon Entropy Engine|  | - Behavioral Telemetry   |  | - Threat Category Lookup |
| - PowerShell AST Parser |  | - Cloud Sandbox Traces   |  | - Malware/Phishing C2    |
| - Archive Safety Engine |  | - MITRE ATT&CK Mapping   |  | - Real-time Blacklisting |
| - File Remediation Svc  |  | - Cryptographic Shredder |  +--------------------------+
+-------------------------+  +--------------------------+
```

---

## Core Capabilities & Features

### 1. VirusTotal v3 Antivirus Engine Integration
The scanner checks files against **70+ industry-leading antivirus engines** (including Microsoft Defender, Kaspersky, CrowdStrike, Sophos, Bitdefender, Symantec, ESET, and Fortinet) to identify known malware, trojans, ransomware, and exploits:
- **Instant SHA-256 Calculation**: Automatically generates cryptographic SHA-256 hashes for all selected or dropped files during a single stream traversal.
- **Multi-Engine AV Lookup**: Queries the VirusTotal v3 REST API to retrieve real-time detection ratios (e.g., `58/72 AV Engines Malicious`).
- **Vendor Detections Modal**: Clicking any VirusTotal detection badge opens an interactive breakdown displaying the exact malware signature identified by each antivirus vendor.
- **Smart Rate-Limit Guard & Caching**: Designed for VirusTotal's free community tier (4 queries/min, 500/day). Uses in-memory caching and prioritizes anomalous files so scans complete without unnecessary delay.
- **Zero-Key Fallback**: Even without an API key, SHA-256 hashes are computed for every file with a 1-click **Lookup on VirusTotal** link to view or submit files on the web.

### 2. Google Safe Browsing v4 Threat Intelligence
Weaponized files (such as PowerShell droppers, batch files, macros, PDFs, or HTML attachments) often do not contain the final binary payload locally; instead, they embed external links to download stages or connect to Command-and-Control (C2) servers:
- **Embedded URL Extractor**: Automatically parses text files, scripts (`.ps1`, `.bat`, `.vbs`, `.js`, `.py`, `.sh`), HTML, documents, and configs for embedded web URLs and endpoints.
- **Real-Time Blacklist Verification**: Queries Google's Safe Browsing v4 API (`threatMatches:find`) across four threat categories:
  - `MALWARE` (malware distribution endpoints)
  - `SOCIAL_ENGINEERING` (phishing and credential harvesting pages)
  - `UNWANTED_SOFTWARE` (adware, spyware, and bundleware)
  - `POTENTIALLY_HARMFUL_APPLICATION`
- **Critical Alerting**: Flags any file containing blacklisted links with Critical severity, isolating the suspicious URL and threat classification.

### 3. Zero-OOM Streaming File Inspector & Large File Architecture
Handling multi-gigabyte files (such as 50 GB+ disk images or large archives) can create memory exhaustion risks. The streaming pipeline incorporates:
- **`ArrayPool<byte>` Buffer Pooling**: Reads streams in 64 KB rented chunks without allocating on the Large Object Heap (LOH).
- **Single-Pass Shannon Entropy Histogram**: Computes mathematically exact Shannon entropy across any file size using a streaming `long[256]` byte frequency histogram:
  $$H = -\sum_{i=0}^{255} p_i \log_2(p_i)$$
- **Sliding-Window Block Entropy**: Computes localized entropy across 64 KB stepped windows, immediately flagging packed crypters, encrypted overlays, or hidden payloads even inside large files.
- **Concurrent `IncrementalHash`**: Simultaneously generates cryptographic SHA-256 hashes during the single-pass stream traversal.

### 4. Zero-Day Threat Arbiter & Privacy-Preserving Cloud Submission
When VirusTotal returns `NotFound` for an unseen or freshly compiled zero-day binary, the scanner executes an enterprise-grade defense workflow:
- **Composite Local Risk Scoring (0-100)**: Aggregates signals across magic byte masquerades (+40), AST script indicators (+35), evasive naming (+35), high-entropy sections (+25), and Safe Browsing matches (+50).
- **Zero-Day Suspicion Alerting**: Novel files with local risk $\ge 35$ or Critical anomalies are elevated to **Novel Zero-Day Threat Suspicion**.
- **Privacy-Preserving User Consent Modal**: Prompts the user with an explicit privacy warning before submitting binaries to VirusTotal, preventing accidental leakage of proprietary code or confidential data to third-party security vendors.

### 5. Deep PowerShell Abstract Syntax Tree (AST) Inspection
Replaces fragile regular expressions with the official Microsoft PowerShell compiler parser (`System.Management.Automation.Language.Parser`):
- **Evasion-Resistant Token Parsing**: Automatically normalizes backtick escapes (e.g., `` `I`E`x `` resolves to `IEx`) and whitespace obfuscation.
- **Dynamic Member Invocation Extraction**: Detects staged download cradle methods (such as `.DownloadString()` or `.DownloadFile()`) even when obfuscated through string concatenation (e.g., `('Down'+'load'+'String')`).
- **Heavy Concatenation Tree Detection**: Analyzes `BinaryExpressionAst` trees to identify automated obfuscation tools (e.g., Invoke-Obfuscation).
- **Recursive Base64 Payload De-obfuscation**: Automatically extracts, decodes, and recursively runs AST analysis on embedded encoded script blocks.

### 6. Cloud Sandbox Behavioral Telemetry Engine
Dynamic execution forensics powered by cloud sandbox hypervisors (via VirusTotal v3 API):
- **False Positive Adjudication**: Inspect actual dynamic execution traces from cloud sandbox hypervisors (process trees, command executions, C2 network connections, autostart registry keys, and dropped secondary payloads) to determine whether a local heuristic flag is an actual malicious threat or a benign false alarm.
- **Visual Process Tree & Command Execution**: Displays the complete execution hierarchy of spawned child processes and command-line arguments (e.g., `cmd.exe /c ...` or `powershell.exe -enc ...`).
- **Network & C2 Traffic Telemetry**: Tabulates all contacted IP addresses, outbound ports, transport protocols (TCP/UDP), DNS lookups, and HTTP web conversations.
- **Persistence & Filesystem Forensics**: Pinpoints persistence mechanisms (such as autostart `CurrentVersion\Run` registry keys) and secondary dropper files.
- **MITRE ATT&CK Technique Mapping**: Automatically maps behavioral actions to adversary tactics and techniques with severity ratings (e.g., `T1055 Process Injection`, `T1547 Boot or Logon Autostart Execution`).
- **Automated Adjudication Heuristics**: Automatically scores execution traces as **Confirmed Threat (True Positive)** versus **Benign Dynamic Behavior (Likely False Positive)** with forensic confidence scoring.
- **Mark Safe / Dismiss**: Allows instant whitelisting and clearing of verified benign false positives from the dashboard.

### 7. Cryptographic File Remediation & Permanent Eradication
When a file is confirmed as an active threat, the application provides built-in eradication:
- **DoD 5220.22-M Multi-Pass Shredding**:
  1. *Pass 1*: Cryptographically secure pseudo-random byte overwriting (`RandomNumberGenerator.Fill`).
  2. *Pass 2*: Complete zero-fill pass across all allocated sectors.
  3. *Pass 3*: File stream truncation to 0 bytes.
- **MFT Metadata Sanitization**: Renames the target file to an anonymous temporary GUID prior to deletion, clearing the original filename and metadata from Master File Table (MFT) directory entries.
- **SHA-256 Pre-Verification Guard**: Validates that the file on disk matches the scanned hash before destruction begins, preventing accidental deletion of replaced or modified files.
- **Safety Boundary Enforcements**: Hardcoded protections prevent shredding root drives, Windows system directories, System32, Program Files, or the scanner application itself.

### 8. Structural & Heuristic Anomaly Engine
- **Header vs. Extension Validation**: Detects file extension spoofing (e.g., Windows PE executables disguised as `.png`, `.jpg`, `.pdf`, `.docx`).
- **Deceptive Naming Detection**: Flags RTLO Unicode override characters (`U+202E`) and double extensions (e.g., `Report.pdf.exe`).
- **Shannon Entropy Analysis**: Detects packed, obfuscated, or encrypted payloads with abnormal entropy ratings.
- **Polyglot & Embedded PE Headers**: Identifies DOS execution stubs and secondary `MZ` headers inside non-executable containers.
- **Malicious Script Signatures**: Detects base64-encoded PowerShell cradles, `DownloadString` / `Invoke-Expression` execution chains, and PHP webshell primitives (`eval(base64_decode)`, `passthru`, `system`).
- **Container & Archive Inspection**: Unpacks and inspects nested `.zip`, `.jar`, `.apk`, and OpenXML archives for directory traversal and zip-bomb hazards.

---

## Security Risk Analysis & Threat Modeling

An in-depth security posture assessment was conducted across the scanner architecture. The findings, existing mitigations, and operational recommendations are summarized below:

### Threat Matrix & Security Posture Summary

| Domain | Risk Description | Severity | Implemented Mitigations | Recommended Best Practice |
| :--- | :--- | :--- | :--- | :--- |
| **API Key Storage** | Plaintext keys in local configuration file (`security-settings.json`). | Medium | Excluded from git via `.gitignore`; masked in all API responses (`••••••••abcd`); environment variable overrides supported. | Use Windows DPAPI (`ProtectedData`) for encryption at rest; restrict file permissions to current user SID. |
| **Local Web API** | Embedded ASP.NET Core Web API on loopback `127.0.0.1:5000` with permissive CORS. | Medium | Bound strictly to loopback (`127.0.0.1`); requests cannot originate from external LAN hosts. | Restrict CORS policy to exact origins (`http://localhost:5000`, `http://127.0.0.1:5000`); add startup session authentication token for desktop WebView2 requests. |
| **File Eradication** | Arbitrary file deletion or path traversal via `POST /api/sandbox/remediate`. | High | Strict path validation (`ValidatePathSafety` blocks root, Windows, System32, Program Files, AppDir); optional SHA-256 pre-check prevents shredding modified files. | Log all eradication actions with timestamp and operator details to a dedicated audit log. |
| **Cloud Sample Upload** | Leaking sensitive, proprietary, or personal files to VirusTotal cloud repositories. | High | Zero automatic uploads; hash lookups are strictly metadata-only; full binary upload requires explicit confirmation in the Privacy Consent Modal. | Avoid uploading files from known sensitive directories (e.g., containing `.env`, `.pem`, `id_rsa`, or database files). |
| **Archive Hazards** | Malicious archives containing Zip-Slip directory traversal or Zip-Bombs. | High | In-memory stream parsing only; files are never written to disk during inspection; entry count capped at 5,000; compression ratios > 100:1 flagged. | Current controls are robust; maintain in-memory inspection boundaries. |
| **Malware Execution** | Host infection during inspection of malicious binaries or scripts. | Critical | Static analysis only; AST parser analyzes syntax trees without runtime script invocation; PE headers inspected without binary execution. | Retain strict static analysis separation; never execute untrusted payloads on the host OS. |

### Detailed Security Risk Assessment

#### 1. API Key Storage & Protection
* **Current Implementation**: API keys entered via the Settings modal are stored in `security-settings.json` within the application working directory. When the frontend requests settings, `SecuritySettingsService.MaskKey()` returns only the first and last four characters, preventing keys from being exposed in browser DOM inspection.
* **Residual Risk**: Any local process executing under the current user context with read access to the directory could read `security-settings.json`.
* **Mitigation Recommendation**: For shared workstations, configure `VIRUSTOTAL_API_KEY` and `GOOGLE_SAFE_BROWSING_API_KEY` as user-level environment variables rather than persisting them to disk. In future enterprise builds, encrypt the JSON payload using Windows DPAPI (`DataProtectionScope.CurrentUser`).

#### 2. Localhost API & Cross-Origin Requests
* **Current Implementation**: `DesktopHost` binds to `http://127.0.0.1:5000` to serve the local React SPA and receive file scan requests.
* **Residual Risk**: A malicious website visited in a standard web browser on the same host could attempt to make cross-origin `fetch` requests to `http://127.0.0.1:5000`.
* **Mitigation Recommendation**: In addition to loopback binding, restrict the CORS policy strictly to `http://localhost:5000` and `http://127.0.0.1:5000`, and implement an internal anti-CSRF request header for remediation calls.

#### 3. File Remediation & Destructive Action Safeguards
* **Current Implementation**: The remediation engine implements defensive guardrails in `FileRemediationService.ValidatePathSafety`:
  * Denies path roots (preventing accidental wiping of entire drives).
  * Denies system folders (`C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, `C:\Program Files (x86)`).
  * Denies application binaries (`AppContext.BaseDirectory`).
  * Enforces hash matching when an expected SHA-256 is supplied.
* **Residual Risk**: Malicious input targeting user documents could destroy files if an attacker had local execution privileges to call the API.
* **Operational Recommendation**: Always keep the expected SHA-256 validation enabled (as enforced by the frontend UI) so shredding is aborted if file contents change.

#### 4. Cloud Telemetry & Data Privacy
* **Current Implementation**: VirusTotal is an open threat intelligence platform; files submitted to VirusTotal are shared with security partners worldwide.
* **Defensive Controls**:
  * Default lookups check only cryptographic SHA-256 hashes. No file contents or filenames are sent to VirusTotal during regular scans.
  * Binary uploads are quarantined behind the `UploadConsentModal`, requiring the operator to review file details and explicitly acknowledge the external transfer.

#### 5. Safe Static Inspection Guarantee
* **Current Implementation**: The entire heuristic engine operates on static file content. The PowerShell Abstract Syntax Tree engine uses `System.Management.Automation.Language.Parser` to parse scripts into syntax trees; no script is ever executed or evaluated. PE headers and archive entries are inspected purely as raw byte arrays.

---

## Threat Intelligence & API Configuration

Click the **API Settings** button in the header bar to configure your optional threat intelligence keys:

1. **VirusTotal API Key**:
   - Obtain a free community key at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) (Free tier includes 500 lookups/day, 4 lookups/minute).
   - Enter your key in the settings modal and click **Test Key** to verify connectivity against the standard EICAR test signature.
   - Configure the maximum number of automatic VT lookups per scan batch.
2. **Google Safe Browsing API Key**:
   - Obtain an API key via the [Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) (Free tier includes 10,000 lookups/day).
   - Enter your key and click **Test Key** to verify connectivity against Google's official malware test domain.
   - Toggle embedded URL extraction on/off.

> **Privacy Note**: Settings and keys are stored locally in `security-settings.json` (ignored by git). Keys are communicated solely to official Google (`safebrowsing.googleapis.com`) and VirusTotal (`www.virustotal.com`) endpoints over HTTPS.

---

## How to Run

### Option 1: 1-Click Desktop Application (Recommended)
Double-click:
```
FileAnomalyScanner.exe
```
located directly in the repository root folder. It immediately launches the native WPF desktop window with the embedded frontend and backend services.

### Option 2: Run via Terminal
1. Open a terminal in the `backend` folder and run:
   ```bash
   dotnet run
   ```
2. Navigate to `http://localhost:5000` in your web browser.

### Option 3: Live Frontend Development Mode (HMR)
1. In `backend`: `dotnet run`
2. In `frontend`: `npm run dev`
3. Open `http://localhost:5173` in your browser.

---

## Built-in Synthetic Test Suite

Click **Load Synthetic Test Folder** in the top bar to verify the complete detection pipeline against 8 pre-configured test scenarios:

1. `eicar_antivirus_test.com.txt`: The standard EICAR antivirus test file (harmless string recognized across 65+ AV engines on VirusTotal).
2. `updater_c2_test.ps1`: Script containing Google's official Safe Browsing malware test URL.
3. `obfuscated_cradle.ps1`: Dynamic memory execution cradle testing the PowerShell AST engine against string concatenation and backtick escapes (`.('Down'+'load'+'String')` and `` `I`Ex ``).
4. `logo_banner.png`: Masqueraded Windows PE executable disguised with a `.png` image extension.
5. `Q3_Financial_Report.pdf.exe`: Deceptive double-extension executable file.
6. `deploy_updater.ps1`: Base64-encoded stealth PowerShell execution cradle.
7. `audit_notes.txt`: High-entropy packed pseudo-random content.
8. `config.txt`: Legitimate baseline text file with normal entropy.

---

## Technology Stack

* **Backend**: .NET 8, ASP.NET Core Web API, System.Management.Automation (PowerShell AST), System.Security.Cryptography.
* **Desktop Shell**: WPF (Windows Presentation Foundation), Microsoft.Web.WebView2.
* **Frontend**: React 18, Vite, Vanilla CSS (Clean Light Security Theme), REST API Client.
* **Threat Intelligence**: VirusTotal v3 REST API, Google Safe Browsing v4 REST API.