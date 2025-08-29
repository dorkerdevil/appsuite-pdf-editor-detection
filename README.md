# AppSuite PDF Editor Backdoor Detection

## Overview
AppSuite PDF Editor is a trojanized Electron-based PDF editor distributed via high-ranking websites. The installer downloads the app from `vault.appsuites.ai` and installs to `%USERPROFILE%\PDF Editor` or `%LOCALAPPDATA%\Programs\PDF Editor`. The main payload is `pdfeditor.js`, heavily obfuscated, which implements a backdoor. Persistence is achieved via scheduled tasks and registry RUN keys. The backdoor communicates with C2 servers and can execute arbitrary commands, exfiltrate data, and download further malware. It targets browser data and can manipulate browser settings, steal credentials, and more.

## Indicators of Compromise (IOCs)
- **Install Locations:**
  - `%LOCALAPPDATA%\Programs\PDF Editor`
  - `%USERPROFILE%\PDF Editor`
- **Files:**
  - `pdfeditor.js` (main backdoor)
  - `UtilityAddon.node` (helper DLL)
  - `PDF Editor.exe` (Electron launcher)
  - `LOG1`, `LOG0` (encoded JSON config files)
- **Scheduled Tasks:**
  - `PDFEditorScheduledTask`
  - `PDFEditorUScheduledTask`
  - `ShiftLaunchTask`
  - `OneLaunchLaunchTask`
  - `WaveBrowser-StartAtLogin`
- **Registry:**
  - RUN key: `PDFEditorUpdater` with value pointing to `PDF Editor.exe`
- **User Agent:**
  - `PDFFusion/93HEU7AJ`
- **C2 URLs:**
  - `appsuites.ai`, `sdk.appsuites.ai`, `on.appsuites.ai`, `log.appsuites.ai`
  - Download: `vault.appsuites.ai/AppSuite-PDF-1.0.28.exe`



## Detection
- [Python script](detections/appsuite_detect.py): Use on Windows systems to scan for AppSuite PDF Editor backdoor indicators (install locations, scheduled tasks, registry keys, LOG files). Run with Python 3 on a potentially infected machine.
- [Python script](detections/appsuite_pdfeditor_log1_decode.py): For forensic analysis, use to decode the LOG1 file and extract configuration, keys, and infection status. Run with Python 3 and provide the path to the LOG1 file as argument.
- [YARA rule](detections/appsuite_pdfeditor.yar): Use with YARA to scan files or memory for AppSuite PDF Editor backdoor artifacts. Suitable for endpoint or malware analysis.
- [Sigma rule](detections/appsuite_pdfeditor_sigma.yml): Use with SIEM systems supporting Sigma to detect suspicious scheduled tasks related to the backdoor in event logs.

## Usage

### Python Scripts
- `appsuite_detect.py`: Run on Windows (with Python 3) to check for infection. Example:
  ```
  python detections/appsuite_detect.py
  ```
- `appsuite_pdfeditor_log1_decode.py`: Run on any OS (with Python 3) for forensic analysis of LOG1 files. Example:
  ```
  python detections/appsuite_pdfeditor_log1_decode.py /path/to/LOG1
  ```

### YARA Rule
- Use with YARA to scan files or memory:
  ```
  yara detections/appsuite_pdfeditor.yar /path/to/suspicious/files
  ```

### Sigma Rule
- Use with SIEM/Sigma-compatible tools to detect scheduled tasks in logs.

## Author
dorkerdevil (Ashish Kunwar)

## Remediation
- Remove all files, scheduled tasks, registry keys, and repave the system (format and reinstall OS) if infection confirmed.

## References
- [G DATA Blog](https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis)
