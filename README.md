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
- **Sample Hashes (SHA256):**
  - MSI installer: `fde67ba523b2c1e517d679ad4eaf87925c6bbf2f171b9212462dc9a855faa34b`
  - `pdfeditor.js`: `b3ef2e11c855f4812e64230632f125db5e7da1df3e9e34fdb2f088ebe5e16603`
  - `UtilityAddon.node`: `6022fd372dca7d6d366d9df894e8313b7f0bd821035dd9fa7c860b14e8c414f2`
  - `PDFEditorSetup.exe`: `da3c6ec20a006ec4b289a90488f824f0f72098a2f5c2d3f37d7a2d4a83b344a0`
  - `PDF Editor.exe`: `cb15e1ec1a472631c53378d54f2043ba57586e3a28329c9dbf40cb69d7c10d2c`
  - `Uninstall PDF Editor.exe`: `956f7e8e156205b8cbf9b9f16bae0e43404641ad8feaaf5f59f8ba7c54f15e24`
  - Deobfuscated `pdfeditor.js`: `104428a78aa75b4b0bc945a2067c0e42c8dfd5d0baf3cb18e0f6e4686bdc0755`
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
