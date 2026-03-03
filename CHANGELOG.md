# Changelog

All notable changes to the Installer Analysis Tool are documented in this file.

## [1.0.0] - 2026-03-03

### Added
- **WinForms GUI** (`start-installeranalysis.ps1`) for analyzing EXE and MSI installer files
  - Drag-and-drop support for instant analysis
  - File browse with Ctrl+O shortcut
  - 4 tabbed views: Overview, MSI Properties, Payload Contents, Strings
  - Dark/light theme, window state persistence, preferences dialog

- **Installer type detection** via binary signature scanning
  - MSI (OLE magic bytes / extension), NSIS (DEADBEEF + NullsoftInst), Inno Setup, InstallShield, WiX Burn (WixBundleManifest), 7-Zip SFX, WinRAR SFX, Advanced Installer

- **Version intelligence**
  - FileVersionInfo (FileVersion, ProductVersion, CompanyName, FileDescription)
  - PE header architecture detection (x86, x64, ARM64)
  - Digital signature via Get-AuthenticodeSignature (status, signer, issuer, thumbprint)
  - SHA-256 file hash

- **MSI property extraction**
  - Primary: PSGallery MSI module (`Get-MSIProperty`, `Get-MSISummaryInfo`)
  - Fallback: COM interop via WindowsInstaller.Installer (zero external dependencies)
  - Reads full Property table + Summary Information stream (architecture from Template)

- **Silent install switch database**
  - MSI: `/qn /norestart`
  - NSIS: `/S` (case sensitive)
  - Inno Setup: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-`
  - InstallShield: `/s /v"/qn"`
  - WiX Burn: `/quiet /norestart`
  - Advanced Installer, 7z SFX, WinRAR SFX, Unknown
  - Auto-substitutes actual filename and ProductCode into templates

- **Payload extraction** via 7-Zip (`7z.exe`)
  - List contents without extracting (`7z l`)
  - Extract all to user-chosen directory (`7z x`)
  - Auto-detects embedded MSI in EXE wrappers and analyzes it
  - Auto-detects 7z.exe in Program Files, PATH, or prefs override

- **Binary string analysis**
  - Extracts printable ASCII strings >= 8 chars
  - Categorizes: Installer Markers, URLs, Registry Paths, File Paths, GUIDs, Version Strings
  - Real-time filter on Strings tab

- **Export**: CSV, HTML (styled report), clipboard summary

- **Core module** (`InstallerAnalysisCommon.psm1`) with 18 exported functions

- `InstallerAnalysisCommon.Tests.ps1` -- 30 Pester 5.x tests covering logging, PE architecture, installer type detection (MSI/NSIS/Inno/WiX/InstallShield), silent switch database, file info, 7-Zip path detection, binary strings, interesting strings, export, and summary text
