# Changelog

All notable changes to the Installer Analysis Tool are documented in this file.

## [1.0.0] - 2026-05-02

Installer Analysis is a MahApps.Metro WPF desktop tool that detects 18
installer / package formats, extracts deployment-ready metadata, and
exports MECM-ready digests in one pass.

### Shell

- MahApps.Metro WPF shell replaces the v1.1.0 WinForms GUI.
- Left-nav sidebar with four view buttons (Overview, MSI Properties,
  Payload, Strings) plus Options. Active-view highlight via per-theme
  border brush.
- Content-area action bar (Copy Summary, Copy JSON, Export CSV,
  Export HTML, Extract Payload) surfaces after each analysis; extract
  is only shown for 7-Zip-listable payloads.
- Module header tracks the active view's title + subtitle.
- Log drawer (resizable) and status bar on every view.
- Drag-drop overlay during drag-over with "Drop installer to analyze"
  affordance.
- Options window: 7-Zip path, Logging, Reports folder, About. The
  dark / light theme toggle lives on the main sidebar only per brand.
- Startup-file parameter (`-StartupFile`) for scripted automation.
- STA guard, Dispatcher + AppDomain crash handlers, multi-monitor
  window-state save / restore.
- Progress overlay with MahApps ProgressRing shown for the duration of
  each analysis run; updates a status line per pipeline stage (Reading
  file info, Detecting type, Reading MSI properties, Reading package
  metadata, Resolving deployment fields, Listing payload, Scanning
  interesting strings, Rendering views). Dispatcher pumps between
  stages keep the spinner animating instead of freezing while the
  binary-strings scan runs on large installers.

### Detection (18 formats)

- Classic EXE / MSI: MSI, NSIS, Inno Setup, InstallShield, WiX Burn,
  7-Zip SFX, WinRAR SFX, Advanced Installer, **BitRock InstallBuilder
  (new)**.
- Package formats: Chocolatey `.nupkg`, NuGet `.nupkg`, Intune
  `.intunewin`, MSIX / APPX, MSIX / APPX Bundle, PSAppDeployToolkit v3,
  PSAppDeployToolkit v4, Squirrel / Electron `Setup.exe`.
- Binary-signature scan window bumped from 512KB to 4MB. Modern
  installers (GIMP, Audacity, Git, Positron, PostgreSQL, etc.) embed
  their framework marker past 512KB; the prior window missed all of
  them as Unknown.
- Silent-switch database expanded for every new format, including
  BitRock's `--mode unattended --unattendedmodeui none`.

### Overview rendering

- Per-format Package Metadata section surfaces format-specific extras:
  - Chocolatey / NuGet: nuspec id, version, authors, project URL, tags,
    description.
  - Intunewin: Name, Setup File, Tool Version, encryption flag, and a
    nested Source MSI block when the original was an MSI.
  - MSIX / APPX: Identity (Name, Publisher, Version, Processor
    Architecture, Resource Id) + Properties description.
  - MSIX / APPX Bundle: Identity plus a full bundled-packages list with
    each inner package's type, architecture, version, resource id, and
    filename.
  - PSADT v3 / v4: Toolkit variant + version plus all nine AppMetadata
    fields (AppVendor, AppName, AppVersion, AppArch, AppLang, AppRevision,
    ScriptVersion, ScriptDate, ScriptAuthor).
  - Squirrel / Electron: app name, version, lifecycle markers found,
    embedded nupkg reference, confidence rating.
- MECM-ready JSON export (`ConvertTo-DeploymentJson`): SchemaVersion 1.0
  digest with Source / Application / Deployment / Detection / Raw
  sections, paste-ready into New-CMApplication parameter splats.

### Input hardening + safety

- Extract Payload confirms before extracting into a non-empty target
  folder.
- 7-Zip path auto-detects in Program Files when not configured in Options.
- Theme toggle persists to gitignored `InstallerAnalysis.prefs.json`
  alongside LastBrowseDir, SevenZipPath, ReportsFolder.
- Module import is fail-loud (no SilentlyContinue) so a missing
  InstallerAnalysisCommon.psd1 surfaces the real error instead of masking
  every downstream call as CommandNotFoundException.

### Accessibility + brand

- WCAG AA verified via the brand contrast harness on both Dark.Steel
  and Light.Blue (0 real-text failures).
- Theme toggle cleanly swaps Dark.Steel <-> Light.Blue at runtime;
  sidebar button fills + title-bar brushes + LOG OUTPUT label hex all
  re-apply per theme.
- Type scale fixed at 20 / 18 / 13 / 12 / 11 / 10. Monospace stack:
  Cascadia Code, Consolas, Courier New.
- No red / green status colors; state carried by glyph shape.

### Distribution

- `install.ps1` copies files to `%LOCALAPPDATA%\InstallerAnalysis` and
  adds a Start Menu shortcut. Runs as the logged-in user, no admin
  required. `uninstall.ps1` reverses the install, with `-PurgeData`
  for full removal including logs and prefs.
- Shortcut launches with `-NoProfile -ExecutionPolicy Bypass -STA -File`
  per PS 5.1 exit-code + STA guards.
- Vendored under `Lib/`: MahApps.Metro, ControlzEx, Microsoft.Xaml.Behaviors
  for the WPF shell, plus the PSGallery `MSI` module (heaths/psmsi,
  MIT-licensed) for enhanced MSI property extraction. `WindowsInstaller`
  COM fallback still runs if the vendored module cannot load. No NuGet,
  no runtime network pulls.

### Testing

- Pester: 103 tests across logging, PE architecture, installer-type
  detection (including the 18th BitRock format and the deep Inno Setup
  detection past 512KB), ZIP helpers, MSI property extraction, per-
  format cracker metadata, deployment-fields resolution precedence,
  silent-switch template expansion, summary-text rendering per format,
  and the MECM-ready JSON digest.
- Headless smoke (`Tests/Smoke.Tests.ps1`): 6 stages covering module
  load, exported-function registration, 7 cracker invocations against
  synthetic fixtures, the core `Get-SilentSwitches` + `Get-DeploymentFields`
  pipeline, the WPF shell's XAML parse + FindName resolution for all 30
  named elements, and optional real-installer end-to-end against a
  configurable fixture directory (default `c:/temp/ap`).

## Historical pre-1.0 entries

Nominal v1.0.x and v1.1.0 releases shipped as patch increments on pre-1.0
code. This archive preserves their history; the public release is v1.0.0
on a fresh orphan commit per `feedback_public_v1_single_commit.md`.

### [1.1.0] - 2026-04-23

#### Added

- **Five new package-format crackers**, bringing the tool to parity with modern Windows packaging workflows:
  - **Chocolatey / NuGet `.nupkg`** (`Get-ChocolateyMetadata`) -- parses the root `.nuspec` (namespace-aware, BOM-tolerant) and distinguishes Chocolatey from plain NuGet by presence of `tools/chocolatey*.ps1`. Returns id, version, authors, description, project URL, tags.
  - **Microsoft Intune `.intunewin`** (`Get-IntunewinMetadata`) -- parses the `IntuneWinPackage/Metadata/Detection.xml` emitted by the Win32 Content Prep Tool. Extracts Name, SetupFile, ToolVersion, EncryptionInfo, and the full MsiInfo block when the source installer was an MSI. Does not attempt to decrypt the inner payload (those keys live in Intune).
  - **MSIX / APPX single packages and bundles** (`Get-MsixManifest`) -- parses `AppxManifest.xml` for single packages and `AppxMetadata/AppxBundleManifest.xml` for bundles. Surfaces Identity (Name, Publisher, Version, ProcessorArchitecture) and Properties (DisplayName, PublisherDisplayName). Bundles enumerate every inner package with architecture and resource id.
  - **PSAppDeployToolkit v3 + v4** (`Get-PsadtMetadata`) -- detects zipped PSADT wrappers via sentinel files (v4: `PSAppDeployToolkit.psd1` / `Invoke-AppDeployToolkit.ps1`; v3: `Deploy-Application.ps1` + `AppDeployToolkit/AppDeployToolkitMain.ps1`). Reads toolkit engine version and per-app header ($appVendor, $appName, $appVersion, etc., plus the v4 hashtable equivalent).
  - **Squirrel / Electron Setup.exe** (`Get-SquirrelMetadata`) -- binary-string scan for Squirrel lifecycle markers (`SquirrelTemp`, `squirrel-install`, etc.) plus embedded `<AppName>-<Version>-full.nupkg` reference. Requires two or more markers (or one marker plus Update.exe) to confirm. Ordered before NSIS in the detection chain to defend against false positives.
- **Generic ZIP helpers** shared by every package cracker (`Test-IsZipFile`, `Test-ZipEntryExists`, `Get-ZipEntryText`, `Get-ZipRootEntryByPattern`, `Get-ZipEntryPathByPattern`) using `System.IO.Compression.FileSystem` -- no external DLL dependencies.
- **Unified package-metadata pipeline:** `Get-DeploymentFields` gained an optional `-PackageMetadata` parameter so any new format's standardized fields (DisplayName, DisplayVersion, Publisher, SilentUninstallCommand) take precedence over MSI properties and FileVersionInfo.
- **Overview tab** now renders a format-specific "PACKAGE METADATA" section with the relevant extras per format (nuspec project URL; Intunewin MsiInfo; MSIX Identity; PSADT toolkit version; Squirrel markers + embedded nupkg).
- 52 new Pester tests (35 -> 87 total), all using synthetic ZIP fixtures -- no real installer binaries committed.

#### Changed

- `Get-InstallerType` now returns one of 17 values (was 9): MSI, NSIS, InnoSetup, InstallShield, WixBurn, AdvancedInstaller, 7zSFX, WinRarSFX, Chocolatey, NuGet, Intunewin, Msix, MsixBundle, PsadtV3, PsadtV4, Squirrel, Unknown.
- `Get-SilentSwitchDatabase` expanded with rows for every new format including the non-obvious switches (MSIX: `Add-AppxPackage`; Squirrel: `--silent` double-dash; PSADT v4 exe entry point).

### [1.0.2] - 2026-03-17

#### Added
- `Get-DeploymentFields` function: resolves ARP registry fields (DisplayName, DisplayVersion, Vendor, SilentUninstallString) from best available source (MSI properties > FileVersionInfo fallback)
- Deployment Fields section in Overview tab, CSV export, HTML export, and clipboard summary
- 5 Pester tests for `Get-DeploymentFields` (MSI preference, FileVersionInfo fallback, sparse/empty data)

#### Fixed
- `New-AnalysisSummaryText` version line now uses resolved `DeploymentFields.DisplayVersion` when available instead of reimplementing its own fallback chain

### [1.0.1] - 2026-03-03

#### Fixed
- MSI Summary Information COM fallback: wrapped `InvokeMember` args in explicit arrays and corrected `Property` binding flags from `InvokeMethod` to `GetProperty`, fixing `DISP_E_MEMBERNOTFOUND` errors when the PSGallery MSI module is not installed
- `Write-Log` ERROR messages no longer display twice in the console (was writing to both `Write-Host` and `WriteErrorLine`)

#### Added
- LICENSE (MIT)
- Screenshots in README

### [1.0.0] - 2026-03-03

#### Added
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
