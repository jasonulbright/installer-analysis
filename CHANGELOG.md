# Changelog

## [2026.09.21.0012] - 2026-09-21

### Changed

- Use the product name Configuration Manager in the application and the documentation.
- Use date versions.
- Update the shared SuiteCommon module to 2026.09.21.0031.

## [1.3.4.0] - 2026-09-09

### Added

- Detect Velopack Setup.exe installers, including Draftable Desktop Setup,
  and report `--silent` / `-s` install support.
- Read Velopack's embedded nuspec for application metadata, the default
  per-user uninstall command and HKCU detection key. Preserve the full
  package version separately from the shorter ARP DisplayVersion.

### Fixed

- Use the Velopack application's architecture in deployment JSON when it
  differs from the setup launcher's architecture.

## [1.3.3.0] - 2026-09-04

### Changed

- Show each install mode's switch, folder, uninstall command and detection key in the Overview.

### Fixed

- Resolve NSIS detection keys written through a variable or beside a variant key.
- Place NSIS detection keys in the 64-bit view when SetRegView 64 runs in .onInit.
- Register SHCTX keys under HKLM when the script targets Program Files for all users.
- Honour HKLM64 and HKLM32 roots and SetRegView 32 when placing NSIS detection keys.
- Report no detection key for Inno Setup scripts with Uninstallable=no.
- Read NSIS headers faster and without exhausting memory on very large installers.

## [1.3.2.0] - 2026-09-04

### Added

- **Install modes for switchable installers.** `Get-NsisMetadata` and
  `Get-InnoSetupMetadata` report `InstallModes`, the default
  `InstallMode`, the switch literals (`AllUsersSwitch`,
  `CurrentUserSwitch`) and `ModeVariants`, one fully resolved branch per
  mode: install arguments with the mode switch, install folder,
  uninstaller path and silent uninstall command, ARP key with hive and
  registry view, and install context. An NSIS script that carries the
  `/allusers` and `/currentuser` options (electron-builder, MultiUser)
  and a Program Files candidate beside the per-user one gets both modes;
  an Inno Setup script gets both when
  `PrivilegesRequiredOverridesAllowed` includes the command line
  (`/ALLUSERS`, `/CURRENTUSER`). The top-level fields are unchanged and
  keep describing the default branch, so a per-machine deployment built
  from the other branch never mixes values from the per-user one.
- **Summary text** lists the install modes and the switch that selects
  each non-default one.

### Changed

- **Branch resolution is one code path.** The NSIS and Inno Setup
  decoders resolve folder, uninstaller, key, hive, view and context
  through a single per-branch resolver that the default and the
  switchable branches share.

## [1.3.1.0] - 2026-09-04

### Added

- **Inno Setup compiled `[Setup]` header decoded (`Get-InnoSetupMetadata`).**
  The SetupLdr offset table (RCDATA 11111, revision 1 and the 64-bit
  revision 2 of 6.5+) locates the setup-0 block; the CRC-chunked LZMA1
  block is decoded and the leading `TSetupHeader` record parsed by data
  version from 5.x through 7.0.0.3, including the 6.5 encryption header
  and the 6.7 64-bit block size. Reported: `AppId`, `AppName`,
  `AppVersion`, `AppPublisher`, `DefaultDirName` (and its environment
  form), `UninstallFilesDir`, `PrivilegesRequired`,
  `PrivilegesRequiredOverridesAllowed`, `ArchitecturesInstallIn64BitMode`,
  `MinVersion`, `CreateUninstallRegKey`, `Uninstallable`, and the ARP
  values the setup writes. Encrypted headers are reported, not decoded.
- **`ConvertTo-InnoWindowsPath`** rewrites `{autopf}`, `{pf}`, `{cf}`,
  `{localappdata}`, `{userpf}`, `{commonappdata}`, `{sd}`, `{win}`,
  `{sys}`, `{%ENV|default}` and the `{{` escape into environment form
  for the install mode; run-time constants (`{code:...}`, `{reg:...}`)
  stay in place so callers can tell the folder is unresolved.
- **`Get-PeResourceData`** reads one numbered resource from a PE file;
  `Get-PeRequestedExecutionLevel` now uses it for `RT_MANIFEST`.

### Changed

- **Inno Setup deployment fields come from the header.** The predicted
  ARP key is `<AppId>_is1` (GUID or name, with the `{{` escape
  resolved) under HKLM in the 64-bit view, under `WOW6432Node` when the
  setup never enters 64-bit mode, or under HKCU for
  `PrivilegesRequired=lowest`; `DisplayVersion` is `AppVersion` even
  when the stub carries no file version; the silent uninstall string
  names `unins000.exe` in `UninstallFilesDir` (`"%ProgramFiles%\App\unins000.exe"
  /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`); `InstallContext` follows
  `PrivilegesRequired`. The `DisplayName_is1` convention remains the
  fallback when the header is not decoded.
- **Summary text** carries a "Package Metadata (Inno Setup compiled
  [Setup] header)" block and qualifies the manifest `Elevation` line:
  an Inno Setup 6 stub is `asInvoker` and elevates itself for
  `PrivilegesRequired=admin`, so the manifest does not indicate a
  per-user install.

## [1.3.0.2] - 2026-09-04

### Changed

- **Vendored `SuiteCommon` 0.4.3.** The shared module repairs the process
  PSModulePath at import, which supersedes the runspace-local repair 1.3.0.0
  carried in the analysis runspace init; a Windows PowerShell process
  launched from PowerShell 7 no longer hands any runspace or child process
  the 7.x module directories. A background runspace whose module import
  fails is disposed and the original error thrown.

## [1.3.0.1] - 2026-09-04

### Fixed

- **Header string decoding no longer copies the header per call.** The
  strings block is decoded once into a table string and entries index
  into it; binding the header byte array to a typed parameter for every
  string made PowerShell copy it each time, so scripts with thousands of
  entries took minutes.
- **Run-time `$INSTDIR` resolution covers user-variable indirection.**
  `StrCpy $INSTDIR "$0\App"` resolves through the last literal assigned
  to `$0` (electron-builder), `StrCpy $INSTDIR "$INSTDIR\App"` extends
  the assignment before it (MultiUser scripts), and `WriteUninstaller
  "$2"` / an `UninstallString` of `"$2" $0` resolve through `$2`. A
  relative `WriteUninstaller` path is rooted at `$INSTDIR`.
- **Candidate choice follows the elevation model.** With several
  run-time folders, an installer that requests elevation or registers
  under HKLM takes the Program Files candidate; otherwise the per-user
  folder. `SHCTX` resolves to HKLM only when the script switches to the
  all-users context and elevates. A per-user folder picked from the
  candidates keeps its per-user meaning under `SetShellVarContext all`.
- **NSIS 2.x shell encoding.** The registry-resolved Program Files
  constant carries its flag in the high byte in the 2.x line; it decodes
  to `$PROGRAMFILES` / `$PROGRAMFILES64` instead of `$SHELL[..]`.
- **Install context** is decided by where the files land: a Program
  Files target is per-machine even when the script registers under HKCU.

## [1.3.0.0] - 2026-09-04

### Added

- **`Get-NsisMetadata`** - decodes the compiled script inside an NSIS
  installer instead of guessing from FileVersionInfo. Locates the
  firstheader, decompresses the header block (LZMA solid and non-solid
  via a self-contained decoder with BCJ x86 support, zlib via
  `DeflateStream`, uncompressed; bzip2 is reported as not decoded),
  decodes the Unicode or ANSI string table with its shell-folder,
  variable and LangString escapes, and walks the entry list in script
  order. Yields `InstallDir` (compile-time value, or the `StrCpy $INSTDIR`
  assignment that matches the ARP hive when the script chooses the folder
  in `.onInit`), the `WriteUninstaller` path, every value the script
  writes under `...\CurrentVersion\Uninstall\`, the ARP hive and 32/64-bit
  view as of that write (`SetRegView`), `SetShellVarContext`, the
  installer `Name`, and an `InstallContext` of PerUser or PerMachine.
  Paths are also rendered in Windows environment form
  (`%LOCALAPPDATA%\App\Uninstall.exe`, `%ProgramW6432%\...`) so the silent
  uninstall command is executable as emitted.
- **`Get-PeRequestedExecutionLevel`** - reads `requestedExecutionLevel`
  from a PE file's embedded manifest by walking the resource directory,
  without loading the image. Surfaced as `RequestedExecutionLevel` on
  `Get-InstallerFileInfo` for every `.exe` and as an `Elevation:` line in
  the summary.
- **`ConvertTo-NsisWindowsPath`** - rewrites NSIS folder constants to
  environment variables, honouring the all-users shell context.

### Changed

- **`Get-SilentSwitches`** gains `-PackageMetadata`; for NSIS the decoded
  uninstaller path replaces the bare `uninstall.exe` placeholder.
- **`Get-UninstallRegistryKey`** for NSIS returns the script-defined key,
  hive and note ahead of the DisplayName convention, including the
  WOW6432Node placement for 32-bit installers that never call
  `SetRegView 64`.
- **Overview and JSON** carry an NSIS package-metadata block (stream
  type, InstallDir, uninstaller, ARP hive and view, shell context, install
  context, run-time InstallDir candidates) and a detection hint keyed on
  the decoded ARP path. Dictionary-valued metadata renders one row per
  entry in the Overview grid.
- **All shipped PowerShell files are pure ASCII.**

## [1.2.0.1] - 2026-08-16

### Changed

- **Vendored `SuiteCommon` 0.3.2.** Window restore applies the saved
  geometry before maximizing, so un-maximizing returns to the saved size
  instead of the XAML defaults.

## [1.2.0.0] - 2026-08-16

### Changed

- **Window chrome, theming, and the message dialog now come from the
  vendored `SuiteCommon` module** (0.3.0), with this tool's border-based
  active-button visual preserved as the shared layer's Border mode.
  Behavior gains: hook state no longer leaks on window close, a
  maximized close persists the pre-maximize geometry, an off-screen
  saved position clamps into the nearest monitor, and Escape closes
  OK-only dialogs.

## [1.1.0.0] - 2026-08-14

### Changed

- **Shared plumbing moved to the vendored `SuiteCommon` module.** Logging
  (`Initialize-Logging`, `Write-Log`) and preference persistence now load
  from `Lib\SuiteCommon\`, shared across the tool suite and synced from
  the suite-core repository instead of hand-edited per repo.
- **ERROR log lines now reach stdout and stderr.** The previous local
  `Write-Log` sent ERROR lines to stderr only; the suite-wide contract
  writes every level to stdout and mirrors ERROR to stderr. File log
  format is unchanged. `Initialize-Logging` additionally gains `-Attach`.

## [1.0.0.0] - 2026-05-20

Initial public release.

### Installer formats detected

- Classic EXE: NSIS, Inno Setup, InstallShield, WiX Burn, 7-Zip SFX, BitRock
- MSI family: MSI, MSP
- Modern packages: MSIX / APPX (+ bundles), `.intunewin`, Chocolatey / NuGet `.nupkg`
- Script wrappers: PSAppDeployToolkit v3 + v4, Squirrel / Electron

### Overview

- Source facts: type, architecture, size, SHA-256, Authenticode status and signer.
- Deployment fields: DisplayName, DisplayVersion, Vendor, silent install /
  uninstall command lines, predicted ARP `UninstallRegistryKey` with
  WOW6432Node routing for 32-bit MSIs on x64 and HKCU routing for per-user.
- MSI properties: ProductCode, UpgradeCode, ProductVersion, Manufacturer,
  full Property table for MSI files and EXE wrappers with an embedded MSI.
- Per-type package metadata: nuspec for `.nupkg`, AppxManifest for
  MSIX / APPX, MsiPatchMetadata for MSP, `.wixburn` PE-section bundle ID
  for WiX Burn, Detection.xml for `.intunewin`.
- Effective post-patch detection target: when an outer file contains a
  base MSI plus a cumulative MSP, the analyzer combines the inner MSI's
  ProductCode with the MSP's `MsiPatchMetadata.DisplayName` to render
  the ARP key and DisplayVersion the patched product will write — no
  test install required.

### Inner Installers

A nav tab that classifies installer-class payload entries (inner MSI /
MSP / sub-EXE / CAB / `.nupkg`). Analyze Selected drills into a row;
breadcrumb bar shows `← Back` plus clickable ancestor segments. Open
in new window spawns a sibling analyzer. Drill depth caps at 5; temp
folder is wiped on shell close.

### Right-click

Context menus on the Payload grid, Inner Installers grid, and the path TextBox.

### Export

- Copy Summary (plain text), Copy JSON (MECM-ready detection digest).
- Export CSV, Export HTML.
- Extract Payload (full 7-Zip extraction).
