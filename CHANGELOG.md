# Changelog

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