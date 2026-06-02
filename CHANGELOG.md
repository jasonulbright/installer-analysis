# Changelog

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