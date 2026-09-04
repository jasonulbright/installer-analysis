# Sources and Public Precedents

Every capability this repository exposes corresponds to a publicly
documented precedent on GitHub, almost always owned by the format's
vendor or by a long-standing community project. This file maps each
function to its precedent. Every entry below was verified directly
against the linked repository.

This tool is integration work: a PowerShell + WPF UI over format reads
that the upstream owners of each format already publish themselves.

## Per-extractor precedent map

| Function in this repo | Capability | Public precedent (GitHub) | Precedent license | Authority |
|---|---|---|---|---|
| `Get-ChocolateyMetadata` | Read `.nuspec` from a `.nupkg` ZIP | [NuGet/NuGet.Client](https://github.com/NuGet/NuGet.Client) — official .NET Foundation NuGet client | Apache 2.0 | Vendor (NuGet team) |
| `Get-ChocolateyMetadata` | Same (Chocolatey emitter / consumer) | [chocolatey/choco](https://github.com/chocolatey/choco) — official Chocolatey CLI | Apache 2.0 | Vendor (Chocolatey team) |
| `Get-IntunewinMetadata` | Parse unencrypted `IntuneWinPackage/Metadata/Detection.xml` from a `.intunewin` ZIP | [MSEndpointMgr/IntuneWin32App](https://github.com/MSEndpointMgr/IntuneWin32App) — `Expand-IntuneWin32AppPackage` reads Detection.xml for the encryption metadata | MIT | Community standard |
| `Get-IntunewinMetadata` | Same (long-standing community decoder) | [okieselbach/Intune](https://github.com/okieselbach/Intune/tree/master/IntuneWinAppUtilDecoder) — Oliver Kieselbach's `IntuneWinAppUtilDecoder` | See repo | Community standard |
| `Get-IntunewinMetadata` | Format authority (create side) | [microsoft/Microsoft-Win32-Content-Prep-Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool) — the tool that creates `.intunewin` files | Microsoft proprietary | Vendor (Microsoft Intune team) |
| `Get-MsixManifest`, `ConvertFrom-MsixPackageManifest` | Read `AppxManifest.xml` from an MSIX / APPX ZIP | [microsoft/msix-packaging](https://github.com/microsoft/msix-packaging) — official MSIX SDK | MIT | Vendor (Microsoft) |
| `Get-MsixManifest`, `ConvertFrom-MsixBundleManifest` | Read `AppxBundleManifest.xml` from a bundle ZIP | [microsoft/msix-packaging](https://github.com/microsoft/msix-packaging) | MIT | Vendor (Microsoft) |
| `Get-PsadtMetadata`, `ConvertFrom-PsadtDeployApplication` | Detect PSADT v3 / v4 sentinel files and read `appVendor` / `appName` / `appVersion` / `appArch` / `appLang` / `appRevision` from the deployment script | [PSAppDeployToolkit/PSAppDeployToolkit](https://github.com/PSAppDeployToolkit/PSAppDeployToolkit) — official toolkit | LGPL | Vendor (PSADT team) |
| `Get-SquirrelMetadata` | Scan early bytes of EXE for `Squirrel`, `SquirrelTemp`, `Update.exe`, `RELEASES` markers | [Squirrel/Squirrel.Windows](https://github.com/Squirrel/Squirrel.Windows) — official framework that emits those markers | MIT | Vendor (Squirrel team) |
| `Get-SquirrelMetadata` | Alternate emitter | [electron-userland/electron-builder](https://github.com/electron-userland/electron-builder) — produces Squirrel.Windows targets | MIT | Community standard |
| `Get-MsiProperties` | `SELECT Property, Value FROM Property` via `WindowsInstaller.Installer` COM | [heaths/psmsi](https://github.com/heaths/psmsi) — canonical PowerShell MSI module by Heath Stewart (Microsoft engineer), on the PowerShell Gallery | MIT | Canonical reference |
| `Get-MsiProperties`, `Get-MsiSummaryInfo` | Same capability via the DTF library | [wixtoolset/wix](https://github.com/wixtoolset/wix) — `Microsoft.Deployment.WindowsInstaller` (DTF) is the canonical .NET wrapper around the same COM API | MS-RL | Vendor (WiX Toolset team) |
| `Get-MspMetadata` | Read MSP `SummaryInformation` + `MsiPatchMetadata` table via the same COM | [heaths/psmsi](https://github.com/heaths/psmsi) | MIT | Canonical reference |
| `Get-WixBurnMetadata` | Parse the `.wixburn` PE section's `BURN_SECTION` header to extract the BundleId GUID | [wixtoolset/wix](https://github.com/wixtoolset/wix/blob/main/src/burn/stub/StubSection.cpp) — `StubSection.cpp` declares the `.wixburn` PE section via `#pragma section`; the full `BURN_SECTION` struct lives in the burn engine headers in the same repo | MS-RL | Vendor (WiX Toolset team) |
| `Get-WixBurnMetadata` | PE / COFF header parsing in .NET | [dotnet/runtime](https://github.com/dotnet/runtime) — `System.Reflection.PortableExecutable.PEReader` ships in the .NET BCL | MIT | Vendor (.NET Foundation) |
| `Get-PayloadContents`, `Find-7ZipPath`, `Expand-InstallerPayload` | List / extract any supported archive via the 7-Zip CLI | [7-zip.org](https://7-zip.org) (official source; community mirrors on GitHub include [mcmilk/7-Zip](https://github.com/mcmilk/7-Zip)) | LGPL-2.1 + unRAR + BSD-3 | Vendor (Igor Pavlov / 7-Zip project) |
| `Get-NsisMetadata` | Locate the NSIS firstheader, decompress the header block, decode the string table and walk the entry list (`InstallDir`, `WriteUninstaller`, `WriteRegStr`, `SetRegView`, `SetShellVarContext`) | [kichik/nsis](https://github.com/kichik/nsis) — `Source/exehead/fileform.h` (firstheader, header, block and entry layouts, opcode numbering), `Source/exehead/util.c` (string escape decoding), `Source/build.cpp` (shell-constant encoding) | zlib/libpng | Vendor (NSIS project) |
| `Get-NsisMetadata` | Same read implemented as an archive handler | [mcmilk/7-Zip](https://github.com/mcmilk/7-Zip/blob/master/CPP/7zip/Archive/Nsis/NsisIn.cpp) — 7-Zip's `NsisIn.cpp` performs the same firstheader search, stream-type detection and string decoding | LGPL-2.1 | Vendor (Igor Pavlov / 7-Zip project) |
| `Get-NsisMetadata` | LZMA1 range decoder and BCJ x86 filter used on the header stream | [LZMA SDK](https://7-zip.org/sdk.html) — `LzmaSpec.cpp` reference decoder and `Bra86.c`, public domain; the C# port in this module follows those files | Public domain | Vendor (Igor Pavlov) |
| `Get-PeRequestedExecutionLevel` | Walk the PE resource directory to `RT_MANIFEST` and read `requestedExecutionLevel` | [dotnet/runtime](https://github.com/dotnet/runtime) — `System.Reflection.PortableExecutable` documents the section table and resource directory layout; [MicrosoftDocs/win32](https://github.com/MicrosoftDocs/win32) — PE format and application manifest reference | MIT / CC-BY | Vendor (Microsoft) |
| `Get-InnoSetupMetadata` | Locate the SetupLdr offset table (RCDATA 11111, revision 1 and 2), read the setup-0 block (CRC-chunked, LZMA1) and parse the leading `TSetupHeader` record (AppId, AppName, AppVersion, DefaultDirName, UninstallFilesDir, PrivilegesRequired, PrivilegesRequiredOverridesAllowed, ArchitecturesInstallIn64BitMode) by data version 5.x through 7.0.0.3 | [jrsoftware/issrc](https://github.com/jrsoftware/issrc) - `Projects/Src/Shared.Struct.pas` (`TSetupHeader`, `TSetupLdrOffsetTable`, `TSetupEncryptionHeader` per tag), `Projects/Src/Compression.Base.pas` (`TCompressedBlockHeader`, chunk CRC layout), `Projects/Src/Setup.MainFunc.pas` (setup-0 read order) | Inno Setup License (BSD-style) | Vendor (Jordan Russell) |
| `Get-InnoSetupMetadata` | Version-conditional field layout for data versions before 6.4 | [dscharrer/innoextract](https://github.com/dscharrer/innoextract) - `src/setup/header.cpp` (field order by version), `src/stream/block.cpp` (block reader), `src/loader/offsets.cpp` (loader table magics) | zlib/libpng | Canonical reference (layout only; no code copied) |

## UI dependencies (vendored as binaries under `Lib\`)

Full attribution lives in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
The precedent maps are:

| Dependency | Repository | License |
|---|---|---|
| MahApps.Metro | [MahApps/MahApps.Metro](https://github.com/MahApps/MahApps.Metro) | MIT |
| ControlzEx | [ControlzEx/ControlzEx](https://github.com/ControlzEx/ControlzEx) | MIT |
| Microsoft.Xaml.Behaviors | [microsoft/XamlBehaviorsWpf](https://github.com/microsoft/XamlBehaviorsWpf) | MIT |
| Windows Installer PowerShell Module (MSI / DTF) | [heaths/psmsi](https://github.com/heaths/psmsi) | MIT |

## License diversity across precedents

Apache 2.0, MIT, LGPL, MS-RL, and LGPL-2.1+unRAR+BSD-3 are all
represented. All are OSI-approved or industry-standard licenses. This
repository vendors only the four MIT components listed under "UI
dependencies"; every other capability is implemented in this repo's
own PowerShell source, against the same documented format the
precedent repository documents and consumes.

## Scope (also stated in [README.md](README.md))

This tool reads installer metadata only. It does not:

- Bypass product licensing.
- Generate, recover, or distribute license keys.
- Remove or bypass activation checks.
- Decrypt protected payloads — `.intunewin` AES content stays
  encrypted; only the unencrypted `Detection.xml` is read, and
  key-shaped fields are redacted in the default JSON export.
- Redistribute third-party installer content.
- Make network calls.

Operates offline against installers the user already possesses.
