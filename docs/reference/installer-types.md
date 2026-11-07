# Installer types

This page lists the installer formats that Installer Analysis detects.

## What it does

The tool finds the type from binary signatures and the layout of ZIP files. It also uses the file extension for `.msi` and `.msp`, and for some ZIP-based formats. The type is a detection. It is not a validation of the signature of the file.

## When to use it

Use it to find out whether the tool knows your file, and what data it reads for the type.

## Requirements

None.

## Types

| Group | Formats |
|---|---|
| Classic EXE | NSIS, Inno Setup, InstallShield, WiX Burn, Advanced Installer, WinRAR SFX, 7-Zip SFX, BitRock |
| MSI family | MSI, MSP (Windows Installer patch) |
| Modern packages | MSIX and APPX (and bundles), `.intunewin`, Chocolatey or NuGet `.nupkg` |
| Script wrappers | PSAppDeployToolkit version 3 and 4, Squirrel or Electron, Velopack |

A file of another kind shows the type `Unknown`. The Overview then shows the version data of the file.

## What the tool reads for a type

- NSIS: the compiled script header, for example the install folder, the uninstaller path and the Add/Remove Programs values.
- Inno Setup: the compiled `[Setup]` header, for example the application ID, the version, the folder and the privilege level.
- WiX Burn: the `.wixburn` section.
- MSI: the property tables. MSP: the patch metadata. The tool infers a version from the patch metadata. This is not a calculation or a verification of the product data after the patch is applied.
- `.nupkg`: the nuspec. MSIX: the manifest.
- Velopack: the embedded nuspec, without 7-Zip.

## Steps

None.

## Limits

- The tool does not decrypt protected data. An encrypted Inno Setup header and an encrypted `.intunewin` payload are reported as such.
- The tool does not bypass licensing or activation.

## Troubleshooting

| Message or symptom | Cause | Fix |
|---|---|---|
| The type is `Unknown`. | The file is not one of the types above, or it is an uninstaller. | Open the setup file of the product. |

## Links

- [Overview](../core/overview.md)
- [Glossary](glossary.md)
