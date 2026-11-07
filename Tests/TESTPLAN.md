# Installer Analysis: test plan

Measured 2026-11-06 with `Invoke-Checks.ps1` (Pester 5.7.1, PSScriptAnalyzer 1.25.0). Counts are tests as run; each data row counts as one test. Coverage is the share of module commands that the tests run.

| | Before | After |
|---|---|---|
| Tests | 298 (`Module\InstallerAnalysisCommon.Tests.ps1`; `Tests\Smoke.Tests.ps1` was a script outside Pester) | 943 on Windows PowerShell 5.1 and on PowerShell 7 (1 skips when no real installers are present) |
| Module coverage | 82.0% (4257 of 5192 commands) | 90.0% (4694 of 5215 commands) |
| Lint | not enforced | 0 Error or Warning on every script, module and test file |
| Lab steps | none | none: the app reads installers and writes only local files, so it needs no ConfigMgr lab |

Run: `.\Invoke-Checks.ps1` (lint, tests, coverage floor 80%). It runs in CI on both hosts (`.github/workflows/checks.yml`).

## Defects found and fixed

Each defect has a failing test that was run against the code before the fix.

| # | Defect | Test | Fix |
|---|---|---|---|
| 1 | A payload extraction that 7-Zip ended with an error code still returned the folder, and the window logged "Extract Payload: complete." | `Module.Write.Tests.ps1` (Expand-InstallerPayload, fatal exit codes), `Shell.Logic.Tests.ps1` (Invoke-PayloadExtractAll) | Exit code 2 and above returns nothing; the window reports a failure in the log and the status bar, also when the call throws. Exit code 1 stays a warning. |
| 2 | Extracting one entry returned the newest file in the output folder when the expected file was missing, so a file from an earlier run was reported as the result (hash, analysis). | `Module.Write.Tests.ps1` (Expand-PayloadEntry) | The fallback considers only files that the run added. |
| 3 | The bundled MSI module was never used. `Import-Module MSI` by name fails when the shell loaded the module by path, and `Get-MSISummaryInfo` inside the module called the module's own `Get-MsiSummaryInfo` (command names ignore case). Every analysis logged two warnings and used Windows Installer. | `Module.Msi.Tests.ps1` (vendored MSI module) | Import only when not loaded; call `MSI\Get-MSISummaryInfo`. Results match Windows Installer on real MSI files. |
| 4 | The platform came from any "64" in the MSI Template, so a language id such as 2064 made a 32-bit package x64, and Arm64 packages were named x64. | `Module.Msi.Tests.ps1` (template cases) | Only the platform part before the semicolon decides; Arm64 is named arm64. |
| 5 | "Open in new window" passed paths to Start-Process without quotes, so a path with a space started the new window with the wrong arguments. The re-launch under STA at start-up had the same fault. | `Shell.Logic.Tests.ps1` (Open-EmbeddedInNewWindow, Start-up re-launch) | Both paths are quoted. |
| 6 | The CSV export wrote installer text that starts with =, +, - or @ as it was, which a spreadsheet runs as a formula. | `Module.Write.Tests.ps1` (Export-AnalysisReport) | Such a cell gets a leading single quote. A plain number stays. |
| 7 | The HTML export logged "Exported HTML" when the file could not be written. | `Module.Write.Tests.ps1` (Export-AnalysisHtml, cannot be written) | The write and the folder creation stop on error. |
| 8 | Lint: an empty catch block, and an assignment to the automatic variable `$args`. | `Invoke-Checks.ps1` lint step | `$null = $_` in the catch; the variable is renamed. |

## What is covered

| Area | File | Contents |
|---|---|---|
| Existing module tests | `Module\InstallerAnalysisCommon.Tests.ps1` | Logging, installer detection, switch database, NSIS and Inno Setup readers, strings, templates (tests that were in the repository before this work) |
| Write paths | `Module.Write.Tests.ps1` | Payload extraction, single-entry extraction, extraction by name list, payload listing, CSV and HTML export. 7z.exe is a .cmd stand-in. Success, failure, partial (exit code 1), missing tool, spaces and Unicode in names, hostile cell text |
| MSI | `Module.Msi.Tests.ps1` | Real MSI files built with Windows Installer: properties, summary, platform names, registry and remove-registry rows, value types, damaged files, the bundled MSI module |
| ZIP formats | `Module.Formats.Tests.ps1` | ZIP helpers, Chocolatey and NuGet (namespaces, byte order mark, bad XML), Intunewin (key redaction), type detection from archives, dispatcher |
| Text and JSON | `Module.Summary.Tests.ps1` | Summary text for each package type, post-patch detection target, JSON digest, inner installer classification, registry reader choice |
| Detection | `Module.Detection.Tests.ps1` | Uninstall key prediction for each installer type and the detection hint of the JSON |
| Binary headers | `Module.Binary.Tests.ps1` | PE machine types, truncated and hostile headers, MSIX package and bundle manifests, external entity in a manifest |
| Script logic | `Shell.Logic.Tests.ps1` | Functions of `start-installeranalysis.ps1` cut out by syntax tree and run with fake controls: preferences, views, grids, file browser, extraction, hashes, drill-down stack, temp folders, argument quoting |
| Script calls | `Script.Contract.Tests.ps1` | Every call from the script and the module into an app function or SuiteCommon names only parameters that exist |
| Release | `Release.Tests.ps1` | One version in the manifest, the script header and the CHANGELOG; manifest matches the module; every file parses; byte order mark for non-ASCII text |
| Smoke | `Smoke.Tests.ps1` | The old smoke script as a Pester file: module load, each ZIP format, core pipeline, optional real installers |
| Windows | `Window.Tests.ps1` | Main window with its seven views filled with sample rows: names, titles, dialog XAML, no clipped text and nothing off screen at 1024x720 and 1440x900 in both themes, text and control contrast |

## Not covered, and why

- Contrast of disabled controls, the sidebar button border and the light text boxes misses the standard (text 4.5:1, borders 3:1). The cause is the shared SuiteCommon palette and the MahApps styles. `Tests/KnownContrastDefects.ps1` lists each violation. The window test fails on a new one and on a listed one that is fixed. The fix belongs in `app-packager-suite`.
- `Get-MspMetadata`: a test needs a real patch file, which Windows Installer cannot write without a transform and a base package. The guard branches are covered.
- The NSIS and Inno Setup readers beyond the cases in the existing tests: they need compiled installers of many versions.
- WiX Burn, Squirrel and Velopack readers: the marker and header branches that need real setup files.
- Handlers that run inside the window (Browse, Options dialog, drag and drop, the analysis timer and the background runspace, the breadcrumb bar). They need a user at the window. The functions they call are tested.
- The settings save in SuiteCommon is not atomic. The fix belongs in `app-packager-suite`.
- Start-up without the ConfigMgr module and the ConfigMgr contract tests do not apply: the app never calls ConfigMgr.
- Lab run: not needed. The app reads installers and writes only to folders and files that the user picks.
