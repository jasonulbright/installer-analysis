#Requires -Version 5.1
<#
.SYNOPSIS
    Installs Installer Analysis to %LOCALAPPDATA% and adds a Start Menu shortcut.

.DESCRIPTION
    Copies the application payload (Lib, Module, start-installeranalysis.ps1,
    README, CHANGELOG, LICENSE) to %LOCALAPPDATA%\InstallerAnalysis and creates
    a Start Menu shortcut that launches the WPF shell with -STA and
    -ExecutionPolicy Bypass.

    Run this script from the extracted release zip folder. No admin required.
    Re-running updates an existing install in place; Logs/, Reports/, and
    user prefs are preserved.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Interactive installer; Write-Host is the intended mechanism to surface progress to the user running install.ps1 from a console.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$here         = $PSScriptRoot
$target       = Join-Path $env:LOCALAPPDATA 'InstallerAnalysis'
$shortcutDir  = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$shortcutPath = Join-Path $shortcutDir 'Installer Analysis.lnk'
$startScript  = 'start-installeranalysis.ps1'
$payload      = @('Lib', 'Module', 'start-installeranalysis.ps1', 'README.md', 'CHANGELOG.md', 'LICENSE')

Write-Host "Installing Installer Analysis"
Write-Host "  Target:   $target"
Write-Host "  Shortcut: $shortcutPath"
Write-Host ''

# Preserve user data if this is an update.
$preserved = @('Logs', 'Reports')
if (Test-Path $target) {
    Write-Host 'Existing install detected; refreshing application files (user data preserved).'
    Get-ChildItem -LiteralPath $target -Force |
        Where-Object {
            ($_.Name -notin $preserved) -and
            ($_.Name -notmatch '\.(prefs|windowstate)\.json$')
        } |
        Remove-Item -Recurse -Force
} else {
    New-Item -ItemType Directory -Path $target -Force | Out-Null
}

foreach ($item in $payload) {
    $src = Join-Path $here $item
    if (Test-Path -LiteralPath $src) {
        Copy-Item -Path $src -Destination $target -Recurse -Force
    } else {
        Write-Warning "Payload item missing from release folder: $item"
    }
}

if (-not (Test-Path -LiteralPath $shortcutDir)) {
    New-Item -ItemType Directory -Path $shortcutDir -Force | Out-Null
}

$psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$targetScript = Join-Path $target $startScript

# Shortcut target uses -File (not -Command) per PS 5.1 exit-code rule (PS51-WPF-017).
$arguments = '-NoProfile -ExecutionPolicy Bypass -STA -File "{0}"' -f $targetScript

$shell = New-Object -ComObject WScript.Shell
$lnk   = $shell.CreateShortcut($shortcutPath)
$lnk.TargetPath       = $psExe
$lnk.Arguments        = $arguments
$lnk.WorkingDirectory = $target
$lnk.IconLocation     = (Join-Path $env:WINDIR 'System32\imageres.dll') + ',77'
$lnk.Description      = 'Installer Analysis -- crack open Windows installer packages'
$lnk.Save()

Write-Host ''
Write-Host 'Installed.'
Write-Host "  Application: $target"
Write-Host "  Shortcut:    $shortcutPath"
Write-Host ''
Write-Host 'Launch from the Start Menu, or run:'
Write-Host "  powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File `"$targetScript`""
