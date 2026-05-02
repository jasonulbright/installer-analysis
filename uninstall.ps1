#Requires -Version 5.1
<#
.SYNOPSIS
    Removes Installer Analysis from %LOCALAPPDATA% and deletes the Start Menu shortcut.

.DESCRIPTION
    Removes application files from %LOCALAPPDATA%\InstallerAnalysis and the
    Start Menu shortcut. By default, Logs/, Reports/, and user prefs are
    preserved. Pass -PurgeData to remove them too.

    No admin required.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1 -PurgeData
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Interactive uninstaller; Write-Host is the intended mechanism to surface progress to the user running uninstall.ps1 from a console.')]
[CmdletBinding()]
param(
    [switch]$PurgeData
)

$ErrorActionPreference = 'Stop'

$target       = Join-Path $env:LOCALAPPDATA 'InstallerAnalysis'
$shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Installer Analysis.lnk'
$preserved    = @('Logs', 'Reports')

if (Test-Path -LiteralPath $shortcutPath) {
    Remove-Item -LiteralPath $shortcutPath -Force
    Write-Host "Removed shortcut: $shortcutPath"
}

if (Test-Path -LiteralPath $target) {
    if ($PurgeData) {
        Remove-Item -LiteralPath $target -Recurse -Force
        Write-Host "Removed application and data: $target"
    } else {
        Get-ChildItem -LiteralPath $target -Force |
            Where-Object {
                ($_.Name -notin $preserved) -and
                ($_.Name -notmatch '\.(prefs|windowstate)\.json$')
            } |
            Remove-Item -Recurse -Force
        Write-Host "Removed application files from: $target"
        Write-Host 'Kept: Logs/, Reports/, user prefs.  Pass -PurgeData to remove them too.'
    }
} else {
    Write-Host "Not installed at: $target"
}
