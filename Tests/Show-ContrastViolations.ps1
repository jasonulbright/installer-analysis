<#
.SYNOPSIS
    Prints the contrast violations of the main window in both themes, in the
    format of KnownContrastDefects.ps1.

.DESCRIPTION
    Run it when the window test reports a new or a fixed violation, to see the
    current list. Opens the window off screen at 1440x900, as Window.Tests.ps1 does.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Console tool.')]
param()
. "$PSScriptRoot\WindowHarness.ps1"
. "$PSScriptRoot\WindowConfig.ps1"
. "$PSScriptRoot\KnownContrastDefects.ps1"
try {
    foreach ($dark in $true, $false) {
        $r = Invoke-WpfSta -Arguments @{ Dark = $dark; Config = $script:AppConfig } -Script {
            $cfg = $Arguments.Config
            $w = Open-TestWindow -XamlPath (Join-Path $Root $cfg.Xaml) -Dark $Arguments.Dark -PopulateScript $cfg.PopulateScript
            $out = @()
            foreach ($view in $cfg.Views) {
                foreach ($v in $cfg.Views) { $w.FindName($v.Container).Visibility = if ($v.Name -eq $view.Name) { 'Visible' } else { 'Collapsed' } }
                Initialize-ShellTheme -Window $w -Dark $Arguments.Dark -Views $cfg.Views -OptionsButtonName $cfg.OptionsButton -LogLabelName $cfg.LogLabel -ActiveView $view.Name -ActiveMode $cfg.ActiveMode
                $out += [PSCustomObject]@{ Text = @(Get-TextContrast $w); Interactive = @(Get-InteractiveContrast $w); TitleBar = Get-TitleBarContrast $w }
            }
            $w.Close(); , $out
        }
        $keys = Get-ContrastViolationKey -Views @($r)
        Write-Host ("== {0}" -f $(if ($dark) { 'dark' } else { 'light' }))
        Write-Host (($keys | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', ')
    }
}
finally { Close-WpfSession }
