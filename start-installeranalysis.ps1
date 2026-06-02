<#
.SYNOPSIS
    MahApps.Metro WPF shell for the Installer Analysis tool.

.DESCRIPTION
    Loads MainWindow.xaml and wires the analysis pipeline behind it: drag-
    drop, Browse, file-path entry, the per-tab views (Overview text,
    MSI Properties grid, Payload grid, Inner Installers grid, Strings grid
    with filter), the action bar (Copy / Export / Extract), the Options
    window, and the crash handlers.

    Requirements:
      - PowerShell 5.1
      - .NET Framework 4.7.2+
      - MahApps.Metro DLLs in .\Lib\
      - InstallerAnalysisCommon module under .\Module\

.NOTES
    ScriptName : start-installeranalysis.ps1
    Version    : 1.0.0.0
    Updated    : 2026-05-20
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification='Flat-.ps1 GetNewClosure strips $script: access; $global: survives closure scope-strip and keeps shared mutable state (Prefs, PrefsPath, crash log scriptblock) reachable from closure-captured handlers.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='WPF event handler scriptblocks bind positional sender/args ($s, $e). The sender is required to fulfill the signature even when the handler body does not read it.')]
[CmdletBinding()]
param(
    # Optional startup file: pre-populates the path TextBox and auto-invokes
    # the analyze pipeline on window load. Useful for scripted automation and
    # quick-launch shortcuts.
    [string]$StartupFile = ''
)

$ErrorActionPreference = 'Stop'

# =============================================================================
# Startup transcript (best-effort).
# =============================================================================
$__txDir = Join-Path $PSScriptRoot 'Logs'
try {
    if (-not (Test-Path -LiteralPath $__txDir)) { New-Item -ItemType Directory -Path $__txDir -Force | Out-Null }
    $__tx = Join-Path $__txDir ('InstallerAnalysis-startup-{0}.txt' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Start-Transcript -LiteralPath $__tx -Force | Out-Null
} catch { $null = $_ }

# =============================================================================
# STA guard. Re-spawn under -STA when launched MTA.
# =============================================================================
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $psExe = (Get-Process -Id $PID).Path
    # -ExecutionPolicy Bypass here re-spawns this same script under the current
    # user. It does not change system-wide execution policy and does not lower
    # any other security boundary -- WPF requires an STA apartment, so this is
    # a self-relaunch of the script the user already chose to run.
    $fwd   = @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',$PSCommandPath)
    if (-not [string]::IsNullOrWhiteSpace($StartupFile)) { $fwd += @('-StartupFile', $StartupFile) }
    Start-Process -FilePath $psExe -ArgumentList $fwd | Out-Null
    try { Stop-Transcript | Out-Null } catch { $null = $_ }
    exit 0
}

# =============================================================================
# Assemblies.
# =============================================================================
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

$libDir = Join-Path $PSScriptRoot 'Lib'
if (-not (Test-Path -LiteralPath $libDir)) {
    throw "Lib/ directory not found at: $libDir. Run install.ps1, or re-extract the release zip."
}

Get-ChildItem -LiteralPath $libDir -File -ErrorAction SilentlyContinue |
    Unblock-File -ErrorAction SilentlyContinue

[void][System.Reflection.Assembly]::LoadFrom((Join-Path $libDir 'Microsoft.Xaml.Behaviors.dll'))
[void][System.Reflection.Assembly]::LoadFrom((Join-Path $libDir 'ControlzEx.dll'))
[void][System.Reflection.Assembly]::LoadFrom((Join-Path $libDir 'MahApps.Metro.dll'))

# Vendored PSGallery MSI module (heaths/psmsi, MIT). Lib/MSI/<version>/MSI.psd1.
# Import is best-effort: if it fails for any reason, Get-MsiProperties falls
# back to the WindowsInstaller COM path (see Module/InstallerAnalysisCommon.psm1).
$__msiManifest = Get-ChildItem -Path (Join-Path $libDir 'MSI') -Recurse -Filter 'MSI.psd1' -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($__msiManifest) {
    try {
        Import-Module -Name $__msiManifest.FullName -Force -DisableNameChecking -ErrorAction Stop
    } catch { $null = $_ }
}

# =============================================================================
# Module import (fail loud).
# =============================================================================
$__modulePath = Join-Path $PSScriptRoot 'Module\InstallerAnalysisCommon.psd1'
if (-not (Test-Path -LiteralPath $__modulePath)) {
    throw "Shared module not found at: $__modulePath"
}
Import-Module -Name $__modulePath -Force -DisableNameChecking
if (-not (Get-Command Initialize-Logging -ErrorAction SilentlyContinue)) {
    throw "InstallerAnalysisCommon imported but Initialize-Logging is not exported. Check Module/InstallerAnalysisCommon.psd1."
}

# =============================================================================
# Preferences. $global: scope keeps prefs reachable from closure-captured
# handlers.
# =============================================================================
$global:PrefsPath = Join-Path $PSScriptRoot 'InstallerAnalysis.prefs.json'

function Get-IatPreferences {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns the full preferences hashtable by design; singular would imply a single-key lookup.')]
    param()

    $defaults = @{
        DarkMode       = $true
        SevenZipPath   = ''
        LastBrowseDir  = ''
        ReportsFolder  = ''
    }
    if (Test-Path -LiteralPath $global:PrefsPath) {
        try {
            $loaded = Get-Content -LiteralPath $global:PrefsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            foreach ($k in @($defaults.Keys)) {
                $val = $loaded.$k
                if ($null -ne $val) { $defaults[$k] = $val }
            }
        } catch { $null = $_ }
    }
    return $defaults
}

function Save-IatPreferences {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Writes the full preferences hashtable by design.')]
    param([Parameter(Mandatory)][hashtable]$Prefs)

    try {
        $Prefs | ConvertTo-Json | Set-Content -LiteralPath $global:PrefsPath -Encoding UTF8
    } catch { $null = $_ }
}

$global:Prefs = Get-IatPreferences

# =============================================================================
# Tool log (per-session file + in-app log drawer).
# =============================================================================
$toolLogPath = Join-Path $__txDir ('InstallerAnalysis-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Initialize-Logging -LogPath $toolLogPath

# =============================================================================
# Load XAML and resolve named elements.
# =============================================================================
$xamlPath = Join-Path $PSScriptRoot 'MainWindow.xaml'
if (-not (Test-Path -LiteralPath $xamlPath)) {
    throw "MainWindow.xaml not found at: $xamlPath"
}
[xml]$xaml = Get-Content -LiteralPath $xamlPath -Raw
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# =============================================================================
# Title-bar drag fallback. WM_NCHITTEST hook + DragMove fallback for hosts
# where HwndSource cannot be hooked. Wire on every MetroWindow.
# =============================================================================
$script:TitleBarHitTestWindows = @{}
$script:TitleBarHitTestHooks   = @{}

function Get-TitleBarDragHeight {
    param([MahApps.Metro.Controls.MetroWindow]$Window)
    try {
        $h = [double]$Window.TitleBarHeight
        if ($h -gt 0 -and -not [double]::IsNaN($h)) { return $h }
    } catch { $null = $_ }
    return 30.0
}

function Get-InputAncestors {
    param([System.Windows.DependencyObject]$Start)
    $cur = $Start
    while ($cur) {
        $cur
        $parent = $null
        if ($cur -is [System.Windows.Media.Visual] -or $cur -is [System.Windows.Media.Media3D.Visual3D]) {
            try { $parent = [System.Windows.Media.VisualTreeHelper]::GetParent($cur) } catch { $parent = $null }
        }
        if (-not $parent -and $cur -is [System.Windows.FrameworkElement]) { $parent = $cur.Parent }
        if (-not $parent -and $cur -is [System.Windows.FrameworkContentElement]) { $parent = $cur.Parent }
        if (-not $parent -and $cur -is [System.Windows.ContentElement]) {
            try { $parent = [System.Windows.ContentOperations]::GetParent($cur) } catch { $parent = $null }
        }
        $cur = $parent
    }
}

function Test-IsWindowCommandPoint {
    param([MahApps.Metro.Controls.MetroWindow]$Window, [System.Windows.Point]$Point)
    try {
        [void]$Window.ApplyTemplate()
        $commands = $Window.Template.FindName('PART_WindowButtonCommands', $Window)
        if ($commands -and $commands.IsVisible -and $commands.ActualWidth -gt 0 -and $commands.ActualHeight -gt 0) {
            $origin = $commands.TransformToAncestor($Window).Transform([System.Windows.Point]::new(0, 0))
            if ($Point.X -ge $origin.X -and $Point.X -le ($origin.X + $commands.ActualWidth) -and
                $Point.Y -ge $origin.Y -and $Point.Y -le ($origin.Y + $commands.ActualHeight)) {
                return $true
            }
        }
    } catch { $null = $_ }
    return ($Window.ActualWidth -gt 150 -and $Point.X -ge ($Window.ActualWidth - 150))
}

function Add-NativeTitleBarHitTestHook {
    param([MahApps.Metro.Controls.MetroWindow]$Window)
    try {
        $helper = [System.Windows.Interop.WindowInteropHelper]::new($Window)
        $source = [System.Windows.Interop.HwndSource]::FromHwnd($helper.Handle)
        if (-not $source) { return }
        $key = $helper.Handle.ToInt64().ToString()
        if ($script:TitleBarHitTestHooks.ContainsKey($key)) { return }
        $script:TitleBarHitTestWindows[$key] = $Window
        $hook = [System.Windows.Interop.HwndSourceHook]{
            param([IntPtr]$hwnd, [int]$msg, [IntPtr]$wParam, [IntPtr]$lParam, [ref]$handled)
            $WM_NCHITTEST = 0x0084; $HTCAPTION = 2
            if ($msg -ne $WM_NCHITTEST) { return [IntPtr]::Zero }
            try {
                $target = $script:TitleBarHitTestWindows[$hwnd.ToInt64().ToString()]
                if (-not $target) { return [IntPtr]::Zero }
                $raw = $lParam.ToInt64()
                $screenX = [int]($raw -band 0xffff); if ($screenX -ge 0x8000) { $screenX -= 0x10000 }
                $screenY = [int](($raw -shr 16) -band 0xffff); if ($screenY -ge 0x8000) { $screenY -= 0x10000 }
                $pt = $target.PointFromScreen([System.Windows.Point]::new($screenX, $screenY))
                $titleBarH = Get-TitleBarDragHeight -Window $target
                if ($pt.X -lt 0 -or $pt.X -gt $target.ActualWidth) { return [IntPtr]::Zero }
                if ($pt.Y -lt 4 -or $pt.Y -gt $titleBarH) { return [IntPtr]::Zero }
                if (Test-IsWindowCommandPoint -Window $target -Point $pt) { return [IntPtr]::Zero }
                $handled.Value = $true
                return [IntPtr]$HTCAPTION
            } catch { return [IntPtr]::Zero }
        }
        $script:TitleBarHitTestHooks[$key] = $hook
        $source.AddHook($hook)
    } catch { $null = $_ }
}

function Remove-NativeTitleBarHitTestHook {
    param([MahApps.Metro.Controls.MetroWindow]$Window)
    try {
        $helper = [System.Windows.Interop.WindowInteropHelper]::new($Window)
        $key = $helper.Handle.ToInt64().ToString()
        if ($script:TitleBarHitTestHooks.ContainsKey($key)) {
            $source = [System.Windows.Interop.HwndSource]::FromHwnd($helper.Handle)
            if ($source) { $source.RemoveHook($script:TitleBarHitTestHooks[$key]) }
            $script:TitleBarHitTestHooks.Remove($key)
        }
        if ($script:TitleBarHitTestWindows.ContainsKey($key)) {
            $script:TitleBarHitTestWindows.Remove($key)
        }
    } catch { $null = $_ }
}

function Install-TitleBarDragFallback {
    param([MahApps.Metro.Controls.MetroWindow]$Window)
    $Window.Add_SourceInitialized({ param($s, $e) Add-NativeTitleBarHitTestHook -Window $s })
    $Window.Add_Closed({ param($s, $e) Remove-NativeTitleBarHitTestHook -Window $s })
    $Window.Add_PreviewMouseLeftButtonDown({
        param($s, $e)
        try {
            if ($s.WindowState -eq [System.Windows.WindowState]::Maximized) { return }
            $titleBarH = Get-TitleBarDragHeight -Window $s
            $pos = $e.GetPosition($s)
            if ($pos.Y -lt 4 -or $pos.Y -gt $titleBarH) { return }
            if (Test-IsWindowCommandPoint -Window $s -Point $pos) { return }
            foreach ($ancestor in Get-InputAncestors -Start ($e.OriginalSource -as [System.Windows.DependencyObject])) {
                if ($ancestor -is [System.Windows.Controls.Primitives.ButtonBase]) { return }
            }
            $s.DragMove()
            $e.Handled = $true
        } catch { $null = $_ }
    })
}

Install-TitleBarDragFallback -Window $window

$txtAppTitle        = $window.FindName('txtAppTitle')
$txtVersion         = $window.FindName('txtVersion')
$txtThemeLabel      = $window.FindName('txtThemeLabel')
$toggleTheme        = $window.FindName('toggleTheme')

$btnViewOverview    = $window.FindName('btnViewOverview')
$btnViewMsi         = $window.FindName('btnViewMsi')
$btnViewPayload     = $window.FindName('btnViewPayload')
$btnViewEmbedded    = $window.FindName('btnViewEmbedded')
$btnViewStrings     = $window.FindName('btnViewStrings')

$btnOptions         = $window.FindName('btnOptions')

$txtModuleTitle     = $window.FindName('txtModuleTitle')
$txtModuleSubtitle  = $window.FindName('txtModuleSubtitle')
$txtFilePath        = $window.FindName('txtFilePath')
$btnBrowse          = $window.FindName('btnBrowse')

$actionBar          = $window.FindName('actionBar')
$btnCopySummary     = $window.FindName('btnCopySummary')
$btnCopyJson        = $window.FindName('btnCopyJson')
$btnExportCsv       = $window.FindName('btnExportCsv')
$btnExportHtml      = $window.FindName('btnExportHtml')
$btnExtractAll      = $window.FindName('btnExtractAll')

$viewHost           = $window.FindName('viewHost')
$dropOverlay        = $window.FindName('dropOverlay')
$progressOverlay    = $window.FindName('progressOverlay')
$txtProgressTitle   = $window.FindName('txtProgressTitle')
$txtProgressStep    = $window.FindName('txtProgressStep')
$txtOverview        = $window.FindName('txtOverview')
$gridMsi            = $window.FindName('gridMsi')
$gridPayload        = $window.FindName('gridPayload')
$panelStrings       = $window.FindName('panelStrings')
$gridStrings        = $window.FindName('gridStrings')
$txtStringsFilter   = $window.FindName('txtStringsFilter')

$panelEmbedded      = $window.FindName('panelEmbedded')
$gridEmbedded       = $window.FindName('gridEmbedded')
$btnExtractAllInner       = $window.FindName('btnExtractAllInner')
$btnAnalyzeSelectedInner  = $window.FindName('btnAnalyzeSelectedInner')
$btnOpenInNewWindow       = $window.FindName('btnOpenInNewWindow')

$breadcrumbBar      = $window.FindName('breadcrumbBar')
$breadcrumbSegments = $window.FindName('breadcrumbSegments')
$btnBreadcrumbBack  = $window.FindName('btnBreadcrumbBack')

$ctxPayloadExtractTemp = $window.FindName('ctxPayloadExtractTemp')
$ctxPayloadCopyName    = $window.FindName('ctxPayloadCopyName')
$ctxPayloadCopyPath    = $window.FindName('ctxPayloadCopyPath')
$ctxPayloadHash        = $window.FindName('ctxPayloadHash')

$ctxEmbAnalyze     = $window.FindName('ctxEmbAnalyze')
$ctxEmbOpenNew     = $window.FindName('ctxEmbOpenNew')
$ctxEmbExtractTemp = $window.FindName('ctxEmbExtractTemp')
$ctxEmbCopyName    = $window.FindName('ctxEmbCopyName')
$ctxEmbCopyPath    = $window.FindName('ctxEmbCopyPath')
$ctxEmbHash        = $window.FindName('ctxEmbHash')

$ctxPathCopyPath   = $window.FindName('ctxPathCopyPath')
$ctxPathOpenFolder = $window.FindName('ctxPathOpenFolder')
$ctxPathReanalyze  = $window.FindName('ctxPathReanalyze')

$lblLogOutput       = $window.FindName('lblLogOutput')
$txtLog             = $window.FindName('txtLog')
$txtStatus          = $window.FindName('txtStatus')

# Silence PSSA about FindName locals consumed via their typed control refs.
$null = $txtAppTitle, $txtVersion, $viewHost

# =============================================================================
# Log drawer + status bar helpers.
# =============================================================================
function Add-LogLine {
    param([Parameter(Mandatory)][string]$Message)

    $ts = (Get-Date).ToString('HH:mm:ss')
    $line = '{0}  {1}' -f $ts, $Message

    if ([string]::IsNullOrWhiteSpace($txtLog.Text)) {
        $txtLog.Text = $line
    } else {
        $txtLog.AppendText([Environment]::NewLine + $line)
    }
    $txtLog.ScrollToEnd()
}

function Set-StatusText {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Updates an in-window TextBlock only; no external state.')]
    param([Parameter(Mandatory)][string]$Text)

    $txtStatus.Text = $Text
}

# =============================================================================
# Theme setup and toggle. Runtime color swap on sidebar buttons + title bar
# + LOG OUTPUT label.
# =============================================================================
[void][ControlzEx.Theming.ThemeManager]::Current.ChangeTheme($window, 'Dark.Steel')

$script:DarkButtonBg       = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#1E1E1E')
$script:DarkButtonBorder   = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#555555')
$script:DarkActiveBorder   = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#F9F9F9')
$script:LightWfBg          = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#0078D4')
$script:LightWfBorder      = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#006CBE')
$script:LightActiveBorder  = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#FFFFFF')

$script:TitleBarBlue         = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#0078D4')
$script:TitleBarBlueInactive = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#4BA3E0')

$script:LogLabelDark  = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#B0B0B0')
$script:LogLabelLight = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#595959')

$script:ViewButtons = @(
    @{ Name = 'Overview';         Button = $btnViewOverview },
    @{ Name = 'MSI Properties';   Button = $btnViewMsi      },
    @{ Name = 'Payload';          Button = $btnViewPayload  },
    @{ Name = 'Inner Installers'; Button = $btnViewEmbedded },
    @{ Name = 'Strings';          Button = $btnViewStrings  }
)

$script:ActiveView = 'Overview'

function Update-SidebarButtonTheme {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Mutates in-window brush properties only; no external state.')]
    param()

    $isDark = [bool]$global:Prefs['DarkMode']
    $bg           = if ($isDark) { $script:DarkButtonBg }      else { $script:LightWfBg }
    $border       = if ($isDark) { $script:DarkButtonBorder }  else { $script:LightWfBorder }
    $activeBorder = if ($isDark) { $script:DarkActiveBorder }  else { $script:LightActiveBorder }
    $thickness    = [System.Windows.Thickness]::new(1)

    # Active-state visual is BorderBrush color only; thickness stays at 1px.
    foreach ($v in $script:ViewButtons) {
        if (-not $v.Button) { continue }
        $v.Button.Background      = $bg
        $v.Button.BorderBrush     = if ($v.Name -eq $script:ActiveView) { $activeBorder } else { $border }
        $v.Button.BorderThickness = $thickness
    }
    if ($btnOptions) {
        $btnOptions.Background      = $bg
        $btnOptions.BorderBrush     = $border
        $btnOptions.BorderThickness = $thickness
    }
    if ($lblLogOutput) {
        $lblLogOutput.Foreground = if ($isDark) { $script:LogLabelDark } else { $script:LogLabelLight }
    }
}

function Update-TitleBarBrushes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Mutates in-window brush properties only; no external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Sets both the WindowTitleBrush and NonActiveWindowTitleBrush per theme.')]
    param()

    $isDark = [bool]$global:Prefs['DarkMode']
    if ($isDark) {
        $window.ClearValue([MahApps.Metro.Controls.MetroWindow]::WindowTitleBrushProperty)
        $window.ClearValue([MahApps.Metro.Controls.MetroWindow]::NonActiveWindowTitleBrushProperty)
    } else {
        $window.WindowTitleBrush          = $script:TitleBarBlue
        $window.NonActiveWindowTitleBrush = $script:TitleBarBlueInactive
    }
}

$__startIsDark = [bool]$global:Prefs['DarkMode']
$toggleTheme.IsOn = $__startIsDark
if ($__startIsDark) {
    [void][ControlzEx.Theming.ThemeManager]::Current.ChangeTheme($window, 'Dark.Steel')
    $txtThemeLabel.Text = 'Dark Theme'
} else {
    [void][ControlzEx.Theming.ThemeManager]::Current.ChangeTheme($window, 'Light.Blue')
    $txtThemeLabel.Text = 'Light Theme'
}
Update-SidebarButtonTheme
Update-TitleBarBrushes

$toggleTheme.Add_Toggled({
    $isDark = [bool]$toggleTheme.IsOn
    if ($isDark) {
        [void][ControlzEx.Theming.ThemeManager]::Current.ChangeTheme($window, 'Dark.Steel')
        $txtThemeLabel.Text = 'Dark Theme'
    } else {
        [void][ControlzEx.Theming.ThemeManager]::Current.ChangeTheme($window, 'Light.Blue')
        $txtThemeLabel.Text = 'Light Theme'
    }
    $global:Prefs['DarkMode'] = $isDark
    Save-IatPreferences -Prefs $global:Prefs
    Update-SidebarButtonTheme
    Update-TitleBarBrushes
    Add-LogLine ('Theme: {0}' -f $(if ($isDark) { 'dark' } else { 'light' }))
})

# =============================================================================
# View switching. Visibility-swap across the stacked panels in viewHost.
# =============================================================================
$script:ViewMeta = @{
    'Overview'         = @{ Title = 'Overview';         Subtitle = 'Summary of installer type, deployment fields, MSI / package metadata, and silent switches.' }
    'MSI Properties'   = @{ Title = 'MSI Properties';   Subtitle = 'Full Property table from the MSI. Populated for MSI files or EXE wrappers with an embedded MSI.' }
    'Payload'          = @{ Title = 'Payload';          Subtitle = 'Contents listing via 7-Zip. Populated for EXE-wrapped installers (NSIS, Inno, InstallShield, WiX Burn, SFX).' }
    'Inner Installers' = @{ Title = 'Inner Installers'; Subtitle = 'Installer-class payload entries (MSIs, CABs, EXEs, .nupkg) that can themselves be opened and analyzed. Drill in with Analyze Selected.' }
    'Strings'          = @{ Title = 'Strings';          Subtitle = 'Categorized interesting strings from the binary -- URLs, registry paths, GUIDs, versions. Filter case-insensitively.' }
}

function Set-ActiveView {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Updates in-window Visibility + header text only; no external state.')]
    param(
        [Parameter(Mandatory)][ValidateSet('Overview','MSI Properties','Payload','Inner Installers','Strings')][string]$View
    )

    $script:ActiveView = $View

    $txtOverview.Visibility    = if ($View -eq 'Overview')         { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $gridMsi.Visibility        = if ($View -eq 'MSI Properties')   { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $gridPayload.Visibility    = if ($View -eq 'Payload')          { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $panelEmbedded.Visibility  = if ($View -eq 'Inner Installers') { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $panelStrings.Visibility   = if ($View -eq 'Strings')          { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }

    $meta = $script:ViewMeta[$View]
    if ($meta) {
        $txtModuleTitle.Text    = $meta.Title
        $txtModuleSubtitle.Text = $meta.Subtitle
    }

    Update-SidebarButtonTheme
}

$btnViewOverview.Add_Click({ Set-ActiveView -View 'Overview' })
$btnViewMsi.Add_Click({      Set-ActiveView -View 'MSI Properties' })
$btnViewPayload.Add_Click({  Set-ActiveView -View 'Payload' })
$btnViewEmbedded.Add_Click({ Set-ActiveView -View 'Inner Installers' })
$btnViewStrings.Add_Click({  Set-ActiveView -View 'Strings' })

# =============================================================================
# Crash handlers (Dispatcher + AppDomain). Direct-to-file via AppendAllText.
# =============================================================================
$global:__crashLog = Join-Path $__txDir ('InstallerAnalysis-crash-{0}.txt' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

$__writeCrash = {
    param($Source, $Exception)
    try {
        $lines = @()
        $lines += ('=== ' + $Source + ' @ ' + (Get-Date -Format 'o') + ' ===')
        $lines += ('Type   : ' + $Exception.GetType().FullName)
        $lines += ('Message: ' + $Exception.Message)
        $lines += ('Stack  :')
        $lines += ([string]$Exception.StackTrace).Split([Environment]::NewLine)
        $inner = $Exception.InnerException
        $depth = 1
        while ($inner) {
            $lines += ('--- InnerException depth ' + $depth + ' ---')
            $lines += ('Type   : ' + $inner.GetType().FullName)
            $lines += ('Message: ' + $inner.Message)
            $lines += ('Stack  :')
            $lines += ([string]$inner.StackTrace).Split([Environment]::NewLine)
            $inner = $inner.InnerException
            $depth++
        }
        [System.IO.File]::AppendAllText($global:__crashLog, (($lines -join [Environment]::NewLine) + [Environment]::NewLine))
    } catch { $null = $_ }
}
$global:__writeCrash = $__writeCrash

$window.Dispatcher.Add_UnhandledException({
    param($s, $e)
    & $global:__writeCrash 'DispatcherUnhandledException' $e.Exception
    $e.Handled = $false
})

[AppDomain]::CurrentDomain.Add_UnhandledException({
    param($s, $e)
    & $global:__writeCrash 'AppDomainUnhandledException' ([Exception]$e.ExceptionObject)
})

# =============================================================================
# Analysis state ($script:Last* variables).
# =============================================================================
$script:LastFileInfo        = $null
$script:LastInstallerType   = $null
$script:LastMsiProperties   = $null
$script:LastPackageMetadata = $null
$script:LastSwitches        = $null
$script:LastDeployment      = $null
$script:LastPayload         = $null
$script:LastEmbedded        = $null
$script:LastMspMetadata     = $null   # array of MSP metadata for inner .msp files
$script:LastInnerMsiData    = $null   # base MSI ProductCode/Name/Version for MSI+MSP outer files
$script:LastInterestingStrings = $null

# LIFO of outer-installer states. Each push snapshots $script:Last*; Pop
# restores without rerunning the pipeline. Depth capped at 5.
$script:AnalysisStack = New-Object 'System.Collections.Generic.Stack[object]'

# =============================================================================
# Pipeline: orchestrate analyzer calls, populate tabs, toggle action buttons.
# =============================================================================

function Show-OverviewText {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Writes in-window TextBox text only; no external state.')]
    param()
    $txtOverview.Text = New-AnalysisSummaryText `
        -FileInfo         $script:LastFileInfo `
        -InstallerType    $script:LastInstallerType `
        -Switches         $script:LastSwitches `
        -MsiProperties    $script:LastMsiProperties `
        -DeploymentFields $script:LastDeployment `
        -PackageMetadata  $script:LastPackageMetadata `
        -MspMetadata      $script:LastMspMetadata `
        -InnerMsiData     $script:LastInnerMsiData
}

function Show-MsiPropertiesGrid {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Populates in-window DataGrid only; no external state.')]
    param()
    $rows = @()
    if ($script:LastMsiProperties -and $script:LastMsiProperties.Count -gt 0) {
        foreach ($k in $script:LastMsiProperties.Keys) {
            $rows += [PSCustomObject]@{ Property = [string]$k; Value = [string]$script:LastMsiProperties[$k] }
        }
    }
    $gridMsi.ItemsSource = $rows
}

function Show-PayloadGrid {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Populates in-window DataGrid only; no external state.')]
    param()
    if ($script:LastPayload) {
        $gridPayload.ItemsSource = @($script:LastPayload)
    } else {
        $gridPayload.ItemsSource = @()
    }
}

function Show-EmbeddedGrid {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Populates in-window DataGrid + nav-button text/visibility only; no external state.')]
    param()

    $rows = @()
    if ($script:LastEmbedded) { $rows = @($script:LastEmbedded) }
    $gridEmbedded.ItemsSource = $rows

    # Nav-button: reveal only when the current file actually contains inner
    # installers. Label includes the count so the analyst sees at a glance
    # whether drill-down will yield anything.
    if ($rows.Count -gt 0) {
        $btnViewEmbedded.Visibility = [System.Windows.Visibility]::Visible
        $btnViewEmbedded.Content    = ('Inner Installers ({0})' -f $rows.Count)
    } else {
        $btnViewEmbedded.Visibility = [System.Windows.Visibility]::Collapsed
        $btnViewEmbedded.Content    = 'Inner Installers'
    }
    Update-SidebarButtonTheme
}

function Show-StringsGrid {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Populates in-window DataGrid only; no external state.')]
    param([string]$Filter = '')

    $source = @()
    if ($script:LastInterestingStrings) { $source = @($script:LastInterestingStrings) }
    if ($Filter) {
        $needle = $Filter.ToLowerInvariant()
        $source = @($source | Where-Object { $_.Value -and ([string]$_.Value).ToLowerInvariant().Contains($needle) })
    }
    $gridStrings.ItemsSource = $source
}

function Set-ActionBarVisible {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Toggles in-window Visibility only.')]
    param([bool]$Analyzed, [bool]$HasPayload)

    $actionBar.Visibility = if ($Analyzed) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $btnExtractAll.Visibility = if ($Analyzed -and $HasPayload) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
}

# =============================================================================
# Temp-folder helpers (Inner Installers + right-click extract). Tree wiped
# on window close.
# =============================================================================
$script:AnalysisTempRoot = Join-Path $env:LOCALAPPDATA 'InstallerAnalysis\Temp'

function Get-InspectTempDir {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Creates a per-file temp folder; idempotent.')]
    param([Parameter(Mandatory)][string]$Sha256)
    $tag = $Sha256.Substring(0, [Math]::Min(16, $Sha256.Length))
    $dir = Join-Path $script:AnalysisTempRoot ('inspect\' + $tag)
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return $dir
}

function Get-DrillTempDir {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Creates a per-file/per-depth temp folder; idempotent.')]
    param(
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][int]$Depth
    )
    $tag = $Sha256.Substring(0, [Math]::Min(16, $Sha256.Length))
    $dir = Join-Path $script:AnalysisTempRoot ('drill\' + $tag + '\' + $Depth)
    if (Test-Path -LiteralPath $dir) {
        # Clean previous content at the same depth so successive drills at the
        # same level don't accumulate cruft from differently-named entries.
        try { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop } catch { $null = $_ }
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

function Resolve-SevenZipPath {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Pure resolver; falls back to Find-7ZipPath if prefs unset.')]
    param()
    $sz = $global:Prefs['SevenZipPath']
    if (-not $sz -or -not (Test-Path -LiteralPath $sz)) { $sz = Find-7ZipPath }
    return $sz
}

function Invoke-7zExtractSingle {
    <#
        UI-thread wrapper around Expand-PayloadEntry. Resolves 7-Zip via prefs
        and logs to the in-app drawer; the actual quoted-arg + exit-code-check
        extraction lives in the module so the bg runspace and the test suite
        both reuse the same code path.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Wraps Expand-PayloadEntry; OutputDir is caller-owned temp.')]
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$EntryName,
        [Parameter(Mandatory)][string]$OutputDir
    )
    $sevenZip = Resolve-SevenZipPath
    if (-not $sevenZip) {
        Add-LogLine '7-Zip not found. Configure the path in Options > 7-Zip.'
        return $null
    }
    $extracted = Expand-PayloadEntry -SevenZipPath $sevenZip `
        -ArchivePath $ArchivePath -EntryName $EntryName -OutputDir $OutputDir
    if (-not $extracted) {
        Add-LogLine ('Extract failed for {0} (see module log for 7z exit code).' -f $EntryName)
    }
    return $extracted
}

# =============================================================================
# Breadcrumb + analysis stack (drill-down state).
# =============================================================================
function Update-BreadcrumbBar {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Repopulates the breadcrumb StackPanel; no external state.')]
    param()

    $depth = $script:AnalysisStack.Count
    if ($depth -eq 0) {
        $breadcrumbBar.Visibility = [System.Windows.Visibility]::Collapsed
        $breadcrumbSegments.Children.Clear()
        return
    }

    $breadcrumbBar.Visibility = [System.Windows.Visibility]::Visible
    $breadcrumbSegments.Children.Clear()

    # Stack is LIFO; ToArray() yields top-first. Reverse so the breadcrumb
    # reads root -> current (left to right).
    $stackArr = @($script:AnalysisStack.ToArray())
    [array]::Reverse($stackArr)

    $segments = @()
    foreach ($frame in $stackArr) {
        $segments += [PSCustomObject]@{
            Label = [System.IO.Path]::GetFileName([string]$frame.Path)
            IsCurrent = $false
            FrameIndex = $segments.Count
        }
    }
    # Current frame (not on stack — it's live state).
    $currentName = if ($script:LastFileInfo) { [string]$script:LastFileInfo.FileName }
                   else { [System.IO.Path]::GetFileName([string]$txtFilePath.Text) }
    $segments += [PSCustomObject]@{ Label = $currentName; IsCurrent = $true; FrameIndex = $segments.Count }

    $i = 0
    foreach ($seg in $segments) {
        if ($i -gt 0) {
            $sep = New-Object System.Windows.Controls.TextBlock
            $sep.Text = ' > '
            $sep.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
            $sep.Margin = [System.Windows.Thickness]::new(2,0,2,0)
            $sep.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'MahApps.Brushes.Gray1')
            [void]$breadcrumbSegments.Children.Add($sep)
        }

        $btn = New-Object System.Windows.Controls.Button
        $btn.Content = $seg.Label
        $btn.MinHeight = 22
        $btn.Padding = [System.Windows.Thickness]::new(6,0,6,0)
        $btn.FontSize = 11
        [MahApps.Metro.Controls.ControlsHelper]::SetContentCharacterCasing($btn, [System.Windows.Controls.CharacterCasing]::Normal)
        $btn.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'MahApps.Styles.Button.Square')
        if ($seg.IsCurrent) {
            $btn.IsEnabled = $false
            $btn.FontWeight = [System.Windows.FontWeights]::SemiBold
        } else {
            $localTarget = [int]$seg.FrameIndex
            $btn.Add_Click({
                # Pops until current == segment level. Required closure capture
                # of $localTarget via GetNewClosure.
                $needed = $script:AnalysisStack.Count - $localTarget
                for ($k = 0; $k -lt $needed; $k++) { Pop-AnalysisStack }
            }.GetNewClosure())
        }
        [void]$breadcrumbSegments.Children.Add($btn)
        $i++
    }
}

function Push-AnalysisStack {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Pushes the current $script:Last* snapshot onto the drill-down stack.')]
    param()

    if ($script:AnalysisStack.Count -ge 5) {
        Add-LogLine 'Max drill-down depth (5) reached. Extract manually to continue deeper.'
        return $false
    }

    $frame = [PSCustomObject]@{
        Path                  = [string]$txtFilePath.Text
        FileInfo              = $script:LastFileInfo
        InstallerType         = $script:LastInstallerType
        MsiProperties         = $script:LastMsiProperties
        PackageMetadata       = $script:LastPackageMetadata
        Switches              = $script:LastSwitches
        Deployment            = $script:LastDeployment
        Payload               = $script:LastPayload
        Embedded              = $script:LastEmbedded
        MspMetadata           = $script:LastMspMetadata
        InnerMsiData          = $script:LastInnerMsiData
        InterestingStrings    = $script:LastInterestingStrings
        ActiveView            = $script:ActiveView
    }
    $script:AnalysisStack.Push($frame)
    return $true
}

function Pop-AnalysisStack {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Restores the previous $script:Last* snapshot from the drill-down stack.')]
    param()

    if ($script:AnalysisStack.Count -eq 0) { return }
    $f = $script:AnalysisStack.Pop()

    $txtFilePath.Text              = [string]$f.Path
    $script:LastFileInfo           = $f.FileInfo
    $script:LastInstallerType      = $f.InstallerType
    $script:LastMsiProperties      = $f.MsiProperties
    $script:LastPackageMetadata    = $f.PackageMetadata
    $script:LastSwitches           = $f.Switches
    $script:LastDeployment         = $f.Deployment
    $script:LastPayload            = $f.Payload
    $script:LastEmbedded           = $f.Embedded
    $script:LastMspMetadata        = $f.MspMetadata
    $script:LastInnerMsiData       = $f.InnerMsiData
    $script:LastInterestingStrings = $f.InterestingStrings

    Show-OverviewText
    Show-MsiPropertiesGrid
    Show-PayloadGrid
    Show-EmbeddedGrid
    Show-StringsGrid -Filter $txtStringsFilter.Text
    Set-ActionBarVisible -Analyzed:$true -HasPayload:([bool]$script:LastPayload)

    $restoredView = if ($f.ActiveView) { [string]$f.ActiveView } else { 'Overview' }
    if ($script:ViewMeta.ContainsKey($restoredView)) {
        Set-ActiveView -View $restoredView
    } else {
        Set-ActiveView -View 'Overview'
    }

    Update-BreadcrumbBar
    $displayName = if ($script:LastDeployment -and $script:LastDeployment.DisplayName) {
        $script:LastDeployment.DisplayName
    } else { [System.IO.Path]::GetFileName([string]$txtFilePath.Text) }
    Set-StatusText ('Restored: {0}  [{1}]' -f $displayName, $script:LastInstallerType)
    Add-LogLine    ('Breadcrumb back: depth now {0}' -f $script:AnalysisStack.Count)
}

function ConvertTo-StringsGridRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Pure converter that flattens the Get-InterestingStrings hashtable into Category/Value rows.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns an array of grid rows; plural matches the collection being returned.')]
    param($Interesting)

    $rows = @()
    if (-not $Interesting) { return ,$rows }
    if ($Interesting -is [hashtable]) {
        foreach ($k in $Interesting.Keys) {
            foreach ($v in @($Interesting[$k])) {
                if (-not [string]::IsNullOrWhiteSpace([string]$v)) {
                    $rows += [PSCustomObject]@{ Category = [string]$k; Value = [string]$v }
                }
            }
        }
    } else {
        foreach ($prop in $Interesting.PSObject.Properties) {
            foreach ($v in @($prop.Value)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$v)) {
                    $rows += [PSCustomObject]@{ Category = [string]$prop.Name; Value = [string]$v }
                }
            }
        }
    }
    return ,$rows
}

# =============================================================================
# Background analyzer runspace. Lazy-init; STA so MSI COM works inside.
# =============================================================================
$script:BgRunspace   = $null
$script:BgPowerShell = $null
$script:BgInvokeHandle = $null
$script:AnalysisState  = $null
$script:AnalysisTimer  = $null

function Initialize-BackgroundAnalyzer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Lazy-init of the background analysis runspace; idempotent.')]
    param()

    if ($script:BgRunspace -and $script:BgRunspace.RunspaceStateInfo.State -eq 'Opened') { return }

    $script:BgRunspace = [runspacefactory]::CreateRunspace()
    $script:BgRunspace.ApartmentState = 'STA'
    $script:BgRunspace.ThreadOptions  = 'ReuseThread'
    $script:BgRunspace.Open()

    # Pre-import the analyzer module + vendored MSI module into the runspace
    # so per-analyze startup cost is just the analyzer calls themselves.
    $modulePath  = Join-Path $PSScriptRoot 'Module\InstallerAnalysisCommon.psd1'
    $msiPath     = ''
    $msiManifest = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Lib\MSI') -Recurse -Filter 'MSI.psd1' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($msiManifest) { $msiPath = $msiManifest.FullName }

    $initPS = [powershell]::Create()
    $initPS.Runspace = $script:BgRunspace
    [void]$initPS.AddScript({
        param($MsiManifestPath, $ModulePath)
        if ($MsiManifestPath) {
            try { Import-Module -Name $MsiManifestPath -Force -DisableNameChecking -ErrorAction Stop } catch { $null = $_ }
        }
        Import-Module -Name $ModulePath -Force -DisableNameChecking
    }).AddArgument($msiPath).AddArgument($modulePath)
    [void]$initPS.Invoke()
    $initPS.Dispose()
}

function Invoke-AnalysisPipeline {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Posts work to the background runspace and arms a DispatcherTimer; no external state changes from the UI thread.')]
    param()

    $path = [string]$txtFilePath.Text
    if ([string]::IsNullOrWhiteSpace($path)) {
        Set-StatusText 'No file to analyze.'
        Add-LogLine   'Analyze: no file path entered.'
        return
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Set-StatusText ('Not found: {0}' -f $path)
        Add-LogLine   ('Analyze failed: file not found: {0}' -f $path)
        return
    }

    Initialize-BackgroundAnalyzer

    # Cancel any in-flight analysis. Stop is best-effort; the analyzer may
    # still finish its current step before yielding.
    if ($script:AnalysisTimer)  { try { $script:AnalysisTimer.Stop() } catch { $null = $_ } }
    if ($script:BgPowerShell)   {
        try { [void]$script:BgPowerShell.Stop() } catch { $null = $_ }
        try { $script:BgPowerShell.Dispose() }   catch { $null = $_ }
        $script:BgPowerShell = $null
    }

    # Synchronized hashtable bridges the bg runspace -> UI thread. The runspace
    # writes Step / Done / Result / ErrorMsg; the DispatcherTimer reads them.
    $script:AnalysisState = [hashtable]::Synchronized(@{
        Step     = 'Starting...'
        Done     = $false
        Result   = $null
        ErrorMsg = $null
    })

    $btnBrowse.IsEnabled = $false
    $txtProgressTitle.Text = ('Analyzing {0}' -f [System.IO.Path]::GetFileName($path))
    $txtProgressStep.Text  = 'Starting...'
    $progressOverlay.Visibility = [System.Windows.Visibility]::Visible
    Set-StatusText ('Analyzing: {0}' -f [System.IO.Path]::GetFileName($path))
    Add-LogLine    ('Analyze: {0}' -f $path)

    # Resolve 7-Zip path on the UI thread (it touches $global:Prefs); pass into
    # the runspace as a literal so the runspace doesn't need to read prefs.
    $sevenZip = $global:Prefs['SevenZipPath']
    if (-not $sevenZip -or -not (Test-Path -LiteralPath $sevenZip)) { $sevenZip = Find-7ZipPath }

    $script:BgPowerShell = [powershell]::Create()
    $script:BgPowerShell.Runspace = $script:BgRunspace
    [void]$script:BgPowerShell.AddScript({
        param($Path, $State, $SevenZipPath)
        try {
            $State.Step = 'Reading file info (size, signature, hash)...'
            $fi = Get-InstallerFileInfo -Path $Path

            $State.Step = 'Detecting installer type...'
            $type = Get-InstallerType -Path $Path

            $msi = $null
            $msiSummary = $null
            if ($type -eq 'MSI') {
                $State.Step = 'Reading MSI properties...'
                $msi = Get-MsiProperties -MsiPath $Path
                $State.Step = 'Reading MSI summary (Template / architecture)...'
                $msiSummary = Get-MsiSummaryInfo -MsiPath $Path
            }

            $State.Step = "Reading package metadata ($type)..."
            $pkg = Get-PackageMetadataFor -Path $Path -InstallerType $type

            $State.Step = 'Resolving deployment fields...'
            $sw = Get-SilentSwitches -InstallerType $type -FilePath $Path -MsiProperties $msi
            $df = Get-DeploymentFields -FileInfo $fi -MsiProperties $msi -Switches $sw -PackageMetadata $pkg -InstallerType $type -MsiSummary $msiSummary

            $payload = $null
            $embedded = $null
            $mspMetadataList = @()
            $innerMsiData    = $null
            # 7-Zip runs against any file when available; empty result if it
            # can't parse the format.
            if ($SevenZipPath) {
                $State.Step = 'Listing payload via 7-Zip...'
                $payload = Get-PayloadContents -Path $Path -SevenZipPath $SevenZipPath
                $State.Step = 'Classifying inner installers...'
                $embedded = Get-EmbeddedInstallers -Payload $payload -Type $type -PackageMetadata $pkg -ParentPath $Path

                # MSP post-patch metadata. Extract each inner .msp and read
                # MsiPatchMetadata so the Overview can render the post-patch
                # DisplayVersion (the value the ARP key holds after the patch
                # applies).
                $mspEntries = @()
                $msiEntries = @()
                if ($embedded) {
                    $mspEntries = @($embedded | Where-Object { $_.Kind -eq 'MSP' })
                    $msiEntries = @($embedded | Where-Object { $_.Kind -eq 'MSI' })
                }

                if ($mspEntries.Count -gt 0) {
                    $sha16 = $fi.SHA256.Substring(0, [Math]::Min(16, [string]$fi.SHA256.Length))
                    $mspCacheDir = Join-Path $env:LOCALAPPDATA "InstallerAnalysis\Temp\msp\$sha16"
                    if (-not (Test-Path -LiteralPath $mspCacheDir)) {
                        New-Item -ItemType Directory -Path $mspCacheDir -Force | Out-Null
                    }

                    foreach ($mspEntry in $mspEntries) {
                        $leaf = [System.IO.Path]::GetFileName([string]$mspEntry.Name)
                        $mspPath = Join-Path $mspCacheDir $leaf
                        if (-not (Test-Path -LiteralPath $mspPath)) {
                            $State.Step = "Extracting $leaf (post-patch metadata read)..."
                            $mspPath = Expand-PayloadEntry -SevenZipPath $SevenZipPath `
                                -ArchivePath $Path -EntryName ([string]$mspEntry.Name) -OutputDir $mspCacheDir
                        }
                        if ($mspPath -and (Test-Path -LiteralPath $mspPath)) {
                            $State.Step = "Reading MsiPatchMetadata from $leaf..."
                            $md = Get-MspMetadata -Path $mspPath
                            if ($md) {
                                # Annotate which source file the metadata came from.
                                $md | Add-Member -NotePropertyName SourceFile -NotePropertyValue $leaf -Force
                                $mspMetadataList += $md
                            }
                        }
                    }

                    # Inner base MSI (small): extract for ProductCode + base
                    # ProductVersion.
                    if ($msiEntries.Count -gt 0) {
                        $msiEntry = $msiEntries[0]
                        $msiLeaf = [System.IO.Path]::GetFileName([string]$msiEntry.Name)
                        $msiPath = Join-Path $mspCacheDir $msiLeaf
                        if (-not (Test-Path -LiteralPath $msiPath)) {
                            $State.Step = "Extracting $msiLeaf for base ProductCode..."
                            $msiPath = Expand-PayloadEntry -SevenZipPath $SevenZipPath `
                                -ArchivePath $Path -EntryName ([string]$msiEntry.Name) -OutputDir $mspCacheDir
                        }
                        if ($msiPath -and (Test-Path -LiteralPath $msiPath)) {
                            $State.Step = "Reading base MSI ProductCode from $msiLeaf..."
                            try {
                                $iMsi = Get-MsiProperties -MsiPath $msiPath
                                if ($iMsi) {
                                    $iSummary = $null
                                    try { $iSummary = Get-MsiSummaryInfo -MsiPath $msiPath } catch { $null = $_ }
                                    $iArch = if ($iSummary -and $iSummary.PSObject.Properties['Architecture']) { [string]$iSummary.Architecture } else { '' }
                                    $innerMsiData = [PSCustomObject]@{
                                        ProductCode     = [string]$iMsi['ProductCode']
                                        ProductName     = [string]$iMsi['ProductName']
                                        ProductVersion  = [string]$iMsi['ProductVersion']
                                        Manufacturer    = [string]$iMsi['Manufacturer']
                                        MsiArchitecture = $iArch
                                        SourceFile      = $msiLeaf
                                    }
                                }
                            } catch { $null = $_ }
                        }
                    }
                }
            }

            $State.Step = 'Scanning interesting strings (URLs, GUIDs, registry paths)...'
            $interesting = $null
            try { $interesting = Get-InterestingStrings -Path $Path } catch { $null = $_ }

            $State.Result = [PSCustomObject]@{
                FileInfo        = $fi
                InstallerType   = $type
                MsiProperties   = $msi
                PackageMetadata = $pkg
                Switches        = $sw
                Deployment      = $df
                Payload         = $payload
                Embedded        = $embedded
                MspMetadata     = $mspMetadataList
                InnerMsiData    = $innerMsiData
                Interesting     = $interesting
            }
        }
        catch {
            $State.ErrorMsg = $_.Exception.Message
        }
        finally {
            $State.Done = $true
        }
    }).AddArgument($path).AddArgument($script:AnalysisState).AddArgument($sevenZip)

    $script:BgInvokeHandle = $script:BgPowerShell.BeginInvoke()

    # Polling timer: 100ms tick reads the synchronized state, pushes Step into
    # the overlay text, and finalises when Done flips. The UI thread stays
    # free to render the ProgressRing animation continuously.
    $script:AnalysisTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:AnalysisTimer.Interval = [TimeSpan]::FromMilliseconds(100)
    $script:AnalysisTimer.Add_Tick({
        if ($script:AnalysisState) {
            $currentStep = [string]$script:AnalysisState.Step
            if ($txtProgressStep.Text -ne $currentStep) { $txtProgressStep.Text = $currentStep }
        }
        if ($script:AnalysisState -and $script:AnalysisState.Done) {
            $script:AnalysisTimer.Stop()
            try { [void]$script:BgPowerShell.EndInvoke($script:BgInvokeHandle) } catch { $null = $_ }
            try { $script:BgPowerShell.Dispose() } catch { $null = $_ }
            $script:BgPowerShell   = $null
            $script:BgInvokeHandle = $null

            if ($script:AnalysisState.ErrorMsg) {
                $script:LastFileInfo           = $null
                $script:LastInstallerType      = $null
                $script:LastMsiProperties      = $null
                $script:LastPackageMetadata    = $null
                $script:LastSwitches           = $null
                $script:LastDeployment         = $null
                $script:LastPayload            = $null
                $script:LastEmbedded           = $null
                $script:LastMspMetadata        = $null
                $script:LastInnerMsiData       = $null
                $script:LastInterestingStrings = $null
                $txtOverview.Text = 'Analyze failed. Check the log drawer below for details.'
                $gridMsi.ItemsSource      = @()
                $gridPayload.ItemsSource  = @()
                $gridEmbedded.ItemsSource = @()
                $gridStrings.ItemsSource  = @()
                $btnViewEmbedded.Visibility = [System.Windows.Visibility]::Collapsed
                Set-ActionBarVisible -Analyzed:$false -HasPayload:$false
                Set-StatusText 'Analyze failed.'
                Add-LogLine    ('Analyze failed: {0}' -f $script:AnalysisState.ErrorMsg)
            } else {
                $r = $script:AnalysisState.Result
                $script:LastFileInfo           = $r.FileInfo
                $script:LastInstallerType      = $r.InstallerType
                $script:LastMsiProperties      = $r.MsiProperties
                $script:LastPackageMetadata    = $r.PackageMetadata
                $script:LastSwitches           = $r.Switches
                $script:LastDeployment         = $r.Deployment
                $script:LastPayload            = $r.Payload
                $script:LastEmbedded           = $r.Embedded
                $script:LastMspMetadata        = $r.MspMetadata
                $script:LastInnerMsiData       = $r.InnerMsiData
                $script:LastInterestingStrings = ConvertTo-StringsGridRows -Interesting $r.Interesting

                Show-OverviewText
                Show-MsiPropertiesGrid
                Show-PayloadGrid
                Show-EmbeddedGrid
                Show-StringsGrid -Filter $txtStringsFilter.Text
                Set-ActionBarVisible -Analyzed:$true -HasPayload:([bool]$script:LastPayload)
                Update-BreadcrumbBar

                $currentViewHasData = switch ($script:ActiveView) {
                    'Overview'         { $true }
                    'MSI Properties'   { [bool]$script:LastMsiProperties -and $script:LastMsiProperties.Count -gt 0 }
                    'Payload'          { [bool]$script:LastPayload }
                    'Inner Installers' { ($script:LastEmbedded -and @($script:LastEmbedded).Count -gt 0) }
                    'Strings'          { [bool]$script:LastInterestingStrings }
                    default            { $true }
                }
                if (-not $currentViewHasData) { Set-ActiveView -View 'Overview' }

                $displayName = if ($script:LastDeployment -and $script:LastDeployment.DisplayName) {
                    $script:LastDeployment.DisplayName
                } else { [System.IO.Path]::GetFileName([string]$txtFilePath.Text) }
                Set-StatusText ('Analyzed: {0}  [{1}]' -f $displayName, $script:LastInstallerType)
                Add-LogLine    ('Analyzed type={0} name=''{1}''' -f $script:LastInstallerType, $displayName)
            }

            $progressOverlay.Visibility = [System.Windows.Visibility]::Collapsed
            $btnBrowse.IsEnabled = $true
        }
    })
    $script:AnalysisTimer.Start()
}

# =============================================================================
# Show-ThemedMessage: theme-aware modal that replaces MessageBox::Show.
# =============================================================================
function Show-ThemedMessage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Shows a modal MetroWindow and returns the chosen string; mutates no external state.')]
    param(
        [Parameter(Mandatory)]$Owner,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('OK','OKCancel','YesNo')][string]$Buttons = 'OK',
        [ValidateSet('None','Info','Warn','Error','Question')][string]$Icon = 'None'
    )

    $dlgXaml = @'
<Controls:MetroWindow
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:Controls="clr-namespace:MahApps.Metro.Controls;assembly=MahApps.Metro"
    Title="Message"
    SizeToContent="Height"
    Width="460" MinHeight="160"
    WindowStartupLocation="CenterOwner"
    TitleCharacterCasing="Normal"
    ShowIconOnTitleBar="False"
    ResizeMode="NoResize"
    GlowBrush="{DynamicResource MahApps.Brushes.Accent}"
    BorderThickness="1">
    <Window.Resources>
        <ResourceDictionary>
            <ResourceDictionary.MergedDictionaries>
                <ResourceDictionary Source="pack://application:,,,/MahApps.Metro;component/Styles/Controls.xaml" />
                <ResourceDictionary Source="pack://application:,,,/MahApps.Metro;component/Styles/Fonts.xaml" />
                <ResourceDictionary Source="pack://application:,,,/MahApps.Metro;component/Styles/Themes/Dark.Steel.xaml" />
            </ResourceDictionary.MergedDictionaries>
        </ResourceDictionary>
    </Window.Resources>
    <Grid Margin="20,18,20,14">
        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="txtIcon" Grid.Row="0" Grid.Column="0" FontSize="20" VerticalAlignment="Top" Margin="0,0,14,0"/>
        <TextBlock x:Name="txtMsg"  Grid.Row="0" Grid.Column="1" FontSize="13" TextWrapping="Wrap" VerticalAlignment="Center"/>
        <StackPanel Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
            <Button x:Name="btnPrimary"   MinWidth="90" Height="32" Margin="0,0,8,0" IsDefault="True"
                    Style="{DynamicResource MahApps.Styles.Button.Square.Accent}"
                    Controls:ControlsHelper.ContentCharacterCasing="Normal"/>
            <Button x:Name="btnSecondary" MinWidth="90" Height="32" IsCancel="True" Visibility="Collapsed"
                    Style="{DynamicResource MahApps.Styles.Button.Square}"
                    Controls:ControlsHelper.ContentCharacterCasing="Normal"/>
        </StackPanel>
    </Grid>
</Controls:MetroWindow>
'@

    [xml]$xml = $dlgXaml
    $xmlReader = New-Object System.Xml.XmlNodeReader $xml
    $dlg    = [System.Windows.Markup.XamlReader]::Load($xmlReader)
    Install-TitleBarDragFallback -Window $dlg

    $theme = [ControlzEx.Theming.ThemeManager]::Current.DetectTheme($Owner)
    if ($theme) { [void][ControlzEx.Theming.ThemeManager]::Current.ChangeTheme($dlg, $theme) }
    $dlg.Owner = $Owner
    try {
        $dlg.WindowTitleBrush          = $Owner.WindowTitleBrush
        $dlg.NonActiveWindowTitleBrush = $Owner.NonActiveWindowTitleBrush
        $dlg.GlowBrush                 = $Owner.GlowBrush
        $dlg.NonActiveGlowBrush        = $Owner.NonActiveGlowBrush
    } catch { $null = $_ }

    $dlg.Title   = $Title
    $txtIcon     = $dlg.FindName('txtIcon')
    $txtMsg      = $dlg.FindName('txtMsg')
    $btn1        = $dlg.FindName('btnPrimary')
    $btn2        = $dlg.FindName('btnSecondary')
    $txtMsg.Text = $Message

    # Glyph-only state (no red/green); inherits ThemeForeground for AAA
    # contrast on both themes.
    $glyph = switch ($Icon) {
        'Info'     { [char]0x2139 }
        'Warn'     { [char]0x26A0 }
        'Error'    { [char]0x2716 }
        'Question' { [char]0x003F }
        default    { '' }
    }
    $txtIcon.Text = [string]$glyph

    switch ($Buttons) {
        'OK' {
            $btn1.Content = 'OK'
            $btn2.Visibility = [System.Windows.Visibility]::Collapsed
        }
        'OKCancel' {
            $btn1.Content = 'OK'
            $btn2.Content = 'Cancel'
            $btn2.Visibility = [System.Windows.Visibility]::Visible
        }
        'YesNo' {
            $btn1.Content = 'Yes'
            $btn2.Content = 'No'
            $btn2.Visibility = [System.Windows.Visibility]::Visible
        }
    }

    $script:ThemedMessageResult = switch ($Buttons) { 'YesNo' { 'No' } default { 'Cancel' } }

    # No GetNewClosure -- Show-ThemedMessage still on the stack blocked on
    # ShowDialog, so $script: writes to $ThemedMessageResult reach script
    # scope naturally. GetNewClosure would silently drop them.
    $btn1.Add_Click({
        $script:ThemedMessageResult = switch ($Buttons) { 'YesNo' { 'Yes' } default { 'OK' } }
        $dlg.Close()
    })
    $btn2.Add_Click({
        $script:ThemedMessageResult = switch ($Buttons) { 'YesNo' { 'No' } default { 'Cancel' } }
        $dlg.Close()
    })

    [void]$dlg.ShowDialog()
    return $script:ThemedMessageResult
}

# =============================================================================
# Options window panel factories. Each returns @{ Name; Element; Commit }.
# =============================================================================
function New-OptionsSection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs WPF elements; no external state.')]
    param([Parameter(Mandatory)][string]$Heading, [Parameter(Mandatory)][string]$Description)

    $sp = New-Object System.Windows.Controls.StackPanel
    $h = New-Object System.Windows.Controls.TextBlock
    $h.Text = $Heading
    $h.FontSize = 18
    $h.FontWeight = [System.Windows.FontWeights]::SemiBold
    $h.Margin = [System.Windows.Thickness]::new(0,0,0,6)
    [void]$sp.Children.Add($h)

    $d = New-Object System.Windows.Controls.TextBlock
    $d.Text = $Description
    $d.FontSize = 12
    $d.TextWrapping = [System.Windows.TextWrapping]::Wrap
    # Deferred resource lookup: resolves via the visual tree when the TextBlock
    # is mounted into the Options dialog, so we do not need $dlg in scope here.
    $d.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'MahApps.Brushes.Gray1')
    $d.Margin = [System.Windows.Thickness]::new(0,0,0,16)
    [void]$sp.Children.Add($d)

    return $sp
}

function New-PathPickerPanel {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs WPF panel; no external state.')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Heading,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$PrefKey,
        [ValidateSet('File','Folder')][string]$PickerType = 'Folder',
        [string]$FileFilter = 'All files (*.*)|*.*',
        [string]$Watermark  = ''
    )

    $sp = New-OptionsSection -Heading $Heading -Description $Description

    $grid = New-Object System.Windows.Controls.Grid
    $c1 = New-Object System.Windows.Controls.ColumnDefinition
    $c1.Width = [System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)
    $c2 = New-Object System.Windows.Controls.ColumnDefinition
    $c2.Width = [System.Windows.GridLength]::Auto
    [void]$grid.ColumnDefinitions.Add($c1)
    [void]$grid.ColumnDefinitions.Add($c2)

    $txt = New-Object System.Windows.Controls.TextBox
    $txt.Text = [string]$global:Prefs[$PrefKey]
    $txt.FontSize = 12
    $txt.FontFamily = New-Object System.Windows.Media.FontFamily('Cascadia Code, Consolas, Courier New')
    $txt.Padding = [System.Windows.Thickness]::new(6,4,6,4)
    $txt.VerticalContentAlignment = [System.Windows.VerticalAlignment]::Center
    if ($Watermark) {
        [MahApps.Metro.Controls.TextBoxHelper]::SetWatermark($txt, $Watermark)
    }
    [System.Windows.Controls.Grid]::SetColumn($txt, 0)
    [void]$grid.Children.Add($txt)

    $btn = New-Object System.Windows.Controls.Button
    $btn.Content = 'Browse...'
    $btn.MinWidth = 90
    $btn.Height = 28
    $btn.Margin = [System.Windows.Thickness]::new(8,0,0,0)
    $btn.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'MahApps.Styles.Button.Square')
    [MahApps.Metro.Controls.ControlsHelper]::SetContentCharacterCasing($btn, [System.Windows.Controls.CharacterCasing]::Normal)
    [System.Windows.Controls.Grid]::SetColumn($btn, 1)
    [void]$grid.Children.Add($btn)

    # Browse handler fires after the factory returns; GetNewClosure captures
    # the panel-local refs.
    $localType   = $PickerType
    $localFilter = $FileFilter
    $localOwner  = $dlg
    $btn.Add_Click({
        if ($localType -eq 'File') {
            $ofd = New-Object Microsoft.Win32.OpenFileDialog
            $ofd.Filter = $localFilter
            $ofd.Multiselect = $false
            if ($ofd.ShowDialog($localOwner)) { $txt.Text = $ofd.FileName }
        } else {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
            $fbd.ShowNewFolderButton = $true
            if ($txt.Text -and (Test-Path -LiteralPath $txt.Text)) { $fbd.SelectedPath = $txt.Text }
            if ($fbd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $txt.Text = $fbd.SelectedPath }
        }
    }.GetNewClosure())

    [void]$sp.Children.Add($grid)

    $localKey = $PrefKey
    $commit = {
        $global:Prefs[$localKey] = [string]$txt.Text
    }.GetNewClosure()

    return @{ Name = $Name; Element = $sp; Commit = $commit }
}

function New-LoggingPanel {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs WPF panel; no external state.')]
    param()

    $sp = New-OptionsSection -Heading 'Logging' -Description 'Per-session logs are written to the Logs folder beside start-installeranalysis.ps1. Click Open Logs Folder to review recent sessions.'

    $row = New-Object System.Windows.Controls.StackPanel
    $row.Orientation = [System.Windows.Controls.Orientation]::Horizontal
    $row.Margin = [System.Windows.Thickness]::new(0,0,0,0)

    $pathLabel = New-Object System.Windows.Controls.TextBlock
    $pathLabel.Text = [string]$__txDir
    $pathLabel.FontSize = 11
    $pathLabel.FontFamily = New-Object System.Windows.Media.FontFamily('Cascadia Code, Consolas, Courier New')
    $pathLabel.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $pathLabel.Margin = [System.Windows.Thickness]::new(0,0,12,0)
    $pathLabel.TextWrapping = [System.Windows.TextWrapping]::Wrap
    [void]$row.Children.Add($pathLabel)

    $btn = New-Object System.Windows.Controls.Button
    $btn.Content = 'Open Logs Folder'
    $btn.MinWidth = 140
    $btn.Height = 28
    $btn.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'MahApps.Styles.Button.Square')
    [MahApps.Metro.Controls.ControlsHelper]::SetContentCharacterCasing($btn, [System.Windows.Controls.CharacterCasing]::Normal)
    # Factory-returned handler needs GetNewClosure to see the captured
    # $localLogDir path when the click fires.
    $localLogDir = $__txDir
    $btn.Add_Click({
        if (Test-Path -LiteralPath $localLogDir) {
            Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $localLogDir)
        }
    }.GetNewClosure())
    [void]$row.Children.Add($btn)

    [void]$sp.Children.Add($row)

    $commit = { }.GetNewClosure()
    return @{ Name = 'Logging'; Element = $sp; Commit = $commit }
}

function New-AboutPanel {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs WPF panel; no external state.')]
    param()

    $sp = New-OptionsSection -Heading 'About' -Description 'Installer Analysis -- a PowerShell + WPF analyzer for MSI, EXE, MSIX, .intunewin, .nupkg, PSADT, and Squirrel installers.'

    $grid = New-Object System.Windows.Controls.Grid
    $c1 = New-Object System.Windows.Controls.ColumnDefinition
    $c1.Width = [System.Windows.GridLength]::Auto
    $c2 = New-Object System.Windows.Controls.ColumnDefinition
    $c2.Width = [System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)
    [void]$grid.ColumnDefinitions.Add($c1)
    [void]$grid.ColumnDefinitions.Add($c2)

    $rows = @(
        @{ K = 'Version';    V = 'v1.0.0.0' },
        @{ K = 'Author';     V = 'Jason Ulbright' },
        @{ K = 'License';    V = 'MIT' },
        @{ K = 'Formats';    V = '17 detected types -- MSI, NSIS, Inno Setup, InstallShield, WiX Burn, Advanced Installer, 7zSFX, WinRAR SFX, Chocolatey, NuGet, Intunewin, MSIX, MSIX Bundle, PSADT v3, PSADT v4, Squirrel, Unknown' },
        @{ K = 'Offline';    V = 'No NuGet, no runtime network pulls. MahApps.Metro / ControlzEx / Xaml.Behaviors vendored under Lib/.' },
        @{ K = 'Repository'; V = 'https://github.com/jasonulbright/installer-analysis' }
    )

    for ($i = 0; $i -lt $rows.Count; $i++) {
        $rd = New-Object System.Windows.Controls.RowDefinition
        $rd.Height = [System.Windows.GridLength]::Auto
        [void]$grid.RowDefinitions.Add($rd)

        $k = New-Object System.Windows.Controls.TextBlock
        $k.Text = [string]$rows[$i].K
        $k.FontSize = 12
        $k.FontWeight = [System.Windows.FontWeights]::SemiBold
        $k.Margin = [System.Windows.Thickness]::new(0,0,16,6)
        $k.VerticalAlignment = [System.Windows.VerticalAlignment]::Top
        [System.Windows.Controls.Grid]::SetRow($k, $i)
        [System.Windows.Controls.Grid]::SetColumn($k, 0)
        [void]$grid.Children.Add($k)

        $v = New-Object System.Windows.Controls.TextBlock
        $v.Text = [string]$rows[$i].V
        $v.FontSize = 12
        $v.TextWrapping = [System.Windows.TextWrapping]::Wrap
        $v.Margin = [System.Windows.Thickness]::new(0,0,0,6)
        [System.Windows.Controls.Grid]::SetRow($v, $i)
        [System.Windows.Controls.Grid]::SetColumn($v, 1)
        [void]$grid.Children.Add($v)
    }

    [void]$sp.Children.Add($grid)

    $commit = { }.GetNewClosure()
    return @{ Name = 'About'; Element = $sp; Commit = $commit }
}

# =============================================================================
# Show-InstallerAnalysisOptions: in-app MetroWindow with left-nav ListBox +
# right-pane ScrollViewer. Panels return @{Name; Element; Commit};
# Commit scriptblocks are GetNewClosure'd to survive factory-return.
# =============================================================================
function Show-InstallerAnalysisOptions {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Shows a modal MetroWindow; OK handler writes back to $global:Prefs via panel Commit scriptblocks and the caller calls Save-IatPreferences. No external state beyond prefs.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Renders the Options MetroWindow; the composite noun matches the window it shows, not any underlying collection.')]
    param([Parameter(Mandatory)]$Owner)

    $dlgXaml = @'
<Controls:MetroWindow
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:Controls="clr-namespace:MahApps.Metro.Controls;assembly=MahApps.Metro"
    Title="Options"
    Width="860" Height="560"
    MinWidth="720" MinHeight="460"
    WindowStartupLocation="CenterOwner"
    TitleCharacterCasing="Normal"
    ShowIconOnTitleBar="False"
    GlowBrush="{DynamicResource MahApps.Brushes.Accent}"
    BorderThickness="1">
    <Window.Resources>
        <ResourceDictionary>
            <ResourceDictionary.MergedDictionaries>
                <ResourceDictionary Source="pack://application:,,,/MahApps.Metro;component/Styles/Controls.xaml" />
                <ResourceDictionary Source="pack://application:,,,/MahApps.Metro;component/Styles/Fonts.xaml" />
                <ResourceDictionary Source="pack://application:,,,/MahApps.Metro;component/Styles/Themes/Dark.Steel.xaml" />
            </ResourceDictionary.MergedDictionaries>
        </ResourceDictionary>
    </Window.Resources>
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="210"/>
            <ColumnDefinition Width="1"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <ListBox Grid.Column="0" Grid.Row="0" x:Name="lstNav" BorderThickness="0" Padding="0,8,0,0">
            <ListBox.ItemContainerStyle>
                <Style TargetType="ListBoxItem">
                    <Setter Property="Padding" Value="16,10,16,10"/>
                    <Setter Property="FontSize" Value="13"/>
                </Style>
            </ListBox.ItemContainerStyle>
        </ListBox>
        <Border Grid.Column="1" Grid.Row="0" Background="{DynamicResource MahApps.Brushes.Gray8}"/>
        <ScrollViewer Grid.Column="2" Grid.Row="0" VerticalScrollBarVisibility="Auto">
            <ContentControl x:Name="contentArea" Margin="20,18,20,18"/>
        </ScrollViewer>
        <Border Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1"
                BorderBrush="{DynamicResource MahApps.Brushes.Gray8}" BorderThickness="0,1,0,0">
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="20,12,20,12">
                <Button x:Name="btnOK"     Content="OK"     MinWidth="90" Height="32" Margin="0,0,8,0" IsDefault="True"
                        Style="{DynamicResource MahApps.Styles.Button.Square.Accent}"
                        Controls:ControlsHelper.ContentCharacterCasing="Normal"/>
                <Button x:Name="btnCancel" Content="Cancel" MinWidth="90" Height="32" IsCancel="True"
                        Style="{DynamicResource MahApps.Styles.Button.Square}"
                        Controls:ControlsHelper.ContentCharacterCasing="Normal"/>
            </StackPanel>
        </Border>
    </Grid>
</Controls:MetroWindow>
'@

    [xml]$xml = $dlgXaml
    $xmlReader = New-Object System.Xml.XmlNodeReader $xml
    $dlg    = [System.Windows.Markup.XamlReader]::Load($xmlReader)
    Install-TitleBarDragFallback -Window $dlg

    $theme = [ControlzEx.Theming.ThemeManager]::Current.DetectTheme($Owner)
    if ($theme) { [void][ControlzEx.Theming.ThemeManager]::Current.ChangeTheme($dlg, $theme) }
    $dlg.Owner = $Owner
    try {
        $dlg.WindowTitleBrush          = $Owner.WindowTitleBrush
        $dlg.NonActiveWindowTitleBrush = $Owner.NonActiveWindowTitleBrush
        $dlg.GlowBrush                 = $Owner.GlowBrush
        $dlg.NonActiveGlowBrush        = $Owner.NonActiveGlowBrush
    } catch { $null = $_ }

    $lstNav      = $dlg.FindName('lstNav')
    $contentArea = $dlg.FindName('contentArea')
    $btnOK       = $dlg.FindName('btnOK')
    $btnCancel   = $dlg.FindName('btnCancel')

    $panels = @(
        (New-PathPickerPanel -Name '7-Zip Path' -Heading '7-Zip executable' -Description 'Path to 7z.exe for payload listing + extraction. Leave blank to auto-detect in Program Files.' -PrefKey 'SevenZipPath'  -PickerType File -FileFilter '7z.exe|7z.exe|All files|*.*' -Watermark 'C:\Program Files\7-Zip\7z.exe (auto-detect when blank)'),
        (New-LoggingPanel),
        (New-PathPickerPanel -Name 'Reports'    -Heading 'Reports folder'    -Description 'Default folder for CSV and HTML exports. The Save dialog still lets you pick an ad-hoc location per export.' -PrefKey 'ReportsFolder' -PickerType Folder -Watermark 'Defaults to ./Reports next to the script'),
        (New-AboutPanel)
    )

    foreach ($p in $panels) { [void]$lstNav.Items.Add($p.Name) }

    $lstNav.Add_SelectionChanged({
        $i = $lstNav.SelectedIndex
        if ($i -ge 0 -and $i -lt $panels.Count) {
            $contentArea.Content = $panels[$i].Element
        }
    })
    $lstNav.SelectedIndex = 0

    $script:OptionsDialogResult = $false

    $btnOK.Add_Click({
        foreach ($p in $panels) {
            if ($p.Commit) { & $p.Commit }
        }
        Save-IatPreferences -Prefs $global:Prefs
        $script:OptionsDialogResult = $true
        $dlg.Close()
    })

    $btnCancel.Add_Click({
        $script:OptionsDialogResult = $false
        $dlg.Close()
    })

    [void]$dlg.ShowDialog()
    return [bool]$script:OptionsDialogResult
}

# =============================================================================
# Button handlers.
# =============================================================================
function Invoke-FilePicker {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Shows an OpenFileDialog and updates the in-window path; no external state.')]
    param()

    $initialDir = if ($global:Prefs['LastBrowseDir'] -and (Test-Path -LiteralPath $global:Prefs['LastBrowseDir'])) {
        $global:Prefs['LastBrowseDir']
    } else { [Environment]::GetFolderPath('Desktop') }

    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Installer packages (*.exe;*.msi;*.msp;*.msix;*.msixbundle;*.appx;*.appxbundle;*.intunewin;*.nupkg;*.zip)|*.exe;*.msi;*.msp;*.msix;*.msixbundle;*.appx;*.appxbundle;*.intunewin;*.nupkg;*.zip|All files (*.*)|*.*'
    $dlg.Multiselect = $false
    $dlg.InitialDirectory = $initialDir
    if ($dlg.ShowDialog($window)) {
        $txtFilePath.Text = $dlg.FileName
        $global:Prefs['LastBrowseDir'] = [System.IO.Path]::GetDirectoryName($dlg.FileName)
        Save-IatPreferences -Prefs $global:Prefs
        Add-LogLine ('Selected: {0}' -f $dlg.FileName)
        Set-StatusText ('Ready to analyze: {0}' -f [System.IO.Path]::GetFileName($dlg.FileName))
        Invoke-AnalysisPipeline
    }
}

function Invoke-Save-FilePicker {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Returns the chosen path; the caller performs the write.')]
    param(
        [Parameter(Mandatory)][string]$Filter,
        [Parameter(Mandatory)][string]$DefaultExt,
        [Parameter(Mandatory)][string]$DefaultName
    )
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = $Filter
    $dlg.DefaultExt = $DefaultExt
    $dlg.FileName = $DefaultName

    # Prefer the Options-configured Reports folder, fall back to a Reports
    # subdir next to the script, fall back to Documents. The first writable
    # directory wins so Save is a single click without typing a path.
    $initial = $null
    $candidates = @()
    if ($global:Prefs['ReportsFolder']) { $candidates += [string]$global:Prefs['ReportsFolder'] }
    $candidates += (Join-Path $PSScriptRoot 'Reports')
    $candidates += [Environment]::GetFolderPath('MyDocuments')
    foreach ($c in $candidates) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if (-not (Test-Path -LiteralPath $c)) {
            try { New-Item -ItemType Directory -Path $c -Force -ErrorAction Stop | Out-Null } catch { $null = $_ }
        }
        if (Test-Path -LiteralPath $c -PathType Container) { $initial = $c; break }
    }
    if ($initial) { $dlg.InitialDirectory = $initial }

    if ($dlg.ShowDialog($window)) { return [string]$dlg.FileName }
    return $null
}

$btnBrowse.Add_Click({ Invoke-FilePicker })

# Ctrl+O opens the Browse dialog. Window-level so focus location doesn't
# matter. Gated on btnBrowse.IsEnabled (disabled while analysis runs).
$window.Add_PreviewKeyDown({
    param($s, $e)
    $null = $s
    if ($e.Key -eq [System.Windows.Input.Key]::O -and
        ($e.KeyboardDevice.Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -eq [System.Windows.Input.ModifierKeys]::Control -and
        ($e.KeyboardDevice.Modifiers -band [System.Windows.Input.ModifierKeys]::Alt) -eq 0) {
        if ($btnBrowse.IsEnabled) {
            Invoke-FilePicker
        }
        $e.Handled = $true
    }
})

$txtFilePath.Add_KeyDown({
    param($s, $e)
    $null = $s
    if ($e.Key -eq [System.Windows.Input.Key]::Enter) {
        Invoke-AnalysisPipeline
        $e.Handled = $true
    }
})

$txtStringsFilter.Add_TextChanged({
    param($s, $e)
    $null = $s; $null = $e
    Show-StringsGrid -Filter $txtStringsFilter.Text
})

$btnCopySummary.Add_Click({
    if (-not $script:LastFileInfo) { Add-LogLine 'Copy Summary: no analysis result yet.'; return }
    $summary = New-AnalysisSummaryText `
        -FileInfo         $script:LastFileInfo `
        -InstallerType    $script:LastInstallerType `
        -Switches         $script:LastSwitches `
        -MsiProperties    $script:LastMsiProperties `
        -DeploymentFields $script:LastDeployment `
        -PackageMetadata  $script:LastPackageMetadata `
        -MspMetadata      $script:LastMspMetadata `
        -InnerMsiData     $script:LastInnerMsiData
    Set-Clipboard -Value $summary
    Add-LogLine    'Copy Summary: text copied to clipboard.'
    Set-StatusText 'Summary copied to clipboard.'
})

$btnCopyJson.Add_Click({
    if (-not $script:LastFileInfo) { Add-LogLine 'Copy JSON: no analysis result yet.'; return }
    $json = ConvertTo-DeploymentJson `
        -FileInfo         $script:LastFileInfo `
        -InstallerType    $script:LastInstallerType `
        -Switches         $script:LastSwitches `
        -DeploymentFields $script:LastDeployment `
        -MsiProperties    $script:LastMsiProperties `
        -PackageMetadata  $script:LastPackageMetadata
    Set-Clipboard -Value $json
    Add-LogLine    'Copy JSON: MECM-ready digest copied to clipboard.'
    Set-StatusText 'MECM JSON copied to clipboard.'
})

function New-AnalysisDataTable {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Pure constructor for a DataTable snapshot of the current analysis.')]
    param()

    $dt = New-Object System.Data.DataTable
    [void]$dt.Columns.Add('Section')
    [void]$dt.Columns.Add('Property')
    [void]$dt.Columns.Add('Value')

    $fi = $script:LastFileInfo
    if ($fi) {
        [void]$dt.Rows.Add('Source', 'FileName', [string]$fi.FileName)
        [void]$dt.Rows.Add('Source', 'FullPath', [string]$fi.FullPath)
        [void]$dt.Rows.Add('Source', 'FileSize', [string]$fi.FileSize)
        [void]$dt.Rows.Add('Source', 'SHA256', [string]$fi.SHA256)
        [void]$dt.Rows.Add('Source', 'Architecture', [string]$fi.Architecture)
        [void]$dt.Rows.Add('Source', 'SignatureStatus', [string]$fi.SignatureStatus)
        if ($fi.SignerSubject)    { [void]$dt.Rows.Add('Source', 'SignerSubject',    [string]$fi.SignerSubject) }
        if ($fi.SignerIssuer)     { [void]$dt.Rows.Add('Source', 'SignerIssuer',     [string]$fi.SignerIssuer) }
        if ($fi.SignerThumbprint) { [void]$dt.Rows.Add('Source', 'SignerThumbprint', [string]$fi.SignerThumbprint) }
        if ($fi.FileVersion)      { [void]$dt.Rows.Add('Source', 'FileVersion',      [string]$fi.FileVersion) }
        if ($fi.ProductVersion)   { [void]$dt.Rows.Add('Source', 'ProductVersion',   [string]$fi.ProductVersion) }
        if ($fi.ProductName)      { [void]$dt.Rows.Add('Source', 'ProductName',      [string]$fi.ProductName) }
        if ($fi.CompanyName)      { [void]$dt.Rows.Add('Source', 'CompanyName',      [string]$fi.CompanyName) }
    }

    [void]$dt.Rows.Add('Application', 'InstallerType', [string]$script:LastInstallerType)

    $df = $script:LastDeployment
    if ($df) {
        [void]$dt.Rows.Add('Application', 'DisplayName',    [string]$df.DisplayName)
        [void]$dt.Rows.Add('Application', 'DisplayVersion', [string]$df.DisplayVersion)
        [void]$dt.Rows.Add('Application', 'Publisher',      [string]$df.Vendor)
    }

    $sw = $script:LastSwitches
    if ($sw) {
        [void]$dt.Rows.Add('Deployment', 'InstallCommand',   [string]$sw.Install)
        [void]$dt.Rows.Add('Deployment', 'UninstallCommand', [string]$sw.Uninstall)
        if ($sw.Notes) { [void]$dt.Rows.Add('Deployment', 'Notes', [string]$sw.Notes) }
    }
    if ($df -and $df.SilentUninstallString -and $df.SilentUninstallString -ne $sw.Uninstall) {
        [void]$dt.Rows.Add('Deployment', 'UninstallCommand.Resolved', [string]$df.SilentUninstallString)
    }

    if ($script:LastMsiProperties -and $script:LastMsiProperties.Count -gt 0) {
        foreach ($k in $script:LastMsiProperties.Keys) {
            [void]$dt.Rows.Add('MsiProperty', [string]$k, [string]$script:LastMsiProperties[$k])
        }
    }

    $pkg = $script:LastPackageMetadata
    if ($pkg) {
        foreach ($p in $pkg.PSObject.Properties) {
            $name = $p.Name
            $val  = $p.Value
            if ($null -eq $val) { continue }
            if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
                [void]$dt.Rows.Add('PackageMetadata', $name, ('(' + (@($val).Count) + ' items)'))
            } else {
                [void]$dt.Rows.Add('PackageMetadata', $name, [string]$val)
            }
        }
    }

    return ,$dt
}

$btnExportCsv.Add_Click({
    if (-not $script:LastFileInfo) { Add-LogLine 'Export CSV: no analysis result yet.'; return }
    $default = ('{0}-analysis.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($script:LastFileInfo.FullPath))
    $out = Invoke-Save-FilePicker -Filter 'CSV (*.csv)|*.csv' -DefaultExt '.csv' -DefaultName $default
    if (-not $out) { return }
    try {
        $dt = New-AnalysisDataTable
        Export-AnalysisReport -DataTable $dt -OutputPath $out
        Add-LogLine    ('Export CSV: wrote {0}' -f $out)
        Set-StatusText ('Exported CSV: {0}' -f [System.IO.Path]::GetFileName($out))
    } catch {
        Add-LogLine ('Export CSV failed: {0}' -f $_.Exception.Message)
    }
})

$btnExportHtml.Add_Click({
    if (-not $script:LastFileInfo) { Add-LogLine 'Export HTML: no analysis result yet.'; return }
    $default = ('{0}-analysis.html' -f [System.IO.Path]::GetFileNameWithoutExtension($script:LastFileInfo.FullPath))
    $out = Invoke-Save-FilePicker -Filter 'HTML (*.html)|*.html' -DefaultExt '.html' -DefaultName $default
    if (-not $out) { return }
    try {
        $dt = New-AnalysisDataTable
        Export-AnalysisHtml -DataTable $dt -OutputPath $out -ReportTitle ('Installer Analysis -- ' + $script:LastFileInfo.FileName)
        Add-LogLine    ('Export HTML: wrote {0}' -f $out)
        Set-StatusText ('Exported HTML: {0}' -f [System.IO.Path]::GetFileName($out))
    } catch {
        Add-LogLine ('Export HTML failed: {0}' -f $_.Exception.Message)
    }
})

$btnExtractAll.Add_Click({
    if (-not $script:LastFileInfo -or -not $script:LastPayload) {
        Add-LogLine 'Extract Payload: no payload listed for the current file.'
        return
    }
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.Description = 'Choose a folder to extract the installer payload into.'
    $fbd.ShowNewFolderButton = $true
    if ($fbd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $target = $fbd.SelectedPath

    # Confirm before extracting into a non-empty folder. Payload extraction can
    # stomp files the user didn't realize were there; brand checklist section 5
    # wants destructive actions gated.
    $existingCount = 0
    try {
        $existingCount = @(Get-ChildItem -LiteralPath $target -Force -ErrorAction Stop).Count
    } catch { $null = $_ }
    if ($existingCount -gt 0) {
        $ans = Show-ThemedMessage -Owner $window `
            -Title   'Target folder is not empty' `
            -Message ('"{0}" already contains {1} item(s). Extracting may overwrite files with the same names. Continue?' -f $target, $existingCount) `
            -Buttons 'YesNo' -Icon 'Warn'
        if ($ans -ne 'Yes') {
            Add-LogLine 'Extract Payload: canceled (target not empty).'
            return
        }
    }

    $sevenZip = $global:Prefs['SevenZipPath']
    if (-not $sevenZip -or -not (Test-Path -LiteralPath $sevenZip)) { $sevenZip = Find-7ZipPath }
    if (-not $sevenZip) {
        Add-LogLine 'Extract Payload: 7z.exe not found.'
        return
    }
    Set-StatusText ('Extracting to {0}' -f $target)
    Add-LogLine    ('Extract Payload: -> {0}' -f $target)

    # Show the progress overlay during the extract. 7z.exe on a 300MB
    # installer can run for minutes; without the overlay the shell looks
    # frozen. Same spinner used by Invoke-AnalysisPipeline.
    $txtProgressTitle.Text = 'Extracting payload...'
    $txtProgressStep.Text  = ('Running 7z.exe x "{0}" -o"{1}"' -f [System.IO.Path]::GetFileName($script:LastFileInfo.FullPath), $target)
    $progressOverlay.Visibility = [System.Windows.Visibility]::Visible
    $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

    try {
        Expand-InstallerPayload -Path $script:LastFileInfo.FullPath -OutputPath $target -SevenZipPath $sevenZip
        Add-LogLine    'Extract Payload: complete.'
        Set-StatusText ('Extracted: {0}' -f $target)
    } catch {
        Add-LogLine ('Extract Payload failed: {0}' -f $_.Exception.Message)
    } finally {
        $progressOverlay.Visibility = [System.Windows.Visibility]::Collapsed
    }
})

$btnOptions.Add_Click({
    $ok = Show-InstallerAnalysisOptions -Owner $window
    if ($ok) {
        Add-LogLine    'Options: preferences saved.'
        Set-StatusText 'Options saved.'
    } else {
        Add-LogLine 'Options: canceled.'
    }
})

# =============================================================================
# Inner Installers + right-click context menu handlers.
# =============================================================================

function Get-SelectedPayloadEntries {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns the selected DataGrid rows; plural matches the collection being returned.')]
    param([System.Windows.Controls.DataGrid]$Grid)
    if (-not $Grid -or -not $Grid.SelectedItems) { return @() }
    return @($Grid.SelectedItems)
}

function Invoke-PayloadExtractToTemp {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Extracts to %LOCALAPPDATA% inspect dir and opens Explorer; idempotent.')]
    param([object[]]$Entries)

    if (-not $Entries -or $Entries.Count -eq 0) {
        Add-LogLine 'Extract to temp: no rows selected.'
        return
    }
    if (-not $script:LastFileInfo) {
        Add-LogLine 'Extract to temp: no analysis result yet.'
        return
    }

    $dir = Get-InspectTempDir -Sha256 ([string]$script:LastFileInfo.SHA256)
    $ok = 0
    foreach ($e in $Entries) {
        $extracted = Invoke-7zExtractSingle `
            -ArchivePath $script:LastFileInfo.FullPath `
            -EntryName   ([string]$e.Name) `
            -OutputDir   $dir
        if ($extracted) { $ok++ }
    }
    Add-LogLine ('Extracted {0}/{1} entries to {2}' -f $ok, $Entries.Count, $dir)
    Set-StatusText ('Extracted {0} entries to inspect folder' -f $ok)
    try { Start-Process explorer.exe $dir } catch { $null = $_ }
}

function Invoke-PayloadCopyName {
    param([object[]]$Entries)
    if (-not $Entries -or $Entries.Count -eq 0) { return }
    $names = @($Entries | ForEach-Object { [string]$_.Name })
    Set-Clipboard -Value ($names -join [Environment]::NewLine)
    Add-LogLine ('Copied {0} name(s) to clipboard.' -f $names.Count)
    Set-StatusText ('Copied {0} name(s).' -f $names.Count)
}

function Invoke-PayloadCopyPath {
    # In-archive path: 7-Zip reports it directly as Name (with any subdir
    # prefix), which is what 7z e -i! expects.
    param([object[]]$Entries)
    if (-not $Entries -or $Entries.Count -eq 0) { return }
    $names = @($Entries | ForEach-Object { [string]$_.Name })
    Set-Clipboard -Value ($names -join [Environment]::NewLine)
    Add-LogLine ('Copied {0} in-archive path(s) to clipboard.' -f $names.Count)
    Set-StatusText ('Copied {0} path(s).' -f $names.Count)
}

function Invoke-PayloadHash {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Extracts to temp + writes SHA-256 to the clipboard / log; idempotent.')]
    param([object[]]$Entries)

    if (-not $Entries -or $Entries.Count -eq 0) {
        Add-LogLine 'Hash: no rows selected.'
        return
    }
    if (-not $script:LastFileInfo) {
        Add-LogLine 'Hash: no analysis result yet.'
        return
    }

    $dir = Get-InspectTempDir -Sha256 ([string]$script:LastFileInfo.SHA256)
    $hashes = @()
    foreach ($e in $Entries) {
        $extracted = Invoke-7zExtractSingle `
            -ArchivePath $script:LastFileInfo.FullPath `
            -EntryName   ([string]$e.Name) `
            -OutputDir   $dir
        if (-not $extracted) {
            Add-LogLine ('Hash: extraction failed for {0}' -f [string]$e.Name)
            continue
        }
        $h = (Get-FileHash -LiteralPath $extracted -Algorithm SHA256).Hash
        $hashes += ('{0}  {1}' -f $h, [string]$e.Name)
        Add-LogLine ('SHA256 {0}  {1}' -f $h, [string]$e.Name)
    }
    if ($hashes.Count -gt 0) {
        Set-Clipboard -Value ($hashes -join [Environment]::NewLine)
        Set-StatusText ('Hashed {0} entries; SHA-256 copied to clipboard.' -f $hashes.Count)
    }
}

function Invoke-AnalyzeSelectedEmbedded {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Pushes drill-down state, extracts the selected entry to temp, re-runs the pipeline.')]
    param([object]$Entry)

    if (-not $Entry) {
        Add-LogLine 'Analyze Selected: no row selected.'
        return
    }
    if (-not $script:LastFileInfo) {
        Add-LogLine 'Analyze Selected: no analysis result yet.'
        return
    }
    if (-not $Entry.IsAnalyzable) {
        Add-LogLine ('Analyze Selected: entry not analyzable ({0})' -f [string]$Entry.Name)
        return
    }

    $depth = $script:AnalysisStack.Count + 1
    $dir = Get-DrillTempDir -Sha256 ([string]$script:LastFileInfo.SHA256) -Depth $depth
    $extracted = Invoke-7zExtractSingle `
        -ArchivePath $script:LastFileInfo.FullPath `
        -EntryName   ([string]$Entry.Name) `
        -OutputDir   $dir
    if (-not $extracted) {
        Add-LogLine ('Analyze Selected: extraction failed for {0}' -f [string]$Entry.Name)
        Set-StatusText 'Analyze Selected: extraction failed.'
        return
    }

    if (-not (Push-AnalysisStack)) { return }
    $txtFilePath.Text = $extracted
    Add-LogLine ('Drilling into: {0} (depth {1})' -f $Entry.Name, $script:AnalysisStack.Count)
    Invoke-AnalysisPipeline
}

function Open-EmbeddedInNewWindow {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Extracts to temp + spawns a sibling analyzer process; no in-window state change.')]
    param([object]$Entry)

    if (-not $Entry -or -not $script:LastFileInfo) {
        Add-LogLine 'Open in new window: no row / file context.'
        return
    }
    $dir = Get-InspectTempDir -Sha256 ([string]$script:LastFileInfo.SHA256)
    $extracted = Invoke-7zExtractSingle `
        -ArchivePath $script:LastFileInfo.FullPath `
        -EntryName   ([string]$Entry.Name) `
        -OutputDir   $dir
    if (-not $extracted) {
        Add-LogLine ('Open in new window: extraction failed for {0}' -f [string]$Entry.Name)
        return
    }

    $psExe = (Get-Process -Id $PID).Path
    # -ExecutionPolicy Bypass here spawns a sibling analyzer process running this
    # same script under the current user. It does not change system-wide
    # execution policy; WPF requires STA, and this re-launches the script the
    # user already chose to run.
    $args  = @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File', $PSCommandPath, '-StartupFile', $extracted)
    try {
        Start-Process -FilePath $psExe -ArgumentList $args | Out-Null
        Add-LogLine ('Spawned analyzer for {0}' -f $extracted)
    } catch {
        Add-LogLine ('Open in new window failed: {0}' -f $_.Exception.Message)
    }
}

# ---- Action row buttons (Inner Installers tab) ----
$btnExtractAllInner.Add_Click({
    if (-not $script:LastEmbedded -or @($script:LastEmbedded).Count -eq 0) {
        Add-LogLine 'Extract All Inner: no inner installers.'
        return
    }
    if (-not $script:LastFileInfo) {
        Add-LogLine 'Extract All Inner: no analysis result yet.'
        return
    }

    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.Description = 'Choose a folder to extract every classified inner installer into.'
    $fbd.ShowNewFolderButton = $true
    if ($fbd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $target = $fbd.SelectedPath

    $entries = @($script:LastEmbedded)
    $ok = 0
    foreach ($e in $entries) {
        $extracted = Invoke-7zExtractSingle `
            -ArchivePath $script:LastFileInfo.FullPath `
            -EntryName   ([string]$e.Name) `
            -OutputDir   $target
        if ($extracted) { $ok++ }
    }
    Add-LogLine ('Extract All Inner: {0}/{1} entries extracted to {2}' -f $ok, $entries.Count, $target)
    Set-StatusText ('Extracted {0} inner installer(s).' -f $ok)
    try { Start-Process explorer.exe $target } catch { $null = $_ }
})

$btnAnalyzeSelectedInner.Add_Click({
    $sel = $gridEmbedded.SelectedItem
    Invoke-AnalyzeSelectedEmbedded -Entry $sel
})

$gridEmbedded.Add_MouseDoubleClick({
    $sel = $gridEmbedded.SelectedItem
    if ($sel) { Invoke-AnalyzeSelectedEmbedded -Entry $sel }
})

# Right-click selects the targeted row. Walks the visual tree from the
# click source to the DataGridRow and force-selects before the ContextMenu
# opens; without this, right-click leaves the previous selection in place.
$rightClickSelectsRow = {
    param($s, $e)
    $null = $s
    $dep = $e.OriginalSource -as [System.Windows.DependencyObject]
    while ($null -ne $dep -and -not ($dep -is [System.Windows.Controls.DataGridRow])) {
        $dep = [System.Windows.Media.VisualTreeHelper]::GetParent($dep)
    }
    if ($null -ne $dep) {
        $row = [System.Windows.Controls.DataGridRow]$dep
        if (-not $row.IsSelected) { $row.IsSelected = $true }
    }
}
$gridPayload.Add_PreviewMouseRightButtonDown($rightClickSelectsRow)
$gridEmbedded.Add_PreviewMouseRightButtonDown($rightClickSelectsRow)

$btnOpenInNewWindow.Add_Click({
    $sel = $gridEmbedded.SelectedItem
    Open-EmbeddedInNewWindow -Entry $sel
})

# ---- Breadcrumb ----
$btnBreadcrumbBack.Add_Click({ Pop-AnalysisStack })

# ---- Payload grid context menu ----
$ctxPayloadExtractTemp.Add_Click({
    Invoke-PayloadExtractToTemp -Entries (Get-SelectedPayloadEntries -Grid $gridPayload)
})
$ctxPayloadCopyName.Add_Click({
    Invoke-PayloadCopyName -Entries (Get-SelectedPayloadEntries -Grid $gridPayload)
})
$ctxPayloadCopyPath.Add_Click({
    Invoke-PayloadCopyPath -Entries (Get-SelectedPayloadEntries -Grid $gridPayload)
})
$ctxPayloadHash.Add_Click({
    Invoke-PayloadHash -Entries (Get-SelectedPayloadEntries -Grid $gridPayload)
})

# ---- Inner Installers grid context menu ----
$ctxEmbAnalyze.Add_Click({
    Invoke-AnalyzeSelectedEmbedded -Entry $gridEmbedded.SelectedItem
})
$ctxEmbOpenNew.Add_Click({
    Open-EmbeddedInNewWindow -Entry $gridEmbedded.SelectedItem
})
$ctxEmbExtractTemp.Add_Click({
    Invoke-PayloadExtractToTemp -Entries (Get-SelectedPayloadEntries -Grid $gridEmbedded)
})
$ctxEmbCopyName.Add_Click({
    Invoke-PayloadCopyName -Entries (Get-SelectedPayloadEntries -Grid $gridEmbedded)
})
$ctxEmbCopyPath.Add_Click({
    Invoke-PayloadCopyPath -Entries (Get-SelectedPayloadEntries -Grid $gridEmbedded)
})
$ctxEmbHash.Add_Click({
    Invoke-PayloadHash -Entries (Get-SelectedPayloadEntries -Grid $gridEmbedded)
})

# ---- Path TextBox context menu ----
$ctxPathCopyPath.Add_Click({
    $p = [string]$txtFilePath.Text
    if (-not [string]::IsNullOrWhiteSpace($p)) {
        Set-Clipboard -Value $p
        Add-LogLine 'Copied current file path to clipboard.'
        Set-StatusText 'Path copied.'
    }
})
$ctxPathOpenFolder.Add_Click({
    $p = [string]$txtFilePath.Text
    if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)) {
        Start-Process explorer.exe ('/select,"{0}"' -f $p)
    } else {
        Add-LogLine 'Open enclosing folder: path is empty or does not exist.'
    }
})
$ctxPathReanalyze.Add_Click({
    Invoke-AnalysisPipeline
})

# =============================================================================
# Drag-drop.
# =============================================================================
$window.Add_PreviewDragEnter({
    param($s, $e)
    $null = $s
    if ($e.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        $dropOverlay.Visibility = [System.Windows.Visibility]::Visible
    }
    $e.Handled = $true
})

$window.Add_PreviewDragOver({
    param($s, $e)
    $null = $s
    if ($e.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        $e.Effects = [System.Windows.DragDropEffects]::Copy
        $dropOverlay.Visibility = [System.Windows.Visibility]::Visible
    } else {
        $e.Effects = [System.Windows.DragDropEffects]::None
    }
    $e.Handled = $true
})

$window.Add_PreviewDragLeave({
    param($s, $e)
    $null = $s; $null = $e
    $dropOverlay.Visibility = [System.Windows.Visibility]::Collapsed
})

$window.Add_Drop({
    param($s, $e)
    $null = $s
    $dropOverlay.Visibility = [System.Windows.Visibility]::Collapsed
    if ($e.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        $files = $e.Data.GetData([System.Windows.DataFormats]::FileDrop)
        if ($files -and $files.Count -ge 1) {
            $txtFilePath.Text = $files[0]
            Add-LogLine ('Dropped: {0}' -f $files[0])
            Set-StatusText ('Ready to analyze: {0}' -f [System.IO.Path]::GetFileName($files[0]))
            Invoke-AnalysisPipeline
        }
    }
    $e.Handled = $true
})

# =============================================================================
# Window state persistence. Multi-monitor visibility check on restore.
# =============================================================================
$script:WindowStatePath = Join-Path $PSScriptRoot 'InstallerAnalysis.windowstate.json'

function Save-WindowState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Writes a single gitignored prefs file; idempotent.')]
    param()

    $state = @{}
    if ($window.WindowState -eq [System.Windows.WindowState]::Normal) {
        $state.Left   = [int]$window.Left
        $state.Top    = [int]$window.Top
        $state.Width  = [int]$window.Width
        $state.Height = [int]$window.Height
    } else {
        $state.Left   = [int]$window.RestoreBounds.Left
        $state.Top    = [int]$window.RestoreBounds.Top
        $state.Width  = [int]$window.RestoreBounds.Width
        $state.Height = [int]$window.RestoreBounds.Height
    }
    $state.Maximized = ($window.WindowState -eq [System.Windows.WindowState]::Maximized)

    try {
        $state | ConvertTo-Json | Set-Content -LiteralPath $script:WindowStatePath -Encoding UTF8
    } catch { $null = $_ }
}

function Restore-WindowState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Mutates $window placement only; no external state.')]
    param()

    if (-not (Test-Path -LiteralPath $script:WindowStatePath)) { return }
    try {
        $state = Get-Content -LiteralPath $script:WindowStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $w = [int]$state.Width
        $h = [int]$state.Height
        if ($w -lt $window.MinWidth)  { $w = [int]$window.MinWidth }
        if ($h -lt $window.MinHeight) { $h = [int]$window.MinHeight }

        $screens = [System.Windows.Forms.Screen]::AllScreens
        $visible = $false
        foreach ($screen in $screens) {
            $titleBarRect = New-Object System.Drawing.Rectangle ([int]$state.Left), ([int]$state.Top), $w, 40
            if ($screen.WorkingArea.IntersectsWith($titleBarRect)) { $visible = $true; break }
        }

        if ($visible) {
            $window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
            $window.Left   = [double]$state.Left
            $window.Top    = [double]$state.Top
            $window.Width  = [double]$w
            $window.Height = [double]$h
        }
        if ($state.Maximized -eq $true) {
            $window.WindowState = [System.Windows.WindowState]::Maximized
        }
    } catch { $null = $_ }
}

$window.Add_SourceInitialized({ Restore-WindowState })
$window.Add_Closing({
    Save-WindowState
    if ($script:AnalysisTimer)  { try { $script:AnalysisTimer.Stop() } catch { $null = $_ } }
    if ($script:BgPowerShell)   { try { [void]$script:BgPowerShell.Stop() } catch { $null = $_ }; try { $script:BgPowerShell.Dispose() } catch { $null = $_ } }
    if ($script:BgRunspace)     { try { $script:BgRunspace.Close() } catch { $null = $_ }; try { $script:BgRunspace.Dispose() } catch { $null = $_ } }
    # Best-effort temp-folder cleanup on close (locked files swallowed).
    if ($script:AnalysisTempRoot -and (Test-Path -LiteralPath $script:AnalysisTempRoot)) {
        try { Remove-Item -LiteralPath $script:AnalysisTempRoot -Recurse -Force -ErrorAction Stop } catch { $null = $_ }
    }
})

if (-not [string]::IsNullOrWhiteSpace($StartupFile) -and (Test-Path -LiteralPath $StartupFile -PathType Leaf)) {
    $window.Add_Loaded({
        $txtFilePath.Text = $StartupFile
        # Defer the pipeline to ContextIdle so the window paints before the
        # bg analyze kicks off.
        $window.Dispatcher.BeginInvoke(
            [Action]{ Invoke-AnalysisPipeline },
            [System.Windows.Threading.DispatcherPriority]::ContextIdle
        ) | Out-Null
    })
}

# =============================================================================
# Ship it.
# =============================================================================
Add-LogLine ('Installer Analysis v1.0.0.0 -- WPF shell loaded.')
Set-StatusText 'Ready.'

[void]$window.ShowDialog()

try { Stop-Transcript | Out-Null } catch { $null = $_ }
