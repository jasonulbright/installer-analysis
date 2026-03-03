<#
.SYNOPSIS
    WinForms front-end for Installer Analysis Tool.

.DESCRIPTION
    Point it at an EXE or MSI, get everything you need for MECM packaging:
    installer type detection, version intelligence, silent install switches,
    MSI properties, payload extraction, and binary string analysis.

    Supports drag-and-drop. No MECM connection required.

.EXAMPLE
    .\start-installeranalysis.ps1

.NOTES
    Requirements:
      - PowerShell 5.1
      - .NET Framework 4.8+
      - 7-Zip (optional, for payload extraction)
      - PSGallery MSI module (optional, for enhanced MSI analysis)

    ScriptName : start-installeranalysis.ps1
    Version    : 1.0.0
    Updated    : 2026-03-03
#>

param()

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

$moduleRoot = Join-Path $PSScriptRoot "Module"
Import-Module (Join-Path $moduleRoot "InstallerAnalysisCommon.psd1") -Force -DisableNameChecking

$toolLogFolder = Join-Path $PSScriptRoot "Logs"
if (-not (Test-Path -LiteralPath $toolLogFolder)) { New-Item -ItemType Directory -Path $toolLogFolder -Force | Out-Null }
$toolLogPath = Join-Path $toolLogFolder ("InstallerAnalysis-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Initialize-Logging -LogPath $toolLogPath

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Set-ModernButtonStyle {
    param([Parameter(Mandatory)][System.Windows.Forms.Button]$Button, [Parameter(Mandatory)][System.Drawing.Color]$BackColor)
    $Button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat; $Button.FlatAppearance.BorderSize = 0
    $Button.BackColor = $BackColor; $Button.ForeColor = [System.Drawing.Color]::White
    $Button.UseVisualStyleBackColor = $false; $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
    $h = [System.Drawing.Color]::FromArgb([Math]::Max(0,$BackColor.R-18),[Math]::Max(0,$BackColor.G-18),[Math]::Max(0,$BackColor.B-18))
    $d = [System.Drawing.Color]::FromArgb([Math]::Max(0,$BackColor.R-36),[Math]::Max(0,$BackColor.G-36),[Math]::Max(0,$BackColor.B-36))
    $Button.FlatAppearance.MouseOverBackColor = $h; $Button.FlatAppearance.MouseDownBackColor = $d
}

function Enable-DoubleBuffer {
    param([Parameter(Mandatory)][System.Windows.Forms.Control]$Control)
    $prop = $Control.GetType().GetProperty("DoubleBuffered", [System.Reflection.BindingFlags] "Instance,NonPublic")
    if ($prop) { $prop.SetValue($Control, $true, $null) | Out-Null }
}

function Add-LogLine {
    param([Parameter(Mandatory)][System.Windows.Forms.TextBox]$TextBox, [Parameter(Mandatory)][string]$Message)
    $ts = (Get-Date).ToString("HH:mm:ss"); $line = "{0}  {1}" -f $ts, $Message
    if ([string]::IsNullOrWhiteSpace($TextBox.Text)) { $TextBox.Text = $line } else { $TextBox.AppendText([Environment]::NewLine + $line) }
    $TextBox.SelectionStart = $TextBox.TextLength; $TextBox.ScrollToCaret()
}

function Save-WindowState {
    $statePath = Join-Path $PSScriptRoot "InstallerAnalysis.windowstate.json"
    $state = @{ X = $form.Location.X; Y = $form.Location.Y; Width = $form.Size.Width; Height = $form.Size.Height
        Maximized = ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Maximized); ActiveTab = $tabMain.SelectedIndex }
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
}

function Restore-WindowState {
    $statePath = Join-Path $PSScriptRoot "InstallerAnalysis.windowstate.json"
    if (-not (Test-Path -LiteralPath $statePath)) { return }
    try {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.Maximized) { $form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized }
        else {
            $screen = [System.Windows.Forms.Screen]::FromPoint((New-Object System.Drawing.Point($state.X, $state.Y)))
            $bounds = $screen.WorkingArea
            $form.Location = New-Object System.Drawing.Point([Math]::Max($bounds.X,[Math]::Min($state.X,$bounds.Right-200)), [Math]::Max($bounds.Y,[Math]::Min($state.Y,$bounds.Bottom-100)))
            $form.Size = New-Object System.Drawing.Size([Math]::Max($form.MinimumSize.Width,$state.Width), [Math]::Max($form.MinimumSize.Height,$state.Height))
        }
        if ($null -ne $state.ActiveTab -and $state.ActiveTab -ge 0 -and $state.ActiveTab -lt $tabMain.TabCount) { $tabMain.SelectedIndex = [int]$state.ActiveTab }
    } catch { }
}

# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------

function Get-IatPreferences {
    $prefsPath = Join-Path $PSScriptRoot "InstallerAnalysis.prefs.json"
    $defaults = @{ DarkMode = $false; SevenZipPath = ''; LastBrowseDir = '' }
    if (Test-Path -LiteralPath $prefsPath) {
        try {
            $loaded = Get-Content -LiteralPath $prefsPath -Raw | ConvertFrom-Json
            if ($null -ne $loaded.DarkMode) { $defaults.DarkMode = [bool]$loaded.DarkMode }
            if ($loaded.SevenZipPath) { $defaults.SevenZipPath = $loaded.SevenZipPath }
            if ($loaded.LastBrowseDir) { $defaults.LastBrowseDir = $loaded.LastBrowseDir }
        } catch { }
    }
    return $defaults
}

function Save-IatPreferences { param([hashtable]$Prefs)
    $prefsPath = Join-Path $PSScriptRoot "InstallerAnalysis.prefs.json"
    $Prefs | ConvertTo-Json | Set-Content -LiteralPath $prefsPath -Encoding UTF8
}

$script:Prefs = Get-IatPreferences

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

$clrAccent = [System.Drawing.Color]::FromArgb(0, 120, 212)

if ($script:Prefs.DarkMode) {
    $clrFormBg = [System.Drawing.Color]::FromArgb(30,30,30); $clrPanelBg = [System.Drawing.Color]::FromArgb(40,40,40)
    $clrHint = [System.Drawing.Color]::FromArgb(140,140,140); $clrSubtitle = [System.Drawing.Color]::FromArgb(180,200,220)
    $clrGridAlt = [System.Drawing.Color]::FromArgb(48,48,48); $clrGridLine = [System.Drawing.Color]::FromArgb(60,60,60)
    $clrDetailBg = [System.Drawing.Color]::FromArgb(45,45,45); $clrSepLine = [System.Drawing.Color]::FromArgb(55,55,55)
    $clrLogBg = [System.Drawing.Color]::FromArgb(35,35,35); $clrLogFg = [System.Drawing.Color]::FromArgb(200,200,200)
    $clrText = [System.Drawing.Color]::FromArgb(220,220,220); $clrGridText = [System.Drawing.Color]::FromArgb(220,220,220)
    $clrOkText = [System.Drawing.Color]::FromArgb(80,200,80); $clrTreeBg = [System.Drawing.Color]::FromArgb(38,38,38)
} else {
    $clrFormBg = [System.Drawing.Color]::FromArgb(245,246,248); $clrPanelBg = [System.Drawing.Color]::White
    $clrHint = [System.Drawing.Color]::FromArgb(140,140,140); $clrSubtitle = [System.Drawing.Color]::FromArgb(220,230,245)
    $clrGridAlt = [System.Drawing.Color]::FromArgb(248,250,252); $clrGridLine = [System.Drawing.Color]::FromArgb(230,230,230)
    $clrDetailBg = [System.Drawing.Color]::FromArgb(250,250,250); $clrSepLine = [System.Drawing.Color]::FromArgb(218,220,224)
    $clrLogBg = [System.Drawing.Color]::White; $clrLogFg = [System.Drawing.Color]::Black
    $clrText = [System.Drawing.Color]::Black; $clrGridText = [System.Drawing.Color]::Black
    $clrOkText = [System.Drawing.Color]::FromArgb(34,139,34); $clrTreeBg = [System.Drawing.Color]::White
}

if ($script:Prefs.DarkMode) {
    if (-not ('DarkToolStripRenderer' -as [type])) {
        Add-Type -ReferencedAssemblies System.Windows.Forms, System.Drawing -TypeDefinition @(
            'using System.Drawing; using System.Windows.Forms;',
            'public class DarkToolStripRenderer : ToolStripProfessionalRenderer {',
            '  private Color _bg; public DarkToolStripRenderer(Color bg) : base() { _bg = bg; }',
            '  protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e) { }',
            '  protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e) { using (var b = new SolidBrush(_bg)) { e.Graphics.FillRectangle(b, e.AffectedBounds); } }',
            '  protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e) { if (e.Item.Selected||e.Item.Pressed) { using (var b = new SolidBrush(Color.FromArgb(60,60,60))) { e.Graphics.FillRectangle(b, new Rectangle(Point.Empty, e.Item.Size)); } } }',
            '  protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e) { int y=e.Item.Height/2; using (var p = new Pen(Color.FromArgb(70,70,70))) { e.Graphics.DrawLine(p,0,y,e.Item.Width,y); } }',
            '  protected override void OnRenderImageMargin(ToolStripRenderEventArgs e) { using (var b = new SolidBrush(_bg)) { e.Graphics.FillRectangle(b, e.AffectedBounds); } }',
            '}'
        ) -join "`r`n"
    }
    $script:DarkRenderer = New-Object DarkToolStripRenderer($clrPanelBg)
}

# ---------------------------------------------------------------------------
# Preferences dialog
# ---------------------------------------------------------------------------

function Show-PreferencesDialog {
    $dlg = New-Object System.Windows.Forms.Form; $dlg.Text = "Preferences"
    $dlg.Size = New-Object System.Drawing.Size(440, 300); $dlg.MinimumSize = $dlg.Size; $dlg.MaximumSize = $dlg.Size
    $dlg.StartPosition = "CenterParent"; $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.ShowInTaskbar = $false
    $dlg.Font = New-Object System.Drawing.Font("Segoe UI", 9.5); $dlg.BackColor = $clrFormBg

    $grpApp = New-Object System.Windows.Forms.GroupBox; $grpApp.Text = "Appearance"; $grpApp.SetBounds(16, 12, 392, 60)
    $grpApp.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold); $grpApp.ForeColor = $clrText; $grpApp.BackColor = $clrFormBg
    if ($script:Prefs.DarkMode) { $grpApp.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat; $grpApp.ForeColor = $clrSepLine }
    $dlg.Controls.Add($grpApp)
    $chkDark = New-Object System.Windows.Forms.CheckBox; $chkDark.Text = "Enable dark mode (requires restart)"
    $chkDark.Font = New-Object System.Drawing.Font("Segoe UI", 9); $chkDark.AutoSize = $true
    $chkDark.Location = New-Object System.Drawing.Point(14, 24); $chkDark.Checked = $script:Prefs.DarkMode
    $chkDark.ForeColor = $clrText; $chkDark.BackColor = $clrFormBg
    if ($script:Prefs.DarkMode) { $chkDark.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat; $chkDark.ForeColor = [System.Drawing.Color]::FromArgb(170,170,170) }
    $grpApp.Controls.Add($chkDark)

    $grp7z = New-Object System.Windows.Forms.GroupBox; $grp7z.Text = "7-Zip Path (leave blank for auto-detect)"
    $grp7z.SetBounds(16, 82, 392, 70); $grp7z.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $grp7z.ForeColor = $clrText; $grp7z.BackColor = $clrFormBg
    if ($script:Prefs.DarkMode) { $grp7z.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat; $grp7z.ForeColor = $clrSepLine }
    $dlg.Controls.Add($grp7z)
    $txt7z = New-Object System.Windows.Forms.TextBox; $txt7z.SetBounds(14, 28, 360, 24); $txt7z.Text = $script:Prefs.SevenZipPath
    $txt7z.Font = New-Object System.Drawing.Font("Segoe UI", 9); $txt7z.BackColor = $clrDetailBg; $txt7z.ForeColor = $clrText
    $grp7z.Controls.Add($txt7z)

    $btnSave = New-Object System.Windows.Forms.Button; $btnSave.Text = "Save"; $btnSave.SetBounds(220, 210, 90, 32)
    $btnSave.Font = New-Object System.Drawing.Font("Segoe UI", 9); Set-ModernButtonStyle -Button $btnSave -BackColor $clrAccent; $dlg.Controls.Add($btnSave)
    $btnCancel = New-Object System.Windows.Forms.Button; $btnCancel.Text = "Cancel"; $btnCancel.SetBounds(318, 210, 90, 32)
    $btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 9); $btnCancel.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnCancel.ForeColor = $clrText; $btnCancel.BackColor = $clrFormBg; $dlg.Controls.Add($btnCancel)

    $btnSave.Add_Click({
        $script:Prefs.DarkMode = $chkDark.Checked; $script:Prefs.SevenZipPath = $txt7z.Text.Trim()
        Save-IatPreferences -Prefs $script:Prefs
        $dlg.DialogResult = [System.Windows.Forms.DialogResult]::OK; $dlg.Close()
    })
    $btnCancel.Add_Click({ $dlg.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $dlg.Close() })
    $dlg.AcceptButton = $btnSave; $dlg.CancelButton = $btnCancel
    $dlg.ShowDialog($form) | Out-Null; $dlg.Dispose()
}

# ---------------------------------------------------------------------------
# Form
# ---------------------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form; $form.Text = "Installer Analysis Tool"
$form.Size = New-Object System.Drawing.Size(1200, 850); $form.MinimumSize = New-Object System.Drawing.Size(950, 650)
$form.StartPosition = "CenterScreen"; $form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$form.BackColor = $clrFormBg; $form.AllowDrop = $true

# StatusStrip
$statusStrip = New-Object System.Windows.Forms.StatusStrip; $statusStrip.BackColor = $clrPanelBg; $statusStrip.ForeColor = $clrText; $statusStrip.SizingGrip = $false
if ($script:Prefs.DarkMode -and $script:DarkRenderer) { $statusStrip.Renderer = $script:DarkRenderer }
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel; $statusLabel.Text = "Ready"; $statusLabel.Spring = $true
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft; $statusLabel.ForeColor = $clrText
$statusStrip.Items.Add($statusLabel) | Out-Null; $form.Controls.Add($statusStrip)

# Log console
$pnlLog = New-Object System.Windows.Forms.Panel; $pnlLog.Dock = [System.Windows.Forms.DockStyle]::Bottom; $pnlLog.Height = 95; $pnlLog.BackColor = $clrLogBg
$form.Controls.Add($pnlLog)
$txtLog = New-Object System.Windows.Forms.TextBox; $txtLog.Dock = [System.Windows.Forms.DockStyle]::Fill; $txtLog.Multiline = $true; $txtLog.ReadOnly = $true
$txtLog.WordWrap = $true; $txtLog.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$txtLog.Font = New-Object System.Drawing.Font("Consolas", 9); $txtLog.BackColor = $clrLogBg; $txtLog.ForeColor = $clrLogFg
$txtLog.BorderStyle = [System.Windows.Forms.BorderStyle]::None; $pnlLog.Controls.Add($txtLog)
$pnlLogSep = New-Object System.Windows.Forms.Panel; $pnlLogSep.Dock = [System.Windows.Forms.DockStyle]::Bottom; $pnlLogSep.Height = 1; $pnlLogSep.BackColor = $clrSepLine
$form.Controls.Add($pnlLogSep)

# Button panel
$pnlButtons = New-Object System.Windows.Forms.Panel; $pnlButtons.Dock = [System.Windows.Forms.DockStyle]::Bottom; $pnlButtons.Height = 56; $pnlButtons.BackColor = $clrPanelBg
$pnlButtons.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 10); $form.Controls.Add($pnlButtons)
$flowButtons = New-Object System.Windows.Forms.FlowLayoutPanel; $flowButtons.Dock = [System.Windows.Forms.DockStyle]::Fill
$flowButtons.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight; $flowButtons.WrapContents = $false; $flowButtons.BackColor = $clrPanelBg
$pnlButtons.Controls.Add($flowButtons)
$btnExportCsv = New-Object System.Windows.Forms.Button; $btnExportCsv.Text = "Export CSV"; $btnExportCsv.Size = New-Object System.Drawing.Size(120, 34)
$btnExportCsv.Font = New-Object System.Drawing.Font("Segoe UI", 9); $btnExportCsv.Margin = New-Object System.Windows.Forms.Padding(0,0,8,0)
Set-ModernButtonStyle -Button $btnExportCsv -BackColor ([System.Drawing.Color]::FromArgb(50,130,50))
$btnExportHtml = New-Object System.Windows.Forms.Button; $btnExportHtml.Text = "Export HTML"; $btnExportHtml.Size = New-Object System.Drawing.Size(120, 34)
$btnExportHtml.Font = New-Object System.Drawing.Font("Segoe UI", 9); $btnExportHtml.Margin = New-Object System.Windows.Forms.Padding(0,0,8,0)
Set-ModernButtonStyle -Button $btnExportHtml -BackColor ([System.Drawing.Color]::FromArgb(50,130,50))
$btnCopySummary = New-Object System.Windows.Forms.Button; $btnCopySummary.Text = "Copy Summary"; $btnCopySummary.Size = New-Object System.Drawing.Size(130, 34)
$btnCopySummary.Font = New-Object System.Drawing.Font("Segoe UI", 9); Set-ModernButtonStyle -Button $btnCopySummary -BackColor ([System.Drawing.Color]::FromArgb(100,100,100))
$flowButtons.Controls.Add($btnExportCsv); $flowButtons.Controls.Add($btnExportHtml); $flowButtons.Controls.Add($btnCopySummary)
$pnlBtnSep = New-Object System.Windows.Forms.Panel; $pnlBtnSep.Dock = [System.Windows.Forms.DockStyle]::Bottom; $pnlBtnSep.Height = 1; $pnlBtnSep.BackColor = $clrSepLine
$form.Controls.Add($pnlBtnSep)

# MenuStrip
$menuStrip = New-Object System.Windows.Forms.MenuStrip; $menuStrip.BackColor = $clrPanelBg; $menuStrip.ForeColor = $clrText
if ($script:Prefs.DarkMode -and $script:DarkRenderer) { $menuStrip.Renderer = $script:DarkRenderer }
$mnuFile = New-Object System.Windows.Forms.ToolStripMenuItem("&File"); $mnuFile.ForeColor = $clrText
$mnuBrowse = New-Object System.Windows.Forms.ToolStripMenuItem("&Browse..."); $mnuBrowse.ForeColor = $clrText
$mnuBrowse.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::O
$mnuBrowse.Add_Click({ Invoke-Browse }); $mnuFile.DropDownItems.Add($mnuBrowse) | Out-Null
$mnuFile.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$mnuPrefs = New-Object System.Windows.Forms.ToolStripMenuItem("&Preferences..."); $mnuPrefs.ForeColor = $clrText
$mnuPrefs.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Oemcomma
$mnuPrefs.Add_Click({ Show-PreferencesDialog }); $mnuFile.DropDownItems.Add($mnuPrefs) | Out-Null
$mnuFile.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$mnuExit = New-Object System.Windows.Forms.ToolStripMenuItem("E&xit"); $mnuExit.ForeColor = $clrText
$mnuExit.Add_Click({ $form.Close() }); $mnuFile.DropDownItems.Add($mnuExit) | Out-Null
$menuStrip.Items.Add($mnuFile) | Out-Null
$mnuHelp = New-Object System.Windows.Forms.ToolStripMenuItem("&Help"); $mnuHelp.ForeColor = $clrText
$mnuAbout = New-Object System.Windows.Forms.ToolStripMenuItem("&About"); $mnuAbout.ForeColor = $clrText
$mnuAbout.Add_Click({
    [System.Windows.Forms.MessageBox]::Show("Installer Analysis Tool v1.0.0`r`n`r`nAnalyze EXE and MSI installers for packaging intelligence.`r`nDetects: MSI, NSIS, Inno Setup, InstallShield, WiX Burn, 7z SFX, WinRAR SFX.`r`n`r`nOptional: 7-Zip (payload extraction), PSGallery MSI module.", "About", "OK", "Information") | Out-Null
})
$mnuHelp.DropDownItems.Add($mnuAbout) | Out-Null; $menuStrip.Items.Add($mnuHelp) | Out-Null

# Header
$pnlHeader = New-Object System.Windows.Forms.Panel; $pnlHeader.Dock = [System.Windows.Forms.DockStyle]::Top; $pnlHeader.Height = 60; $pnlHeader.BackColor = $clrAccent
$lblTitle = New-Object System.Windows.Forms.Label; $lblTitle.Text = "Installer Analysis Tool"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold); $lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.AutoSize = $true; $lblTitle.Location = New-Object System.Drawing.Point(16, 6); $lblTitle.BackColor = [System.Drawing.Color]::Transparent; $pnlHeader.Controls.Add($lblTitle)
$lblSubtitle = New-Object System.Windows.Forms.Label; $lblSubtitle.Text = "Version intelligence, silent switches, payload extraction"
$lblSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 9); $lblSubtitle.ForeColor = $clrSubtitle; $lblSubtitle.AutoSize = $true
$lblSubtitle.Location = New-Object System.Drawing.Point(18, 36); $lblSubtitle.BackColor = [System.Drawing.Color]::Transparent; $pnlHeader.Controls.Add($lblSubtitle)
$form.Controls.Add($pnlHeader)

# File input bar
$pnlFileInput = New-Object System.Windows.Forms.Panel; $pnlFileInput.Dock = [System.Windows.Forms.DockStyle]::Top; $pnlFileInput.Height = 52; $pnlFileInput.BackColor = $clrPanelBg
$pnlFileInput.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 6); $form.Controls.Add($pnlFileInput)
$flowFile = New-Object System.Windows.Forms.FlowLayoutPanel; $flowFile.Dock = [System.Windows.Forms.DockStyle]::Fill
$flowFile.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight; $flowFile.WrapContents = $false; $flowFile.BackColor = $clrPanelBg
$pnlFileInput.Controls.Add($flowFile)
$txtFilePath = New-Object System.Windows.Forms.TextBox; $txtFilePath.Width = 700; $txtFilePath.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$txtFilePath.BackColor = $clrDetailBg; $txtFilePath.ForeColor = $clrText; $txtFilePath.Margin = New-Object System.Windows.Forms.Padding(0, 2, 8, 0)
$txtFilePath.BorderStyle = if ($script:Prefs.DarkMode) { [System.Windows.Forms.BorderStyle]::None } else { [System.Windows.Forms.BorderStyle]::FixedSingle }
$flowFile.Controls.Add($txtFilePath)
$btnBrowse = New-Object System.Windows.Forms.Button; $btnBrowse.Text = "Browse"; $btnBrowse.Size = New-Object System.Drawing.Size(80, 28)
$btnBrowse.Font = New-Object System.Drawing.Font("Segoe UI", 9); $btnBrowse.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
Set-ModernButtonStyle -Button $btnBrowse -BackColor ([System.Drawing.Color]::FromArgb(100,100,100))
$flowFile.Controls.Add($btnBrowse)
$btnAnalyze = New-Object System.Windows.Forms.Button; $btnAnalyze.Text = "Analyze"; $btnAnalyze.Size = New-Object System.Drawing.Size(100, 28)
$btnAnalyze.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
Set-ModernButtonStyle -Button $btnAnalyze -BackColor $clrAccent; $flowFile.Controls.Add($btnAnalyze)

$pnlSep1 = New-Object System.Windows.Forms.Panel; $pnlSep1.Dock = [System.Windows.Forms.DockStyle]::Top; $pnlSep1.Height = 1; $pnlSep1.BackColor = $clrSepLine
$form.Controls.Add($pnlSep1)

# ---------------------------------------------------------------------------
# Themed grid helper
# ---------------------------------------------------------------------------

function New-ThemedGrid { param([switch]$MultiSelect)
    $g = New-Object System.Windows.Forms.DataGridView; $g.Dock = [System.Windows.Forms.DockStyle]::Fill
    $g.ReadOnly = $true; $g.AllowUserToAddRows = $false; $g.AllowUserToDeleteRows = $false; $g.AllowUserToResizeRows = $false
    $g.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect; $g.MultiSelect = [bool]$MultiSelect
    $g.AutoGenerateColumns = $false; $g.RowHeadersVisible = $false; $g.BackgroundColor = $clrPanelBg
    $g.BorderStyle = [System.Windows.Forms.BorderStyle]::None; $g.CellBorderStyle = [System.Windows.Forms.DataGridViewCellBorderStyle]::SingleHorizontal
    $g.GridColor = $clrGridLine; $g.ColumnHeadersDefaultCellStyle.BackColor = $clrAccent
    $g.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $g.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $g.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(4)
    $g.ColumnHeadersDefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::False
    $g.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing
    $g.ColumnHeadersHeight = 32; $g.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::Single
    $g.EnableHeadersVisualStyles = $false; $g.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $g.DefaultCellStyle.ForeColor = $clrGridText; $g.DefaultCellStyle.BackColor = $clrPanelBg
    $g.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(2)
    $g.DefaultCellStyle.SelectionBackColor = if ($script:Prefs.DarkMode) { [System.Drawing.Color]::FromArgb(38,79,120) } else { [System.Drawing.Color]::FromArgb(0,120,215) }
    $g.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $g.RowTemplate.Height = 26; $g.AlternatingRowsDefaultCellStyle.BackColor = $clrGridAlt
    Enable-DoubleBuffer -Control $g; return $g
}

# ---------------------------------------------------------------------------
# TabControl
# ---------------------------------------------------------------------------

$tabMain = New-Object System.Windows.Forms.TabControl; $tabMain.Dock = [System.Windows.Forms.DockStyle]::Fill
$tabMain.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$tabMain.SizeMode = [System.Windows.Forms.TabSizeMode]::Fixed; $tabMain.ItemSize = New-Object System.Drawing.Size(140, 30)
$tabMain.DrawMode = [System.Windows.Forms.TabDrawMode]::OwnerDrawFixed
$tabMain.Add_DrawItem({
    param($s, $e)
    $e.Graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $tab = $s.TabPages[$e.Index]; $sel = ($s.SelectedIndex -eq $e.Index)
    $bg = if ($script:Prefs.DarkMode) { if ($sel) { $clrAccent } else { $clrPanelBg } } else { if ($sel) { $clrAccent } else { [System.Drawing.Color]::FromArgb(240,240,240) } }
    $fg = if ($sel) { [System.Drawing.Color]::White } else { $clrText }
    $bb = New-Object System.Drawing.SolidBrush($bg); $e.Graphics.FillRectangle($bb, $e.Bounds)
    $ft = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = [System.Drawing.StringAlignment]::Near
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Far; $sf.FormatFlags = [System.Drawing.StringFormatFlags]::NoWrap
    $tr = New-Object System.Drawing.RectangleF(($e.Bounds.X + 8), $e.Bounds.Y, ($e.Bounds.Width - 12), ($e.Bounds.Height - 3))
    $tb = New-Object System.Drawing.SolidBrush($fg); $e.Graphics.DrawString($tab.Text, $ft, $tb, $tr, $sf)
    $bb.Dispose(); $tb.Dispose(); $ft.Dispose(); $sf.Dispose()
})
$form.Controls.Add($tabMain)

# ===================== TAB 0: Overview =====================

$tabOverview = New-Object System.Windows.Forms.TabPage; $tabOverview.Text = "Overview"; $tabOverview.BackColor = $clrFormBg
$tabOverview.AutoScroll = $true; $tabMain.TabPages.Add($tabOverview)

$pnlOverview = New-Object System.Windows.Forms.FlowLayoutPanel; $pnlOverview.Dock = [System.Windows.Forms.DockStyle]::Fill
$pnlOverview.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown; $pnlOverview.WrapContents = $false
$pnlOverview.AutoScroll = $true; $pnlOverview.BackColor = $clrFormBg; $pnlOverview.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)
$tabOverview.Controls.Add($pnlOverview)

# Overview uses RichTextBox for flexible display
$txtOverview = New-Object System.Windows.Forms.RichTextBox; $txtOverview.Dock = [System.Windows.Forms.DockStyle]::Fill
$txtOverview.ReadOnly = $true; $txtOverview.BackColor = $clrDetailBg; $txtOverview.ForeColor = $clrText
$txtOverview.Font = New-Object System.Drawing.Font("Consolas", 10); $txtOverview.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$tabOverview.Controls.Remove($pnlOverview); $tabOverview.Controls.Add($txtOverview)

# ===================== TAB 1: MSI Properties =====================

$tabMsi = New-Object System.Windows.Forms.TabPage; $tabMsi.Text = "MSI Properties"; $tabMsi.BackColor = $clrFormBg; $tabMain.TabPages.Add($tabMsi)

$lblMsiStatus = New-Object System.Windows.Forms.Label; $lblMsiStatus.Text = "No MSI properties available. Analyze an MSI file or an EXE with embedded MSI."
$lblMsiStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9); $lblMsiStatus.AutoSize = $true; $lblMsiStatus.Dock = [System.Windows.Forms.DockStyle]::Top
$lblMsiStatus.ForeColor = $clrHint; $lblMsiStatus.BackColor = $clrFormBg; $lblMsiStatus.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 4)
$tabMsi.Controls.Add($lblMsiStatus)

$gridMsi = New-ThemedGrid
$colMProp = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colMProp.HeaderText = "Property"; $colMProp.DataPropertyName = "Property"; $colMProp.Width = 250
$colMVal = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colMVal.HeaderText = "Value"; $colMVal.DataPropertyName = "Value"; $colMVal.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
$gridMsi.Columns.AddRange([System.Windows.Forms.DataGridViewColumn[]]@($colMProp, $colMVal)); $tabMsi.Controls.Add($gridMsi)

$dtMsi = New-Object System.Data.DataTable; [void]$dtMsi.Columns.Add("Property", [string]); [void]$dtMsi.Columns.Add("Value", [string])
$gridMsi.DataSource = $dtMsi

# ===================== TAB 2: Payload Contents =====================

$tabPayload = New-Object System.Windows.Forms.TabPage; $tabPayload.Text = "Payload"; $tabPayload.BackColor = $clrFormBg; $tabMain.TabPages.Add($tabPayload)

$lblPayloadStatus = New-Object System.Windows.Forms.Label; $lblPayloadStatus.Text = "No payload data. Analyze a file to list contents."
$lblPayloadStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9); $lblPayloadStatus.AutoSize = $true; $lblPayloadStatus.Dock = [System.Windows.Forms.DockStyle]::Top
$lblPayloadStatus.ForeColor = $clrHint; $lblPayloadStatus.BackColor = $clrFormBg; $lblPayloadStatus.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 4)
$tabPayload.Controls.Add($lblPayloadStatus)

$gridPayload = New-ThemedGrid
$colPName = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colPName.HeaderText = "Name"; $colPName.DataPropertyName = "Name"; $colPName.Width = 400
$colPSize = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colPSize.HeaderText = "Size"; $colPSize.DataPropertyName = "SizeFormatted"; $colPSize.Width = 100
$colPDir = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colPDir.HeaderText = "Directory"; $colPDir.DataPropertyName = "IsDirectory"; $colPDir.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
$gridPayload.Columns.AddRange([System.Windows.Forms.DataGridViewColumn[]]@($colPName, $colPSize, $colPDir)); $tabPayload.Controls.Add($gridPayload)

$dtPayload = New-Object System.Data.DataTable; [void]$dtPayload.Columns.Add("Name", [string]); [void]$dtPayload.Columns.Add("SizeFormatted", [string]); [void]$dtPayload.Columns.Add("IsDirectory", [string])
$gridPayload.DataSource = $dtPayload

$pnlPayloadBtns = New-Object System.Windows.Forms.FlowLayoutPanel; $pnlPayloadBtns.Dock = [System.Windows.Forms.DockStyle]::Bottom; $pnlPayloadBtns.Height = 40
$pnlPayloadBtns.BackColor = $clrPanelBg; $pnlPayloadBtns.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
$btnExtractAll = New-Object System.Windows.Forms.Button; $btnExtractAll.Text = "Extract All"; $btnExtractAll.Size = New-Object System.Drawing.Size(120, 30)
$btnExtractAll.Font = New-Object System.Drawing.Font("Segoe UI", 8.5); Set-ModernButtonStyle -Button $btnExtractAll -BackColor $clrAccent
$pnlPayloadBtns.Controls.Add($btnExtractAll); $tabPayload.Controls.Add($pnlPayloadBtns)

# ===================== TAB 3: Strings =====================

$tabStrings = New-Object System.Windows.Forms.TabPage; $tabStrings.Text = "Strings"; $tabStrings.BackColor = $clrFormBg; $tabMain.TabPages.Add($tabStrings)

$pnlStrFilter = New-Object System.Windows.Forms.Panel; $pnlStrFilter.Dock = [System.Windows.Forms.DockStyle]::Top; $pnlStrFilter.Height = 36; $pnlStrFilter.BackColor = $clrPanelBg
$lblStrFilter = New-Object System.Windows.Forms.Label; $lblStrFilter.Text = "Filter:"; $lblStrFilter.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblStrFilter.AutoSize = $true; $lblStrFilter.Location = New-Object System.Drawing.Point(8, 8); $lblStrFilter.ForeColor = $clrText; $lblStrFilter.BackColor = $clrPanelBg
$pnlStrFilter.Controls.Add($lblStrFilter)
$txtStrFilter = New-Object System.Windows.Forms.TextBox; $txtStrFilter.SetBounds(50, 5, 300, 24); $txtStrFilter.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$txtStrFilter.BackColor = $clrDetailBg; $txtStrFilter.ForeColor = $clrText; $pnlStrFilter.Controls.Add($txtStrFilter)
$tabStrings.Controls.Add($pnlStrFilter)

$gridStrings = New-ThemedGrid
$colSCat = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colSCat.HeaderText = "Category"; $colSCat.DataPropertyName = "Category"; $colSCat.Width = 150
$colSVal = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colSVal.HeaderText = "Value"; $colSVal.DataPropertyName = "Value"; $colSVal.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
$gridStrings.Columns.AddRange([System.Windows.Forms.DataGridViewColumn[]]@($colSCat, $colSVal)); $tabStrings.Controls.Add($gridStrings)

$dtStrings = New-Object System.Data.DataTable; [void]$dtStrings.Columns.Add("Category", [string]); [void]$dtStrings.Columns.Add("Value", [string])
$gridStrings.DataSource = $dtStrings

$txtStrFilter.Add_TextChanged({
    $ft = $txtStrFilter.Text.Trim()
    if ($ft) { $escaped = $ft.Replace("'", "''"); $dtStrings.DefaultView.RowFilter = "Value LIKE '%$escaped%' OR Category LIKE '%$escaped%'" }
    else { $dtStrings.DefaultView.RowFilter = '' }
})

# ---------------------------------------------------------------------------
# Finalize dock Z-order
# ---------------------------------------------------------------------------

$form.Controls.Add($menuStrip); $menuStrip.SendToBack()
$pnlSep1.BringToFront(); $pnlFileInput.BringToFront(); $pnlHeader.BringToFront()
$tabMain.BringToFront()

# ---------------------------------------------------------------------------
# Module-scoped data
# ---------------------------------------------------------------------------

$script:AnalysisResult = $null

# ---------------------------------------------------------------------------
# Browse
# ---------------------------------------------------------------------------

function Invoke-Browse {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "Installers (*.exe;*.msi;*.msp)|*.exe;*.msi;*.msp|All Files (*.*)|*.*"
    if ($script:Prefs.LastBrowseDir) { $ofd.InitialDirectory = $script:Prefs.LastBrowseDir }
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtFilePath.Text = $ofd.FileName
        $script:Prefs.LastBrowseDir = Split-Path $ofd.FileName -Parent
        Save-IatPreferences -Prefs $script:Prefs
        Invoke-Analysis
    }
    $ofd.Dispose()
}

$btnBrowse.Add_Click({ Invoke-Browse })

# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------

function Invoke-Analysis {
    $filePath = $txtFilePath.Text.Trim()
    if (-not $filePath -or -not (Test-Path -LiteralPath $filePath)) {
        [System.Windows.Forms.MessageBox]::Show("File not found. Enter a valid path or use Browse.", "File Not Found", "OK", "Warning") | Out-Null
        return
    }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; $btnAnalyze.Enabled = $false; $btnBrowse.Enabled = $false

    try {
        # Clear
        $dtMsi.Clear(); $dtPayload.Clear(); $dtStrings.Clear(); $txtOverview.Text = ''
        $lblMsiStatus.Text = ''; $lblPayloadStatus.Text = ''

        # Step 1: File info
        Add-LogLine -TextBox $txtLog -Message "Analyzing: $filePath"
        [System.Windows.Forms.Application]::DoEvents()
        $fileInfo = Get-InstallerFileInfo -Path $filePath
        Add-LogLine -TextBox $txtLog -Message "File: $($fileInfo.FileName) | $($fileInfo.FileSizeFormatted) | $($fileInfo.Architecture)"
        [System.Windows.Forms.Application]::DoEvents()

        # Step 2: Installer type
        $installerType = Get-InstallerType -Path $filePath
        Add-LogLine -TextBox $txtLog -Message "Installer type: $installerType"
        [System.Windows.Forms.Application]::DoEvents()

        # Step 3: MSI properties
        $msiProps = $null; $msiSummary = $null
        if ($installerType -eq 'MSI') {
            Add-LogLine -TextBox $txtLog -Message "Reading MSI properties..."
            [System.Windows.Forms.Application]::DoEvents()
            $msiProps = Get-MsiProperties -MsiPath $filePath
            $msiSummary = Get-MsiSummaryInfo -MsiPath $filePath
            if ($msiSummary) { $fileInfo | Add-Member -NotePropertyName Architecture -NotePropertyValue $msiSummary.Architecture -Force }

            $dtMsi.BeginLoadData()
            foreach ($key in $msiProps.Keys) { [void]$dtMsi.Rows.Add($key, $msiProps[$key]) }
            $dtMsi.EndLoadData()
            $lblMsiStatus.Text = "Properties from: $($fileInfo.FileName)"
            Add-LogLine -TextBox $txtLog -Message "Loaded $($msiProps.Count) MSI properties"
        }
        [System.Windows.Forms.Application]::DoEvents()

        # Step 4: Silent switches
        $switches = Get-SilentSwitches -InstallerType $installerType -FilePath $filePath -MsiProperties $msiProps
        [System.Windows.Forms.Application]::DoEvents()

        # Step 5: Payload contents
        Add-LogLine -TextBox $txtLog -Message "Listing payload contents..."
        [System.Windows.Forms.Application]::DoEvents()
        $sevenZip = Find-7ZipPath -PreferredPath $script:Prefs.SevenZipPath
        $payloadItems = $null
        if ($sevenZip) {
            $payloadItems = Get-PayloadContents -Path $filePath -SevenZipPath $sevenZip
            if ($payloadItems) {
                $dtPayload.BeginLoadData()
                foreach ($item in $payloadItems) { [void]$dtPayload.Rows.Add($item.Name, $item.SizeFormatted, [string]$item.IsDirectory) }
                $dtPayload.EndLoadData()
                $lblPayloadStatus.Text = "$($payloadItems.Count) items found"

                # Check for embedded MSI
                if ($installerType -ne 'MSI') {
                    $embeddedMsi = $payloadItems | Where-Object { $_.Name -match '\.msi$' } | Select-Object -First 1
                    if ($embeddedMsi) {
                        Add-LogLine -TextBox $txtLog -Message "Found embedded MSI: $($embeddedMsi.Name). Extracting for analysis..."
                        [System.Windows.Forms.Application]::DoEvents()
                        $extractDir = Expand-InstallerPayload -Path $filePath -SevenZipPath $sevenZip
                        if ($extractDir) {
                            $msiPath = Get-ChildItem -Path $extractDir -Filter '*.msi' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                            if ($msiPath) {
                                $msiProps = Get-MsiProperties -MsiPath $msiPath.FullName
                                $msiSummary = Get-MsiSummaryInfo -MsiPath $msiPath.FullName
                                $dtMsi.BeginLoadData()
                                foreach ($key in $msiProps.Keys) { [void]$dtMsi.Rows.Add($key, $msiProps[$key]) }
                                $dtMsi.EndLoadData()
                                $lblMsiStatus.Text = "Properties from embedded: $($msiPath.Name)"
                                Add-LogLine -TextBox $txtLog -Message "Loaded MSI properties from embedded $($msiPath.Name)"
                            }
                        }
                    }
                }
            } else {
                $lblPayloadStatus.Text = "No extractable contents found"
            }
        } else {
            $lblPayloadStatus.Text = "7-Zip not found. Install 7-Zip or configure path in Preferences."
        }
        [System.Windows.Forms.Application]::DoEvents()

        # Step 6: Interesting strings
        Add-LogLine -TextBox $txtLog -Message "Scanning for interesting strings..."
        [System.Windows.Forms.Application]::DoEvents()
        $strings = Get-InterestingStrings -Path $filePath
        $dtStrings.BeginLoadData()
        foreach ($cat in @('InstallerMarkers', 'URLs', 'RegistryPaths', 'FilePaths', 'GUIDs', 'VersionStrings')) {
            $displayCat = switch ($cat) {
                'InstallerMarkers' { 'Installer Markers' }
                'URLs' { 'URLs' }
                'RegistryPaths' { 'Registry Paths' }
                'FilePaths' { 'File Paths' }
                'GUIDs' { 'GUIDs' }
                'VersionStrings' { 'Version Strings' }
            }
            foreach ($val in $strings[$cat]) { [void]$dtStrings.Rows.Add($displayCat, $val) }
        }
        $dtStrings.EndLoadData()
        [System.Windows.Forms.Application]::DoEvents()

        # Step 7: Populate overview
        $overviewLines = @(
            "FILE INFORMATION",
            ("=" * 50),
            "File Name:       $($fileInfo.FileName)",
            "File Size:       $($fileInfo.FileSizeFormatted)",
            "SHA-256:         $($fileInfo.SHA256)",
            "File Version:    $($fileInfo.FileVersion)",
            "Product Version: $($fileInfo.ProductVersion)",
            "Product Name:    $($fileInfo.ProductName)",
            "Company:         $($fileInfo.CompanyName)",
            "Description:     $($fileInfo.FileDescription)",
            "Copyright:       $($fileInfo.LegalCopyright)",
            "",
            "INSTALLER TYPE",
            ("=" * 50),
            "Framework:       $installerType",
            "Architecture:    $($fileInfo.Architecture)",
            "Signature:       $($fileInfo.SignatureStatus)",
            "Signer:          $($fileInfo.SignerSubject)"
        )

        if ($msiProps -and $msiProps.Count -gt 0) {
            $overviewLines += ""
            $overviewLines += "MSI PROPERTIES (KEY)"
            $overviewLines += ("=" * 50)
            if ($msiProps.Contains('ProductCode'))   { $overviewLines += "Product Code:    $($msiProps['ProductCode'])" }
            if ($msiProps.Contains('UpgradeCode'))   { $overviewLines += "Upgrade Code:    $($msiProps['UpgradeCode'])" }
            if ($msiProps.Contains('ProductVersion')) { $overviewLines += "MSI Version:     $($msiProps['ProductVersion'])" }
            if ($msiProps.Contains('Manufacturer'))  { $overviewLines += "Manufacturer:    $($msiProps['Manufacturer'])" }
            if ($msiProps.Contains('ProductName'))   { $overviewLines += "Product Name:    $($msiProps['ProductName'])" }
        }

        $overviewLines += ""
        $overviewLines += "SILENT INSTALL SWITCHES"
        $overviewLines += ("=" * 50)
        $overviewLines += "Install:         $($switches.Install)"
        $overviewLines += "Uninstall:       $($switches.Uninstall)"
        $overviewLines += "Notes:           $($switches.Notes)"

        if ($payloadItems) {
            $overviewLines += ""
            $overviewLines += "PAYLOAD"
            $overviewLines += ("=" * 50)
            $overviewLines += "$($payloadItems.Count) items found in archive"
            $msiPayloads = @($payloadItems | Where-Object { $_.Name -match '\.msi$' })
            if ($msiPayloads.Count -gt 0) {
                $overviewLines += "Embedded MSI: $($msiPayloads | ForEach-Object { $_.Name }) -join ', '"
            }
        }

        $txtOverview.Text = $overviewLines -join "`r`n"

        # Store result
        $script:AnalysisResult = @{
            FileInfo      = $fileInfo
            InstallerType = $installerType
            MsiProperties = $msiProps
            MsiSummary    = $msiSummary
            Switches      = $switches
            Payload       = $payloadItems
            Strings       = $strings
        }

        $statusLabel.Text = "Analysis complete: $($fileInfo.FileName) ($installerType)"
        Add-LogLine -TextBox $txtLog -Message "Analysis complete."
    }
    catch {
        Add-LogLine -TextBox $txtLog -Message "ERROR: $($_.Exception.Message)"
        Write-Log "Analysis failed: $_" -Level ERROR
    }
    finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default; $btnAnalyze.Enabled = $true; $btnBrowse.Enabled = $true
    }
}

$btnAnalyze.Add_Click({ Invoke-Analysis })
$txtFilePath.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) { Invoke-Analysis; $e.SuppressKeyPress = $true } })

# ---------------------------------------------------------------------------
# Drag-and-drop
# ---------------------------------------------------------------------------

$form.Add_DragEnter({
    param($s, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
        if ($files.Count -eq 1 -and ($files[0] -match '\.(exe|msi|msp)$')) {
            $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
        } else { $e.Effect = [System.Windows.Forms.DragDropEffects]::None }
    }
})

$form.Add_DragDrop({
    param($s, $e)
    $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    if ($files.Count -ge 1) { $txtFilePath.Text = $files[0]; Invoke-Analysis }
})

# ---------------------------------------------------------------------------
# Extract All handler
# ---------------------------------------------------------------------------

$btnExtractAll.Add_Click({
    $filePath = $txtFilePath.Text.Trim()
    if (-not $filePath -or -not (Test-Path -LiteralPath $filePath)) { return }
    $sevenZip = Find-7ZipPath -PreferredPath $script:Prefs.SevenZipPath
    if (-not $sevenZip) { [System.Windows.Forms.MessageBox]::Show("7-Zip not found.", "Extract", "OK", "Warning") | Out-Null; return }
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog; $fbd.Description = "Select extraction directory"
    if ($fbd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $outPath = Expand-InstallerPayload -Path $filePath -OutputPath $fbd.SelectedPath -SevenZipPath $sevenZip
        Add-LogLine -TextBox $txtLog -Message "Extracted to: $outPath"
    }
    $fbd.Dispose()
})

# ---------------------------------------------------------------------------
# Export handlers
# ---------------------------------------------------------------------------

$btnExportCsv.Add_Click({
    if (-not $script:AnalysisResult) { [System.Windows.Forms.MessageBox]::Show("No analysis data.", "Export", "OK", "Information") | Out-Null; return }
    # Build a property/value DataTable from the overview
    $dtExport = New-Object System.Data.DataTable; [void]$dtExport.Columns.Add("Property", [string]); [void]$dtExport.Columns.Add("Value", [string])
    $fi = $script:AnalysisResult.FileInfo; $sw = $script:AnalysisResult.Switches
    [void]$dtExport.Rows.Add("File Name", $fi.FileName); [void]$dtExport.Rows.Add("File Size", $fi.FileSizeFormatted)
    [void]$dtExport.Rows.Add("SHA-256", $fi.SHA256); [void]$dtExport.Rows.Add("Installer Type", $script:AnalysisResult.InstallerType)
    [void]$dtExport.Rows.Add("Architecture", $fi.Architecture); [void]$dtExport.Rows.Add("File Version", $fi.FileVersion)
    [void]$dtExport.Rows.Add("Product Version", $fi.ProductVersion); [void]$dtExport.Rows.Add("Company", $fi.CompanyName)
    [void]$dtExport.Rows.Add("Signature", $fi.SignatureStatus); [void]$dtExport.Rows.Add("Silent Install", $sw.Install)
    [void]$dtExport.Rows.Add("Silent Uninstall", $sw.Uninstall)
    if ($script:AnalysisResult.MsiProperties) {
        foreach ($k in $script:AnalysisResult.MsiProperties.Keys) { [void]$dtExport.Rows.Add("MSI:$k", $script:AnalysisResult.MsiProperties[$k]) }
    }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter = "CSV (*.csv)|*.csv"
    $sfd.FileName = "Analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"; $sfd.InitialDirectory = Join-Path $PSScriptRoot "Reports"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Export-AnalysisReport -DataTable $dtExport -OutputPath $sfd.FileName
        Add-LogLine -TextBox $txtLog -Message "Exported CSV: $($sfd.FileName)"
    }
    $sfd.Dispose()
})

$btnExportHtml.Add_Click({
    if (-not $script:AnalysisResult) { [System.Windows.Forms.MessageBox]::Show("No analysis data.", "Export", "OK", "Information") | Out-Null; return }
    $dtExport = New-Object System.Data.DataTable; [void]$dtExport.Columns.Add("Property", [string]); [void]$dtExport.Columns.Add("Value", [string])
    $fi = $script:AnalysisResult.FileInfo; $sw = $script:AnalysisResult.Switches
    [void]$dtExport.Rows.Add("File Name", $fi.FileName); [void]$dtExport.Rows.Add("Installer Type", $script:AnalysisResult.InstallerType)
    [void]$dtExport.Rows.Add("Architecture", $fi.Architecture); [void]$dtExport.Rows.Add("Version", $fi.ProductVersion)
    [void]$dtExport.Rows.Add("Company", $fi.CompanyName); [void]$dtExport.Rows.Add("SHA-256", $fi.SHA256)
    [void]$dtExport.Rows.Add("Silent Install", $sw.Install); [void]$dtExport.Rows.Add("Silent Uninstall", $sw.Uninstall)
    if ($script:AnalysisResult.MsiProperties) {
        foreach ($k in @('ProductCode','UpgradeCode','ProductVersion','Manufacturer')) {
            if ($script:AnalysisResult.MsiProperties.Contains($k)) { [void]$dtExport.Rows.Add($k, $script:AnalysisResult.MsiProperties[$k]) }
        }
    }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter = "HTML (*.html)|*.html"
    $sfd.FileName = "Analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"; $sfd.InitialDirectory = Join-Path $PSScriptRoot "Reports"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Export-AnalysisHtml -DataTable $dtExport -OutputPath $sfd.FileName -ReportTitle "Installer Analysis: $($fi.FileName)"
        Add-LogLine -TextBox $txtLog -Message "Exported HTML: $($sfd.FileName)"
    }
    $sfd.Dispose()
})

$btnCopySummary.Add_Click({
    if (-not $script:AnalysisResult) { [System.Windows.Forms.MessageBox]::Show("No analysis data.", "Copy", "OK", "Information") | Out-Null; return }
    $summary = New-AnalysisSummaryText -FileInfo $script:AnalysisResult.FileInfo -InstallerType $script:AnalysisResult.InstallerType `
        -Switches $script:AnalysisResult.Switches -MsiProperties $script:AnalysisResult.MsiProperties
    [System.Windows.Forms.Clipboard]::SetText($summary)
    Add-LogLine -TextBox $txtLog -Message "Summary copied to clipboard"
})

# ---------------------------------------------------------------------------
# Form events
# ---------------------------------------------------------------------------

$form.Add_FormClosing({ Save-WindowState })
$form.Add_Shown({
    Restore-WindowState
    $sevenZip = Find-7ZipPath -PreferredPath $script:Prefs.SevenZipPath
    $msiMod = Test-MsiModuleAvailable
    Add-LogLine -TextBox $txtLog -Message "Ready. Browse to an installer or drag-drop a file."
    Add-LogLine -TextBox $txtLog -Message "7-Zip: $(if ($sevenZip) { $sevenZip } else { 'NOT FOUND' }) | MSI module: $(if ($msiMod) { 'Available' } else { 'Not installed (using COM fallback)' })"
})

[System.Windows.Forms.Application]::Run($form)
