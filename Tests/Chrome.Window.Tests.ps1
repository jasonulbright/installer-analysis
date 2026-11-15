#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Window test for the chrome and the buttons of the main window and of every dialog, in both themes.
# Every dialog is opened by its real function (Show-InstallerAnalysisOptions of the shell script, Show-ThemedMessage of
# SuiteCommon) with the main window as owner, measured while it is open, and closed. The Options window is measured on every
# panel. Tests\WindowDialogs.ps1 finds the dialog functions with the syntax tree. Rules:
#   - the dialog title bar brush (active and inactive) is the title bar brush of the main window
#   - the title bar text of the dialog is readable (4.5:1) on that brush
#   - every button has bold text (SemiBold or heavier, 600; a normal weight is a defect)
#   - no button has a border thicker than 1 px, and no button border has the text color of the theme

BeforeDiscovery {
    . "$PSScriptRoot\WindowHarness.ps1"
    $script:WindowGuard = Test-WindowTestsAllowed
    if (-not $script:WindowGuard.Allowed -and -not $env:SUITE_WINDOW_GUARD_REPORTED) { Write-Host ('Window tests skipped: {0}.' -f $script:WindowGuard.Reason) }
    $script:ThemeCases = @(@{ Dark = $true; Theme = 'dark' }, @{ Dark = $false; Theme = 'light' })
}

BeforeAll {
    . "$PSScriptRoot\WindowHarness.ps1"
    $script:WindowGuard = Test-WindowTestsAllowed
    if (-not $script:WindowGuard.Allowed) { return }
    . "$PSScriptRoot\WindowConfig.ps1"
    . "$PSScriptRoot\WindowDialogs.ps1"
    $script:AppRoot = Split-Path -Parent $PSScriptRoot
    $script:Source = Get-AppDialogSource -Root $script:AppRoot -Shell $script:AppConfig.Shell
    $script:CallMissing = @($script:Source.DialogFunctions | Where-Object { -not $script:AppConfig.DialogCalls.ContainsKey($_) })
    $dialogList = @($script:Source.DialogFunctions | Where-Object { $script:AppConfig.DialogCalls.ContainsKey($_) } |
            ForEach-Object { @{ Name = $_; Call = $script:AppConfig.DialogCalls[$_] } })
    $script:Measured = @{}
    foreach ($dark in $true, $false) {
        $key = if ($dark) { 'dark' } else { 'light' }
        $script:Measured[$key] = Invoke-WpfSta -Arguments @{ Dark = $dark; Config = $script:AppConfig; Dialogs = $dialogList; Helper = $script:DialogHelperScript; ShellFunctions = $script:Source.ShellFunctions } -Script {
            . ([scriptblock]::Create($Arguments.Helper))
            . ([scriptblock]::Create($Arguments.ShellFunctions))
            # The Options window reads its preferences from this table.
            $global:Prefs = @{ SevenZipPath = ''; ReportsFolder = ''; DarkMode = $Arguments.Dark }
            $main = Open-MainWindowForTest -Config $Arguments.Config -Dark $Arguments.Dark
            try {
                $mainChrome = Get-SuiteWindowChrome -Window $main -Label 'main'
                $mainBody = Get-SuiteWindowBody -Window $main -Label 'main'
                $dialogs = @(foreach ($dlg in $Arguments.Dialogs) { Measure-AppDialog -Name $dlg.Name -Owner $main -CallScript $dlg.Call -Mode Chrome -Dark $Arguments.Dark })
                [pscustomobject]@{
                    ThemeText = $mainChrome.ThemeText; MainChrome = $mainChrome; MainBody = $mainBody
                    MainTitle = $mainChrome.Active; MainTitleInactive = $mainChrome.Inactive
                    Main      = @($mainChrome.Buttons); Dialogs = $dialogs
                }
            }
            finally { $main.Close() }
        }
    }
}

# The STA session is shared by all window test files of the run. A plain Close-WpfSession keeps it open.
AfterAll {
    if ($script:WindowGuard.Allowed) { Close-WpfSession }
}

Describe 'Chrome <Theme>' -ForEach $script:ThemeCases -Skip:(-not $script:WindowGuard.Allowed) {
    BeforeAll {
        $script:M = @($script:Measured[$Theme]) | Where-Object { $_.PSObject.Properties['Dialogs'] } | Select-Object -Last 1
    }

    It 'finds every dialog of the app and measures each one' {
        @($script:Source.DialogFunctions).Count | Should -BeGreaterThan 1
        $script:CallMissing | Should -BeNullOrEmpty -Because 'WindowConfig.ps1 needs a DialogCalls entry for every dialog function'
        @($script:M.Dialogs).Count | Should -Be $script:Source.ExpectedCount -Because 'one measurement per XAML load of a dialog function'
        @($script:M.Dialogs | ForEach-Object Name | Sort-Object) | Should -Be @($script:Source.DialogFunctions | Sort-Object)
    }

    It 'measures the buttons of every Options panel' {
        $options = @($script:M.Dialogs | Where-Object { $_.Name -eq 'Show-InstallerAnalysisOptions' })
        $options.Count | Should -Be 1
        @($options[0].Buttons | Where-Object { $_.Window -match '\[' }).Count | Should -BeGreaterThan 0 -Because 'the Browse and Open Logs Folder buttons sit in the panels'
    }

    It 'gives every dialog the title bar brush of the main window' {
        $bad = @($script:M.Dialogs | Where-Object { $_.Active -ne $script:M.MainTitle -or $_.Inactive -ne $script:M.MainTitleInactive } |
                ForEach-Object { '{0}: active {1} inactive {2}, main {3} {4}' -f $_.Name, $_.Active, $_.Inactive, $script:M.MainTitle, $script:M.MainTitleInactive })
        $bad | Should -BeNullOrEmpty
    }

    It 'keeps the title text of every dialog readable at 4.5:1' {
        $bad = @($script:M.Dialogs | Where-Object { $_.TitleRatio -lt 4.5 } | ForEach-Object { '{0}: {1}' -f $_.Name, $_.TitleRatio })
        $bad | Should -BeNullOrEmpty
    }

    It 'shows bold text on every button of the main window and of every dialog' {
        $all = @($script:M.Main) + @($script:M.Dialogs | ForEach-Object { $_.Buttons })
        $all.Count | Should -BeGreaterThan 5
        $bad = @($all | Where-Object { $_.Weight -lt 600 } | ForEach-Object { '{0} "{1}" weight {2}' -f $_.Window, $_.Text, $_.Weight })
        $bad | Should -BeNullOrEmpty
    }

    It 'gives no button a border thicker than 1 px or in the text color of the theme' {
        $all = @($script:M.Main) + @($script:M.Dialogs | ForEach-Object { $_.Buttons })
        $bad = @($all | Where-Object { $_.BorderThickness -gt 1 -or ($_.BorderThickness -gt 0 -and $_.BorderColor -eq $script:M.ThemeText) } |
                ForEach-Object { '{0} "{1}" border {2}px {3}' -f $_.Window, $_.Text, $_.BorderThickness, $_.BorderColor })
        $bad | Should -BeNullOrEmpty
    }
    It 'lists the body colors of the main window and of every dialog' {
        Write-Host ('{0} main: surface {1} text {2}' -f $Theme, $script:M.MainBody.BackLuminance, $script:M.MainBody.TextRatio)
        foreach ($d in $script:M.Dialogs) {
            Write-Host ('{0} {1}: surface {2} text {3}; inputs: {4}' -f $Theme, $d.Name, $d.Body.BackLuminance, $d.Body.TextRatio, ((@($d.Body.Inputs) | ForEach-Object { '{0} {1} lum {2} text {3} border {4}' -f $_.Kind, $_.Name, $_.BackLuminance, $_.TextRatio, $_.BorderRatio }) -join ' | '))
        }
        @($script:M.Dialogs).Count | Should -BeGreaterThan 0
    }

    It 'gives the body of every dialog the surface of the theme (light in light, dark in dark)' {
        $light = ($Theme -eq 'light')
        $bad = @($script:M.Dialogs | Where-Object { $null -ne $_.Body.BackLuminance -and ((($light -and $_.Body.BackLuminance -lt 0.5) -or (-not $light -and $_.Body.BackLuminance -gt 0.25))) } |
                ForEach-Object { '{0}: surface luminance {1} in the {2} theme' -f $_.Name, $_.Body.BackLuminance, $Theme })
        $bad | Should -BeNullOrEmpty
    }

    It 'gives the body of every dialog the same surface as the main window' {
        $bad = @($script:M.Dialogs | Where-Object { $null -ne $_.Body.BackLuminance -and $null -ne $script:M.MainBody.BackLuminance -and [math]::Abs($_.Body.BackLuminance - $script:M.MainBody.BackLuminance) -gt 0.1 } |
                ForEach-Object { '{0}: surface {1}, main {2}' -f $_.Name, $_.Body.BackLuminance, $script:M.MainBody.BackLuminance })
        $bad | Should -BeNullOrEmpty
    }

    It 'keeps 4.5:1 for the text of every dialog body and every input' {
        $bad = @()
        foreach ($d in $script:M.Dialogs) {
            if ($null -ne $d.Body.TextRatio -and $d.Body.TextRatio -lt 4.5) { $bad += ('{0}: window text {1}' -f $d.Name, $d.Body.TextRatio) }
            foreach ($i in @($d.Body.Inputs)) { if ($null -ne $i.TextRatio -and $i.TextRatio -lt 4.5) { $bad += ('{0}: {1} {2} text {3}' -f $d.Name, $i.Kind, $i.Name, $i.TextRatio) } }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'gives every input of every dialog the surface side of the theme' {
        $light = ($Theme -eq 'light')
        $bad = @()
        foreach ($d in $script:M.Dialogs) { foreach ($i in @($d.Body.Inputs)) { if ($null -ne $i.BackLuminance -and ((($light -and $i.BackLuminance -lt 0.4) -or (-not $light -and $i.BackLuminance -gt 0.3)))) { $bad += ('{0}: {1} {2} luminance {3}' -f $d.Name, $i.Kind, $i.Name, $i.BackLuminance) } } }
        $bad | Should -BeNullOrEmpty
    }

    It 'keeps the caption of the main window readable (4.5:1) on the bar of its state, active and behind a dialog' {
        $script:M.MainChrome.TitleRatio | Should -BeGreaterOrEqual 4.5
        $behind = @($script:M.Dialogs | ForEach-Object { $_.OwnerChrome })
        $behind.Count | Should -BeGreaterThan 0
        foreach ($b in $behind) {
            $b.IsActive | Should -BeFalse -Because 'the dialog took the focus'
            $b.TitleRatio | Should -BeGreaterOrEqual 4.5
        }
    }

    It 'gives the inactive light title bar blue with dark caption text, and the dark one white text' {
        foreach ($b in @($script:M.Dialogs | ForEach-Object { $_.OwnerChrome })) {
            if ($Theme -eq 'light') {
                $b.TitleBrushNow | Should -Be '#FF4BA3E0'
                $b.TitleText | Should -Be '#FF333333'
            }
            else { $b.TitleText | Should -Not -Be '#FF333333' }
        }
        $script:M.MainChrome.TitleText | Should -Not -Be '#FF333333' -Because 'the active caption is white'
    }
}