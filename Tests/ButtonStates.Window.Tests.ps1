#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Window test for the hover, focus and pressed states of sample buttons of the main window and of the Options window, in both themes.
# It needs the real mouse, so it runs only in a visible run (SUITE_VISIBLE_WINDOWS=1, the labadmin session of CLIENT01).
# The measurement is Get-SuiteButtonStateReport of SuiteCommon. The main window gives up to 4 buttons of distinct styles. The
# Options window (opened by its real function, see Tests\WindowDialogs.ps1) gives up to 2 more: the dialog button and the
# primary dialog button. For each sampled button and each state the test requires:
#   - the button text has 4.5:1 contrast on the button fill (the backdrop of the button where the fill is transparent)
#   - the button is told apart from its backdrop: its border or its fill has 3:1 contrast on it

BeforeDiscovery {
    . "$PSScriptRoot\WindowHarness.ps1"
    $guard = Test-WindowTestsAllowed
    $script:Visible = ($env:SUITE_VISIBLE_WINDOWS -eq '1')
    if ($guard.Allowed -and -not $script:Visible) { Write-Host 'Button state tests skipped: SUITE_VISIBLE_WINDOWS is not 1 (they need the real mouse).' }
    # The window guard of this file also needs the visible run, because the test moves the real mouse.
    $script:WindowGuard = [pscustomobject]@{ Allowed = ($guard.Allowed -and $script:Visible); Reason = $guard.Reason }
    $script:ThemeCases = @(@{ Dark = $true; Theme = 'dark' }, @{ Dark = $false; Theme = 'light' })
}

BeforeAll {
    . "$PSScriptRoot\WindowHarness.ps1"
    $guard = Test-WindowTestsAllowed
    $script:Visible = ($env:SUITE_VISIBLE_WINDOWS -eq '1')
    $script:WindowGuard = [pscustomobject]@{ Allowed = ($guard.Allowed -and $script:Visible); Reason = $guard.Reason }
    if (-not $script:WindowGuard.Allowed) { return }
    . "$PSScriptRoot\WindowConfig.ps1"
    . "$PSScriptRoot\WindowDialogs.ps1"
    $script:AppRoot = Split-Path -Parent $PSScriptRoot
    $script:Source = Get-AppDialogSource -Root $script:AppRoot -Shell $script:AppConfig.Shell
    $script:Measured = @{}
    foreach ($dark in $true, $false) {
        $key = if ($dark) { 'dark' } else { 'light' }
        $script:Measured[$key] = Invoke-WpfSta -Arguments @{ Dark = $dark; Config = $script:AppConfig; Helper = $script:DialogHelperScript; ShellFunctions = $script:Source.ShellFunctions } -Script {
            . ([scriptblock]::Create($Arguments.Helper))
            . ([scriptblock]::Create($Arguments.ShellFunctions))
            $global:Prefs = @{ SevenZipPath = ''; ReportsFolder = ''; DarkMode = $Arguments.Dark }
            $cfg = $Arguments.Config
            $main = Open-MainWindowForTest -Config $cfg -Dark $Arguments.Dark
            try {
                $rows = New-Object System.Collections.Generic.List[object]
                foreach ($r in @(Get-SuiteButtonStateReport -Window $main -Dark $Arguments.Dark -Max 6)) {
                    $r.Name = 'main/' + $r.Name
                    $r | Add-Member -NotePropertyName Source -NotePropertyValue 'main'
                    $rows.Add($r)
                }
                $dlg = Measure-AppDialog -Name 'Show-InstallerAnalysisOptions' -Owner $main -CallScript $cfg.DialogCalls['Show-InstallerAnalysisOptions'] -Mode States -Dark $Arguments.Dark -Max 2
                foreach ($r in @($dlg.States)) {
                    $r.Name = 'options/' + $r.Name
                    $r | Add-Member -NotePropertyName Source -NotePropertyValue 'dialog'
                    $rows.Add($r)
                }
                $rows.ToArray()
            }
            finally { $main.Close() }
        }
    }
}

# The STA session is shared by all window test files of the run. A plain Close-WpfSession keeps it open.
AfterAll {
    if ($script:WindowGuard.Allowed) { Close-WpfSession }
}

Describe 'Button states <Theme>' -ForEach $script:ThemeCases -Skip:(-not $script:WindowGuard.Allowed) {
    BeforeAll { $script:Rows = @(@($script:Measured[$Theme]) | Where-Object { $_.PSObject.Properties['States'] }) }

    It 'samples at least 3 buttons and reaches the focus, hover and pressed states' {
        $script:Rows.Count | Should -BeGreaterOrEqual 3
        $bad = @($script:Rows | Where-Object { -not $_.Hover -or -not $_.Pressed -or -not $_.Focused } | ForEach-Object { '{0}: hover {1} pressed {2} focused {3}' -f $_.Name, $_.Hover, $_.Pressed, $_.Focused })
        $bad | Should -BeNullOrEmpty -Because 'the mouse and the keyboard focus must reach the button, or the states are not measured'
    }

    It 'keeps 4.5:1 text contrast in every state' {
        $bad = @()
        foreach ($r in $script:Rows) { foreach ($s in $r.States.Keys) { if ($r.States[$s].Text -lt 4.5) { $bad += ('{0} {1}: {2}' -f $r.Name, $s, $r.States[$s].Text) } } }
        $bad | Should -BeNullOrEmpty
    }

    It 'tells the button from its backdrop (3:1) in every state' {
        $bad = @()
        foreach ($r in $script:Rows) { foreach ($s in $r.States.Keys) { if ($r.States[$s].Edge -lt 3.0) { $bad += ('{0} {1}: {2}' -f $r.Name, $s, $r.States[$s].Edge) } } }
        $bad | Should -BeNullOrEmpty
    }

    It 'keeps a blue button blue in hover and pressed and never black; a dialog button moves one visible step in each state' {
        $bad = @()
        foreach ($r in $script:Rows) {
            if (-not $r.States['normal'].Blue) { continue }
            foreach ($s in 'hover', 'pressed') {
                $st = $r.States[$s]
                if (-not $st.Blue) { $bad += ('{0} {1}: fill {2} is not blue' -f $r.Name, $s, $st.Fill) }
                if ($st.FillLuminance -lt 0.03) { $bad += ('{0} {1}: fill {2} luminance {3} is black' -f $r.Name, $s, $st.Fill, $st.FillLuminance) }
                $step = ([math]::Max($st.FillLuminance, $r.States['normal'].FillLuminance) + 0.05) / ([math]::Min($st.FillLuminance, $r.States['normal'].FillLuminance) + 0.05)
                if ($r.Source -eq 'dialog' -and $step -lt 1.05) { $bad += ('{0} {1}: fill {2} is the same as normal {3}' -f $r.Name, $s, $st.Fill, $r.States['normal'].Fill) }
            }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'never flips a neutral button to black or to white in hover and pressed' {
        $bad = @()
        foreach ($r in $script:Rows) {
            if ($r.States['normal'].Blue) { continue }
            $n = $r.States['normal'].FillLuminance
            foreach ($s in 'hover', 'pressed') {
                $l = $r.States[$s].FillLuminance
                if (-not $r.States[$s].Blue -and (($l -lt 0.03 -and $n -gt 0.1) -or ($l -gt 0.9 -and $n -lt 0.1))) { $bad += ('{0} {1}: fill {2} flips from {3}' -f $r.Name, $s, $r.States[$s].Fill, $r.States['normal'].Fill) }
            }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'measures buttons of the main window and of a dialog, one blue and one neutral dialog button' {
        @($script:Rows | Where-Object Source -eq 'main').Count | Should -BeGreaterThan 0
        $dialog = @($script:Rows | Where-Object Source -eq 'dialog')
        @($dialog | Where-Object { $_.States['normal'].Blue }).Count | Should -BeGreaterThan 0 -Because 'the primary dialog button is blue'
        @($dialog | Where-Object { -not $_.States['normal'].Blue }).Count | Should -BeGreaterThan 0 -Because 'the secondary dialog button is neutral'
    }

    It 'lists the measured values' {
        foreach ($r in $script:Rows) { Write-Host ('{0} {1}: ' -f $Theme, $r.Name) -NoNewline; Write-Host (($r.States.Keys | ForEach-Object { '{0} text {1} edge {2}' -f $_, $r.States[$_].Text, $r.States[$_].Edge }) -join ' | ') }
        $script:Rows.Count | Should -BeGreaterThan 0
    }
}
