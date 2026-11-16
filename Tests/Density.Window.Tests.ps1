#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Window test for the compact 1080p density and for vacant space (D-20). The main window is opened off screen, in both themes,
# at the work area of the session (1920x1032 on a 1080p screen at 100 percent) and at 1024x720, and measured: sidebar buttons,
# inline buttons, single-line boxes, grid rows and headers, the width that each view uses, and the free area of each view.
# The 1024x720 case proves that nothing clips and the sidebar fits. The work area case is the design basis.

BeforeDiscovery {
    . "$PSScriptRoot\WindowHarness.ps1"
    $script:WindowGuard = Test-WindowTestsAllowed
    if (-not $script:WindowGuard.Allowed -and -not $env:SUITE_WINDOW_GUARD_REPORTED) { Write-Host ('Window tests skipped: {0}.' -f $script:WindowGuard.Reason) }
    $script:Cases = @(@{ Dark = $true; Theme = 'dark'; W = 1024; H = 720; Size = '1024x720'; Design = $false }, @{ Dark = $false; Theme = 'light'; W = 1024; H = 720; Size = '1024x720'; Design = $false })
    if ($script:WindowGuard.Allowed) {
        $design = Get-DesignSize
        $script:Cases += @(@{ Dark = $true; Theme = 'dark'; W = $design.W; H = $design.H; Size = $design.Key; Design = $true }, @{ Dark = $false; Theme = 'light'; W = $design.W; H = $design.H; Size = $design.Key; Design = $true })
    }
    $script:ViewCases = @(@{ View = 'Overview' }, @{ View = 'MSI Properties' }, @{ View = 'Payload' }, @{ View = 'File Browser' }, @{ View = 'Inner Installers' }, @{ View = 'Registry Settings' }, @{ View = 'Strings' })
}

BeforeAll {
    . "$PSScriptRoot\WindowHarness.ps1"
    $script:WindowGuard = Test-WindowTestsAllowed
    if (-not $script:WindowGuard.Allowed) { return }
    . "$PSScriptRoot\WindowConfig.ps1"
    $wa = [System.Windows.SystemParameters]::WorkArea
    Write-Host ('Work area of this session: {0}x{1}' -f $wa.Width, $wa.Height)
    $design = Get-DesignSize
    $script:Measured = @{}
    foreach ($case in @(
            @{ Dark = $true; W = 1024; H = 720 }, @{ Dark = $true; W = $design.W; H = $design.H },
            @{ Dark = $false; W = 1024; H = 720 }, @{ Dark = $false; W = $design.W; H = $design.H })) {
        $key = '{0}|{1}x{2}' -f $(if ($case.Dark) { 'dark' } else { 'light' }), $case.W, $case.H
        $case.Config = $script:AppConfig
        $script:Measured[$key] = Invoke-WpfSta -Arguments $case -Script {
            $cfg = $Arguments.Config
            $win = Open-TestWindow -XamlPath (Join-Path $Root $cfg.Xaml) -Dark $Arguments.Dark -Width $Arguments.W -Height $Arguments.H -PopulateScript $cfg.PopulateScript
            try {
                Wait-Layout $win
                $sidebar = @(foreach ($v in $cfg.Views) { $b = $win.FindName($v.Button); $p = $b.TransformToAncestor($win).Transform([System.Windows.Point]::new(0, 0)); [pscustomobject]@{ Name = $v.Button; Bottom = $p.Y + $b.ActualHeight; Height = $b.ActualHeight } })
                $host_ = $win.FindName('viewHost')
                $views = @(foreach ($view in $cfg.Views) {
                        foreach ($v in $cfg.Views) { $win.FindName($v.Container).Visibility = $(if ($v.Name -eq $view.Name) { 'Visible' } else { 'Collapsed' }) }
                        Wait-Layout $win
                        $c = $win.FindName($view.Container)
                        $buttons = @(foreach ($e in (Get-VisualDescendants $c)) { if ($e -is [System.Windows.Controls.Button] -and $e.Style -and $e.Name -and (Test-VisibleInTree $e)) { [pscustomobject]@{ Name = $e.Name; Height = $e.ActualHeight } } })
                        $boxes = @(foreach ($e in (Get-VisualDescendants $c)) { if ($e -is [System.Windows.Controls.TextBox] -and $e.Name -like '*Filter' -and (Test-VisibleInTree $e)) { [pscustomobject]@{ Name = $e.Name; Height = $e.ActualHeight } } })
                        $grids = @(foreach ($e in (Get-VisualDescendants $c)) {
                                if ($e -is [System.Windows.Controls.DataGrid] -and (Test-VisibleInTree $e)) {
                                    $hdr = $null; foreach ($x in (Get-VisualDescendants $e)) { if ($x -is [System.Windows.Controls.Primitives.DataGridColumnHeadersPresenter]) { $hdr = $x; break } }
                                    $row = $null; foreach ($x in (Get-VisualDescendants $e)) { if ($x -is [System.Windows.Controls.DataGridRow]) { $row = $x; break } }
                                    $pt = $e.TransformToAncestor($c).Transform([System.Windows.Point]::new(0, 0))
                                    [pscustomobject]@{ Name = $e.Name; Width = $e.ActualWidth; Height = $e.ActualHeight; Right = $pt.X + $e.ActualWidth; Bottom = $pt.Y + $e.ActualHeight; HeaderHeight = $(if ($hdr) { $hdr.ActualHeight } else { $null }); RowHeight = $(if ($row) { $row.ActualHeight } else { $null }) }
                                }
                            })
                        [pscustomobject]@{ View = $view.Name; Width = $c.ActualWidth; Height = $c.ActualHeight; Buttons = $buttons; Boxes = $boxes; Grids = $grids }
                    })
                [pscustomobject]@{ Width = $win.ActualWidth; Height = $win.ActualHeight; HostWidth = $host_.ActualWidth; HostHeight = $host_.ActualHeight; Sidebar = $sidebar; Views = $views }
            }
            finally { $win.Close() }
        }
    }
}

AfterAll {
    if ($script:WindowGuard.Allowed) { Close-WpfSession }
}

Describe 'Density <Theme> <Size>' -ForEach $script:Cases -Skip:(-not $script:WindowGuard.Allowed) {
    BeforeAll { $script:M = $script:Measured['{0}|{1}' -f $Theme, $Size] }

    It 'sizes every sidebar button between 34 and 36 px and fits all of them without scrolling' {
        foreach ($b in $script:M.Sidebar) { [math]::Round($b.Height) | Should -BeIn 34, 35, 36 -Because $b.Name }
        ($script:M.Sidebar | Select-Object -Last 1).Bottom | Should -BeLessThan $script:M.Height
    }

    It 'sizes the inline buttons at 26 px and the single-line boxes at 26 px in the <View> view' -ForEach $script:ViewCases {
        $m = $script:M.Views | Where-Object View -eq $View
        foreach ($b in @($m.Buttons | Where-Object { $_.Name -notmatch '^btnView|^btnOptions' })) { [math]::Round($b.Height) | Should -BeLessOrEqual 28 -Because $b.Name }
        foreach ($b in @($m.Boxes)) { [math]::Round($b.Height) | Should -BeIn 26, 27, 28 -Because $b.Name }
    }

    It 'gives grid rows 24 to 26 px and headers 26 px in the <View> view' -ForEach $script:ViewCases {
        $m = $script:M.Views | Where-Object View -eq $View
        foreach ($g in @($m.Grids)) {
            if ($null -ne $g.HeaderHeight) { $g.HeaderHeight | Should -BeLessOrEqual 26.5 -Because $g.Name }
            if ($null -ne $g.RowHeight) { [math]::Round($g.RowHeight) | Should -BeIn 24, 25, 26 -Because $g.Name }
        }
    }
}

Describe 'Vacant space at the work area <Theme>' -ForEach @(@{ Theme = 'dark' }, @{ Theme = 'light' }) -Skip:(-not $script:WindowGuard.Allowed) {
    BeforeAll { $design = Get-DesignSize; $script:M = $script:Measured['{0}|{1}' -f $Theme, $design.Key] }

    It 'lets every view use the area of the view host (no vacant area larger than 160 px wide or 120 px high)' {
        $bad = @()
        foreach ($v in $script:M.Views) {
            $freeW = $script:M.HostWidth - $v.Width; $freeH = $script:M.HostHeight - $v.Height
            if ($freeW -gt 160 -or $freeH -gt 120) { $bad += ('{0}: free {1} x {2}' -f $v.View, [int]$freeW, [int]$freeH) }
        }
        $bad | Should -BeNullOrEmpty -Because ('views with vacant area: ' + ($bad -join '; '))
    }

    It 'lets every grid reach the right and the bottom edge of its view (no vacant area larger than 160 px wide or 120 px high)' {
        $bad = @()
        foreach ($v in $script:M.Views) {
            foreach ($g in @($v.Grids)) {
                $freeW = $v.Width - $g.Right; $freeH = $v.Height - $g.Bottom
                if ($freeW -gt 160 -or $freeH -gt 120) { $bad += ('{0}/{1}: free {2} x {3}' -f $v.View, $g.Name, [int]$freeW, [int]$freeH) }
            }
        }
        $bad | Should -BeNullOrEmpty -Because ('grids with vacant area: ' + ($bad -join '; '))
    }
}