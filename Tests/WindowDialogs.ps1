# Shared by the window tests that measure the dialogs of Installer Analysis (Chrome.Window.Tests.ps1 and ButtonStates.Window.Tests.ps1).
#
# The dialogs are not built from one XAML file. The Options window is built by a function of the shell script from a XAML
# here-string, and its panels come from factory functions. The message dialog comes from SuiteCommon (Show-ThemedMessage).
# A test that measures the real dialogs must run the real functions. A modal dialog blocks its caller, and a timer on the
# STA thread cannot close it again (the run hangs). So Get-AppDialogSource copies each dialog function as NameForTest, with
# ShowDialog turned into Show, and Measure-AppDialog measures the open window and closes it.
#
# Get-AppDialogSource (Pester thread) finds every dialog function with the syntax tree of the shell script and of SuiteCommon,
# so a dialog that somebody adds shows up in the count and the tests fail until the dialog is measured too.

function Get-AppDialogSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Shell
    )
    $parse = { param($p) [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$null) }
    $isFunction = { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }
    $isLoad = {
        param($n)
        $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and
        [string]$n.Member.Value -eq 'Load' -and $n.Expression.Extent.Text -match 'XamlReader'
    }
    $isCommand = { param($n) $n -is [System.Management.Automation.Language.CommandAst] }
    $shellAst = & $parse (Join-Path $Root $Shell)
    $commonAst = & $parse (Join-Path $Root 'Lib\SuiteCommon\SuiteCommon.psm1')

    $shellFunction = @{}
    foreach ($f in $shellAst.FindAll($isFunction, $true)) { $shellFunction[$f.Name] = $f }
    $commonFunction = @{}
    foreach ($f in $commonAst.FindAll($isFunction, $true)) { $commonFunction[$f.Name] = $f }

    # Shell functions that load XAML are dialogs of the app. The load of the main window is outside any function.
    $dialogName = New-Object System.Collections.Generic.List[string]
    $loadCount = 0
    foreach ($name in ($shellFunction.Keys | Sort-Object)) {
        $n = @($shellFunction[$name].FindAll($isLoad, $true)).Count
        if ($n -gt 0) { $dialogName.Add($name); $loadCount += $n }
    }
    # SuiteCommon functions that load XAML and that the shell calls are dialogs of the app too.
    $called = @($shellAst.FindAll($isCommand, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($name in $called) {
        if (-not $commonFunction.ContainsKey($name)) { continue }
        $n = @($commonFunction[$name].FindAll($isLoad, $true)).Count
        if ($n -gt 0) { $dialogName.Add($name); $loadCount += $n }
    }

    # The shell functions that the shell dialogs call (the panel factories of the Options window), with their text.
    $needed = New-Object System.Collections.Generic.List[string]
    $queue = New-Object System.Collections.Generic.Queue[string]
    foreach ($name in $dialogName) { if ($shellFunction.ContainsKey($name)) { $queue.Enqueue($name) } }
    while ($queue.Count -gt 0) {
        $name = $queue.Dequeue()
        if ($needed.Contains($name)) { continue }
        $needed.Add($name)
        foreach ($c in $shellFunction[$name].FindAll($isCommand, $true)) {
            $callee = $c.GetCommandName()
            if ($callee -and $shellFunction.ContainsKey($callee) -and -not $needed.Contains($callee)) { $queue.Enqueue($callee) }
        }
    }
    # A modal dialog blocks its caller, and a timer on the STA thread cannot close it again (the run hangs). So each dialog
    # function is copied as NameForTest with its ShowDialog call turned into Show and a return of the window. Everything else
    # in the function runs as the app runs it.
    $testCopy = foreach ($name in $dialogName) {
        $fn = if ($shellFunction.ContainsKey($name)) { $shellFunction[$name] } else { $commonFunction[$name] }
        $pattern = '\[void\]\s*\$dlg\.ShowDialog\(\)'
        if ($fn.Extent.Text -notmatch $pattern) { throw ('{0}: no [void]$dlg.ShowDialog() call to turn into Show.' -f $name) }
        $text = [regex]::Replace($fn.Extent.Text, $pattern, '$dlg.Show(); return $dlg')
        [regex]::Replace($text, ('(?m)^function ' + [regex]::Escape($name) + '\b'), ('function ' + $name + 'ForTest'))
    }
    [pscustomobject]@{
        DialogFunctions = @($dialogName)
        ExpectedCount   = $loadCount
        ShellFunctions  = ((@($needed | ForEach-Object { $shellFunction[$_].Extent.Text }) + @($testCopy)) -join "`n`n")
    }
}

# Script text that runs in the STA runspace (Invoke-WpfSta). Dot-source it with . ([scriptblock]::Create($text)).
$script:DialogHelperScript = @'
# $Mode is Chrome (title bar and button rows of the dialog and of every Options panel) or States (button states with the
# real mouse). $CallScript opens the dialog by its ForTest function (not modal) and returns the window.
function Measure-AppDialog {
    param([string]$Name, $Owner, [string]$CallScript, [string]$Mode = 'Chrome', [bool]$Dark = $true, [int]$Max = 2)
    $d = @(& ([scriptblock]::Create($CallScript))) | Where-Object { $_ -is [System.Windows.Window] } | Select-Object -Last 1
    if (-not $d) { throw ('{0}: the dialog did not open.' -f $Name) }
    try {
        Wait-Layout $d
        if ($Mode -eq 'States') {
            return [pscustomobject]@{ Name = $Name; States = @(Get-SuiteButtonStateReport -Window $d -Dark $Dark -Max $Max) }
        }
        $c = Get-SuiteWindowChrome -Window $d -Label $Name
        $body = Get-SuiteWindowBody -Window $d -Label $Name
        # The owner behind the open dialog: its title bar is the inactive one.
        $ownerChrome = $(if ($Owner) { Get-SuiteWindowChrome -Window $Owner -Label ('main behind ' + $Name) })
        $buttons = New-Object System.Collections.Generic.List[object]
        foreach ($b in @($c.Buttons)) { $buttons.Add($b) }
        # The Options window shows one panel at a time. Walk every panel so that its buttons are measured too.
        $nav = $d.FindName('lstNav')
        if ($nav) {
            $base = @($c.Buttons | Where-Object { $_.Name } | ForEach-Object { $_.Name })
            for ($i = 0; $i -lt $nav.Items.Count; $i++) {
                $nav.SelectedIndex = $i
                Wait-Layout $d
                if ($i -eq 0) { continue }
                foreach ($b in @(Get-SuiteButtonRow -Window $d -Label ('{0} [{1}]' -f $Name, $nav.Items[$i]))) {
                    if (-not ($b.Name -and $base -contains $b.Name)) { $buttons.Add($b) }
                }
            }
        }
        return [pscustomobject]@{ Name = $Name; Title = $c.Title; Active = $c.Active; Inactive = $c.Inactive; TitleRatio = $c.TitleRatio; Body = $body; OwnerChrome = $ownerChrome; Buttons = $buttons.ToArray() }
    }
    finally { $d.Close() }
}

# Opens the main window the way Window.Tests.ps1 does, with the sample data of the config, and applies the theme.
function Open-MainWindowForTest {
    param($Config, [bool]$Dark)
    $w = Open-TestWindow -XamlPath (Join-Path $Root $Config.Xaml) -Dark $Dark -PopulateScript $Config.PopulateScript
    Initialize-ShellTheme -Window $w -Dark $Dark -Views $Config.Views -OptionsButtonName $Config.OptionsButton -LogLabelName $Config.LogLabel -ActiveView $Config.Views[0].Name -ActiveMode $Config.ActiveMode
    foreach ($v in $Config.Views) { $w.FindName($v.Container).Visibility = $(if ($v.Name -eq $Config.Views[0].Name) { 'Visible' } else { 'Collapsed' }) }
    Wait-Layout $w
    return $w
}
'@
