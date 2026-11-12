#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Guard tests for the theme rules. They parse the files (XAML, XAML here-strings and PowerShell syntax trees). The one
# behavior test builds a Button without a window in an STA runspace. They run on Windows PowerShell 5.1 and PowerShell 7
# and open no window.
#   (a) Every blue background in XAML and PowerShell has a white foreground, also in hover, pressed and selected states.
#   (b) No font size, weight, style or text decoration depends on the theme. Every title is bold. A title of a site code
#       or SMS Provider box is bold and 14 pt or larger, and its value is not (this app has no such box today).
#   (c) No banned word is in a tooltip, a UI string, the README or the user guide. A tooltip is one short sentence.
#   (d) Every button takes the shared themed style. The dialog has one secondary style. Titles are in Title Case.
#   (e) No window text shows the text of an exception.
#   (f) No path filter of a repository script depends on where the repository folder is.

BeforeDiscovery {
    . "$PSScriptRoot\ThemeGuardHelpers.ps1"
    $script:arrPsFileD = @(
        'start-installeranalysis.ps1', 'Module\InstallerAnalysisCommon.psm1', 'Lib\SuiteCommon\SuiteCommon.psm1'
    ) | ForEach-Object { @{ Name = $_; Path = (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath $_) } }
    $script:arrAppPsFileD = @($script:arrPsFileD | Where-Object { $_.Name -notmatch 'SuiteCommon' })
    $script:arrXamlDocD = @(Get-XamlDocument)
    $script:arrOwnXamlDocD = @($script:arrXamlDocD | Where-Object { $_.Source -notmatch 'SuiteCommon' })
}

BeforeAll {
    . "$PSScriptRoot\ThemeGuardHelpers.ps1"
    $script:arrXamlDoc = @(Get-XamlDocument)
    $script:arrOwnXamlDoc = @($script:arrXamlDoc | Where-Object { $_.Source -notmatch 'SuiteCommon' })
    $script:strShellPath = Join-Path -Path $script:strRepoRoot -ChildPath 'start-installeranalysis.ps1'
    $script:strModulePath = Join-Path -Path $script:strRepoRoot -ChildPath 'Module\InstallerAnalysisCommon.psm1'
    $script:strNamespace = 'xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:Controls="clr-namespace:MahApps.Metro.Controls;assembly=MahApps.Metro"'
    $script:strThemedStyle = '<Style x:Key="ThemedButtonStyle" TargetType="Button" BasedOn="{StaticResource MahApps.Styles.Button.Square}"/>'
    function Write-TempScript {
        param([string]$Text)
        $strTemp = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('themeguard-' + [guid]::NewGuid().ToString('N') + '.ps1')
        [System.IO.File]::WriteAllText($strTemp, $Text)
        return $strTemp
    }
}

Describe 'Blue backgrounds have white text (a)' {
    It 'finds XAML to check' {
        $script:arrXamlDoc.Count | Should -BeGreaterThan 2
        @($script:arrXamlDoc | Where-Object { $_.Source -eq 'MainWindow.xaml' }).Count | Should -Be 1
        @($script:arrOwnXamlDoc | Where-Object { $_.Source -like 'start-installeranalysis.ps1 here-string*' }).Count | Should -BeGreaterThan 0
    }

    It 'recognizes blue and white brushes' {
        Test-BlueBrush '{DynamicResource MahApps.Brushes.Accent}' | Should -BeTrue
        Test-BlueBrush '{DynamicResource MahApps.Colors.Accent}' | Should -BeTrue
        Test-BlueBrush '{DynamicResource MahApps.Colors.AccentBase}' | Should -BeTrue
        Test-BlueBrush '{DynamicResource MahApps.Brushes.Accent3}' | Should -BeTrue
        Test-BlueBrush '{DynamicResource MahApps.Brushes.Highlight}' | Should -BeTrue
        Test-BlueBrush '{DynamicResource {x:Static SystemColors.HighlightBrushKey}}' | Should -BeTrue
        Test-BlueBrush '#0078D4' | Should -BeTrue
        Test-BlueBrush '#FF0078D4' | Should -BeTrue
        Test-BlueBrush '#07D' | Should -BeTrue
        Test-BlueBrush '#1E1E1E' | Should -BeFalse
        Test-BlueBrush '#3A3A3A' | Should -BeFalse
        Test-BlueBrush '{DynamicResource MahApps.Brushes.ThemeBackground}' | Should -BeFalse
        Test-WhiteBrush '{DynamicResource MahApps.Brushes.IdealForeground}' | Should -BeTrue
        Test-WhiteBrush 'White' | Should -BeTrue
        Test-WhiteBrush 'Black' | Should -BeFalse
    }

    It 'flags a blue background that has no white foreground, with every property form' {
        $strOpen = '<Style xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:Controls="clr-namespace:MahApps.Metro.Controls;assembly=MahApps.Metro" TargetType="Button">'
        @(Get-BlueWithoutWhite -Text ($strOpen + '<Setter Property="Background" Value="#0078D4"/></Style>') -Source 's').Count | Should -Be 1
        @(Get-BlueWithoutWhite -Text ($strOpen + '<Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/></Style>') -Source 's').Count | Should -Be 0
        @(Get-BlueWithoutWhite -Text ($strOpen + '<Setter Property="Border.Background" Value="{DynamicResource MahApps.Brushes.Accent}"/></Style>') -Source 's').Count | Should -Be 1
        @(Get-BlueWithoutWhite -Text ($strOpen + '<Setter Property="Controls:ControlsHelper.MouseOverBackground" Value="{DynamicResource MahApps.Brushes.Accent}"/></Style>') -Source 's').Count | Should -Be 1
        @(Get-BlueWithoutWhite -Text ($strOpen + '<Setter Property="Background"><Setter.Value><SolidColorBrush Color="{DynamicResource MahApps.Colors.Accent}"/></Setter.Value></Setter></Style>') -Source 's').Count | Should -Be 1
        @(Get-BlueWithoutWhite -Text ($strOpen + '<Setter Property="Background"><Setter.Value><LinearGradientBrush><GradientStop Color="#0078D4"/></LinearGradientBrush></Setter.Value></Setter></Style>') -Source 's').Count | Should -Be 1
        @(Get-BlueWithoutWhite -Text ($strOpen + '<Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Accent}"/></Trigger></Style.Triggers></Style>') -Source 's').Count | Should -Be 1
        @(Get-BlueWithoutWhite -Text ($strOpen + '<Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Accent}"/><Setter Property="Foreground" Value="{DynamicResource MahApps.Brushes.IdealForeground}"/></Trigger></Style.Triggers></Style>') -Source 's').Count | Should -Be 0
        $strGrid = '<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">'
        @(Get-BlueWithoutWhite -Text ($strGrid + '<Border Background="#0078D4"><TextBlock Text="x"/></Border></Grid>') -Source 's').Count | Should -Be 1
        @(Get-BlueWithoutWhite -Text ($strGrid + '<Border Background="#0078D4"><TextBlock Text="x" Foreground="White"/></Border></Grid>') -Source 's').Count | Should -Be 0
        @(Get-BlueWithoutWhite -Text ($strGrid + '<Button Background="{DynamicResource MahApps.Brushes.Accent}" Content="x"/></Grid>') -Source 's').Count | Should -Be 1
        @(Get-BlueWithoutWhite -Text ($strGrid + '<Border><Border.Background><SolidColorBrush Color="#0078D4"/></Border.Background></Border></Grid>') -Source 's').Count | Should -Be 1
    }

    It 'has a white foreground on every blue background of <_.Source>' -ForEach $script:arrOwnXamlDocD {
        $arrBad = @(Get-BlueWithoutWhite -Text $_.Text -Source $_.Source)
        $arrBad | Should -BeNullOrEmpty
    }

    It 'sets no blue color as a Background in <Name>, and each CSS rule with a blue background has white text' -ForEach $script:arrAppPsFileD {
        $arrBad = @(foreach ($strHit in @(Get-ScriptBlueBackground -Path $Path)) { 'background ' + $strHit })
        $arrBad += @(foreach ($strString in @(Get-ScriptString -Path $Path)) {
                foreach ($objMatch in [regex]::Matches($strString, '\{([^}]*)\}')) {
                    $strRule = $objMatch.Groups[1].Value
                    $objBackground = [regex]::Match($strRule, '(?i)(?<![-\w])background(?:-color)?\s*:\s*(#[0-9A-F]{6,8})\b')
                    if ($objBackground.Success -and (Test-BlueBrush $objBackground.Groups[1].Value) -and $strRule -notmatch '(?i)(?<![-\w])color\s*:\s*(#fff(fff)?|white)\b') { 'css ' + $strRule }
                }
            })
        $arrBad | Should -BeNullOrEmpty
    }

    It 'finds the CSS rule of the HTML export that has a blue background' {
        $strRule = @(Get-ScriptString -Path $script:strModulePath | Where-Object { $_ -match '(?i)background\s*:\s*#0078D4' })
        $strRule.Count | Should -BeGreaterThan 0
        $strRule[0] | Should -Match '(?i)(?<![-\w])color\s*:\s*#fff\b'
    }

    It 'finds a blue Background assignment in a script' {
        $strTemp = Write-TempScript "`$b.Background = '#0078D4'`n`$c.Foreground = '#0078D4'`n`$d.Background = '#1E1E1E'`n"
        try {
            @(Get-ScriptBlueBackground -Path $strTemp).Count | Should -Be 1
            [System.IO.File]::WriteAllText($strTemp, "`$b.Background = '#0078D4'`n`$b.Foreground = 'White'`n")
            @(Get-ScriptBlueBackground -Path $strTemp).Count | Should -Be 0
        }
        finally { Remove-Item -LiteralPath $strTemp -Force -ErrorAction SilentlyContinue }
    }

    It 'sets a white foreground on every accent button style outside SuiteCommon in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        $arrBad = @(Get-AccentButtonWithoutWhite -Text $_.Text -Source $_.Source)
        $arrBad | Should -BeNullOrEmpty
    }

    It 'flags an accent button style that has no white foreground' {
        $strXaml = '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"><Style x:Key="A" TargetType="Button" BasedOn="{StaticResource MahApps.Styles.Button.Square.Accent}"><Setter Property="Height" Value="32"/></Style></ResourceDictionary>'
        @(Get-AccentButtonWithoutWhite -Text $strXaml -Source 'sample').Count | Should -Be 1
        $strOk = $strXaml.Replace('<Setter Property="Height" Value="32"/>', '<Setter Property="Foreground" Value="{DynamicResource MahApps.Brushes.IdealForeground}"/>')
        @(Get-AccentButtonWithoutWhite -Text $strOk -Source 'sample').Count | Should -Be 0
    }

    It 'sets no literal color and no Opacity on a blue element outside the styles of <_.Source>' -ForEach $script:arrOwnXamlDocD {
        @(Get-ElementColorViolation -Text $_.Text -Source $_.Source) | Should -BeNullOrEmpty
    }

    It 'flags a literal color on an element and an Opacity on a blue element' {
        $strGrid = '<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">'
        @(Get-ElementColorViolation -Text ($strGrid + '<TextBlock Foreground="White"/></Grid>') -Source 's').Count | Should -Be 1
        @(Get-ElementColorViolation -Text ($strGrid + '<Border Background="#0078D4"/></Grid>') -Source 's').Count | Should -Be 1
        @(Get-ElementColorViolation -Text ($strGrid + '<Border Background="{DynamicResource MahApps.Brushes.Accent}" Opacity="0.85"/></Grid>') -Source 's').Count | Should -Be 1
        @(Get-ElementColorViolation -Text ($strGrid + '<Border Background="{DynamicResource MahApps.Brushes.ThemeBackground}" Opacity="0.9"><TextBlock Foreground="{DynamicResource MahApps.Brushes.IdealForeground}"/></Border></Grid>') -Source 's').Count | Should -Be 0
        @(Get-ElementColorViolation -Text ($strGrid + '<Grid.Resources><Style TargetType="TextBlock"><Setter Property="Foreground" Value="White"/></Style></Grid.Resources></Grid>') -Source 's').Count | Should -Be 0
    }

    It 'sets the foreground of every selected-state trigger that sets a Background in <_.Source>' -ForEach $script:arrXamlDocD {
        [xml]$xml = $_.Text
        $arrBad = foreach ($objTrigger in @($xml.SelectNodes("//*[local-name()='Trigger'][@Property='IsSelected' or @Property='IsHighlighted' or @Property='IsMouseOver' or @Property='IsPressed']"))) {
            $objBackground = Get-SetterChild -Node $objTrigger -LeafPattern 'Background$' | Select-Object -First 1
            $objForeground = Get-SetterChild -Node $objTrigger -LeafPattern 'Foreground$' | Select-Object -First 1
            if ($objBackground -and -not $objForeground -and -not (Test-WhiteForegroundInScope $objBackground)) { '{0} trigger sets a Background and no Foreground' -f $objTrigger.GetAttribute('Property') }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'gives every list, combo box, tree and grid a selected state with white text on blue in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        $arrBad = @(Get-SelectedStateViolation -Text $_.Text -Source $_.Source)
        $arrBad | Should -BeNullOrEmpty
    }

    It 'finds the item controls of the main window and of the Options dialog' {
        $objMain = @($script:arrXamlDoc | Where-Object { $_.Source -eq 'MainWindow.xaml' })[0]
        [xml]$xml = $objMain.Text
        foreach ($strControl in 'DataGrid', 'TreeView') {
            @($xml.SelectNodes(("//*[local-name()='{0}']" -f $strControl))).Count | Should -BeGreaterThan 0 -Because $strControl
        }
        $objDialog = @($script:arrOwnXamlDoc | Where-Object { $_.Source -like 'start-installeranalysis.ps1 here-string*' })[0]
        [xml]$xmlDialog = $objDialog.Text
        @($xmlDialog.SelectNodes("//*[local-name()='ListBox']")).Count | Should -BeGreaterThan 0
    }

    It 'flags a combo box without the IsHighlighted state and a list without an item container style' {
        $strOpen = '<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">'
        $strSelected = '<Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Accent}"/><Setter Property="Foreground" Value="{DynamicResource MahApps.Brushes.IdealForeground}"/></Trigger>'
        $strHighlighted = '<Trigger Property="IsHighlighted" Value="True"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Accent}"/><Setter Property="Foreground" Value="{DynamicResource MahApps.Brushes.IdealForeground}"/></Trigger>'
        $strRow = '<Style x:Key="R" TargetType="DataGridRow"><Style.Triggers>' + $strSelected + '</Style.Triggers></Style><Style x:Key="G" TargetType="DataGrid"><Setter Property="RowStyle" Value="{StaticResource R}"/></Style>'
        $strCell = '<Style x:Key="C" TargetType="DataGridCell"><Style.Triggers>' + $strSelected + '</Style.Triggers></Style>'
        $strComboBad = '<Style x:Key="I" TargetType="ComboBoxItem"><Style.Triggers>' + $strSelected + '</Style.Triggers></Style>'
        $strComboGood = '<Style x:Key="I" TargetType="ComboBoxItem"><Style.Triggers>' + $strSelected + $strHighlighted + '</Style.Triggers></Style>'
        $strBox = '<ComboBox ItemContainerStyle="{StaticResource I}"/>'
        @(Get-SelectedStateViolation -Text ($strOpen + '<Grid.Resources>' + $strComboBad + '</Grid.Resources>' + $strBox + '</Grid>') -Source 's').Count | Should -Be 1
        @(Get-SelectedStateViolation -Text ($strOpen + '<Grid.Resources>' + $strComboGood + '</Grid.Resources>' + $strBox + '</Grid>') -Source 's').Count | Should -Be 0
        @(Get-SelectedStateViolation -Text ($strOpen + '<ListBox/></Grid>') -Source 's').Count | Should -Be 1
        @(Get-SelectedStateViolation -Text ($strOpen + '<Grid.Resources>' + $strRow + $strCell + '</Grid.Resources><DataGrid Style="{StaticResource G}" CellStyle="{StaticResource C}"/></Grid>') -Source 's').Count | Should -Be 0
        @(Get-SelectedStateViolation -Text ($strOpen + '<Grid.Resources>' + $strRow + '</Grid.Resources><DataGrid Style="{StaticResource G}"/></Grid>') -Source 's').Count | Should -Be 1
        @(Get-SelectedStateViolation -Text ($strOpen + '<TreeView/></Grid>') -Source 's').Count | Should -Be 1
    }

    It 'finds the sidebar buttons of the shell and lists each in the theme call' {
        $strShell = Get-Content -LiteralPath $script:strShellPath -Raw
        $arrThemed = New-Object System.Collections.Generic.HashSet[string]
        foreach ($objMatch in [regex]::Matches($strShell, 'Button\s*=\s*\$(btn\w+)')) { [void]$arrThemed.Add($objMatch.Groups[1].Value) }
        foreach ($objMatch in [regex]::Matches($strShell, '-OptionsButton\s+\$(btn\w+)')) { [void]$arrThemed.Add($objMatch.Groups[1].Value) }
        $objMain = @($script:arrXamlDoc | Where-Object { $_.Source -eq 'MainWindow.xaml' })[0]
        [xml]$xml = $objMain.Text
        $arrSidebar = @($xml.SelectNodes("//*[local-name()='Button'][contains(@Style,'ViewButtonStyle') or contains(@Style,'OptionsButtonStyle')]"))
        $arrSidebar.Count | Should -BeGreaterOrEqual 8
        $arrMissing = foreach ($objButton in $arrSidebar) {
            $strName = $objButton.GetAttribute('Name', $script:strXamlNamespace)
            if (-not $strName) { 'a sidebar button has no x:Name' } elseif (-not $arrThemed.Contains($strName)) { $strName }
        }
        @($arrMissing) | Should -BeNullOrEmpty
        $strShell | Should -Match '-ViewButtons\s+\$script:ViewButtons'
        ([regex]::Matches($strShell, 'Update-SidebarButtonTheme')).Count | Should -BeGreaterOrEqual 3
    }
}

Describe 'Theme helpers of SuiteCommon behave and are used (a, b)' {
    BeforeAll {
        # Set-ThemeForeground tests a type of WindowsBase. The test loads the assemblies itself, so it runs alone.
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
        $script:strSuitePath = Join-Path -Path $script:strRepoRoot -ChildPath 'Lib\SuiteCommon\SuiteCommon.psm1'
        $script:objSuiteAst = [System.Management.Automation.Language.Parser]::ParseFile($script:strSuitePath, [ref]$null, [ref]$null)
        function Get-SuiteFunction {
            param([string]$Name)
            $script:objSuiteAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
        }
        function Get-CommandCount {
            param($Ast, [string]$Name)
            @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $Name }, $true)).Count
        }
        . ([scriptblock]::Create((Get-SuiteFunction 'Set-ThemeForeground').Extent.Text))
    }

    It 'paints the light theme buttons of SuiteCommon with white text' {
        $strText = Remove-ScriptComment -Text (Get-Content -LiteralPath $script:strSuitePath -Raw)
        $strText | Should -Match "OnBlue\s*=\s*\`$bc\.ConvertFrom\('#FFFFFF'\)"
        foreach ($strName in 'Update-SidebarButtonTheme', 'Set-ButtonTheme') {
            $objFunction = Get-SuiteFunction $strName
            $objFunction | Should -Not -BeNullOrEmpty -Because $strName
            (Get-CommandCount $objFunction 'Set-ThemeForeground') | Should -BeGreaterThan 0 -Because ('{0} sets the foreground with each background' -f $strName)
            (Get-CommandCount $objFunction 'Set-ConnectionTextTheme') | Should -BeGreaterThan 0 -Because $strName
        }
    }

    It 'Set-ThemeForeground sets the on-blue brush in light mode and clears it in dark mode on a plain object' {
        $objControl = [pscustomobject]@{ Foreground = $null }
        Set-ThemeForeground -Control $objControl -IsDark $false -OnBlue 'White'
        $objControl.Foreground | Should -Be 'White'
        Set-ThemeForeground -Control $objControl -IsDark $true -OnBlue 'White'
        $objControl.Foreground | Should -BeNullOrEmpty
    }

    It 'Set-ThemeForeground clears a dependency object through ClearValue and takes a null control' {
        $objAst = Get-SuiteFunction 'Set-ThemeForeground'
        $objAst.Extent.Text | Should -Match 'ClearValue\(\[System\.Windows\.Controls\.Control\]::ForegroundProperty\)'
        { Set-ThemeForeground -Control $null -IsDark $false -OnBlue 'White' } | Should -Not -Throw
    }

    It 'Set-ThemeForeground paints a real Button white in light mode and gives the foreground back in dark mode' {
        $strFunction = (Get-SuiteFunction 'Set-ThemeForeground').Extent.Text
        $arrResult = Invoke-StaBlock -Argument @($strFunction) -Script {
            param($Function)
            Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
            . ([scriptblock]::Create($Function))
            $objButton = New-Object System.Windows.Controls.Button
            $objWhite = [System.Windows.Media.Brushes]::White
            $strUnset = [System.Windows.DependencyProperty]::UnsetValue
            Set-ThemeForeground -Control $objButton -IsDark $false -OnBlue $objWhite
            $boolLightWhite = [object]::ReferenceEquals($objButton.ReadLocalValue([System.Windows.Controls.Control]::ForegroundProperty), $objWhite)
            Set-ThemeForeground -Control $objButton -IsDark $true -OnBlue $objWhite
            $boolDarkCleared = [object]::ReferenceEquals($objButton.ReadLocalValue([System.Windows.Controls.Control]::ForegroundProperty), $strUnset)
            $boolLightWhite
            $boolDarkCleared
        }
        $arrResult.Count | Should -Be 2
        $arrResult[0] | Should -BeTrue -Because 'light mode sets the on-blue brush on the button'
        $arrResult[1] | Should -BeTrue -Because 'dark mode clears the local value, so the theme brush shows again'
    }

    It 'the script starts the theme and every dialog calls Set-DialogTheme' {
        $objShell = [System.Management.Automation.Language.Parser]::ParseFile($script:strShellPath, [ref]$null, [ref]$null)
        (Get-CommandCount $objShell 'Initialize-SuiteTheme') | Should -BeGreaterThan 0
        (Get-CommandCount $objShell 'Update-SidebarButtonTheme') | Should -BeGreaterThan 0
        $intDialog = @($script:arrXamlDoc | Where-Object { $_.Source -like 'start-installeranalysis*here-string*' }).Count
        $intDialog | Should -BeGreaterThan 0
        (Get-CommandCount $objShell 'Set-DialogTheme') | Should -BeGreaterOrEqual $intDialog
        (Get-SuiteFunction 'Set-DialogTheme') | Should -Not -BeNullOrEmpty
    }
}

Describe 'Fonts do not depend on the theme (b)' {
    It 'has no font property in a theme branch of <Name>' -ForEach $script:arrPsFileD {
        $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $arrAssign = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)
        $arrBad = foreach ($objAssign in $arrAssign) {
            $strMember = [string]$objAssign.Left.Member.Value
            if ($script:arrThemeProperty -notcontains $strMember) { continue }
            $objParent = $objAssign.Parent
            while ($objParent) {
                $strCondition = ''
                if ($objParent -is [System.Management.Automation.Language.IfStatementAst]) { $strCondition = (@($objParent.Clauses | ForEach-Object { $_.Item1.Extent.Text }) -join ' ') }
                elseif ($objParent -is [System.Management.Automation.Language.SwitchStatementAst]) { $strCondition = $objParent.Condition.Extent.Text }
                if ($strCondition -match '(?i)IsDark|DarkMode|Light|Theme|IsOn') { '{0}:{1} sets {2} in a theme branch' -f $Name, $objAssign.Extent.StartLineNumber, $strMember; break }
                $objParent = $objParent.Parent
            }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'sets no font property in the theme functions of SuiteCommon except the connection boxes' {
        $strPath = Join-Path -Path $script:strRepoRoot -ChildPath 'Lib\SuiteCommon\SuiteCommon.psm1'
        $objAst = [System.Management.Automation.Language.Parser]::ParseFile($strPath, [ref]$null, [ref]$null)
        foreach ($strName in 'Set-ThemeForeground', 'Update-SidebarButtonTheme', 'Set-ButtonTheme', 'Set-DialogTheme', 'Update-TitleBarBrushes', 'Initialize-SuiteTheme') {
            $objFunction = $objAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $strName }, $true)
            $objFunction | Should -Not -BeNullOrEmpty -Because $strName
            $objFunction.Extent.Text | Should -Not -Match '\.(FontSize|FontWeight|FontStyle|TextDecorations)\s*=' -Because $strName
        }
    }

    It 'makes the title of each connection box bold and 14 pt or larger, and leaves the value alone, the same way in both themes' {
        $strPath = Join-Path -Path $script:strRepoRoot -ChildPath 'Lib\SuiteCommon\SuiteCommon.psm1'
        $strText = Remove-ScriptComment -Text (Get-Content -LiteralPath $strPath -Raw)
        $strText | Should -Match 'FieldTitleFontSize\s*=\s*14'
        $objAst = [System.Management.Automation.Language.Parser]::ParseFile($strPath, [ref]$null, [ref]$null)
        $objFunction = $objAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Set-ConnectionTextTheme' }, $true)
        $objFunction | Should -Not -BeNullOrEmpty
        $strCode = Remove-ScriptComment -Text $objFunction.Extent.Text
        $strCode | Should -Match '\$title\.FontWeight\s*=\s*\[System\.Windows\.FontWeights\]::Bold'
        $strCode | Should -Not -Match '\$box\.(FontSize|FontWeight)\s*='
    }

    It 'uses no SemiBold or other weight than Bold for a title or label in the XAML of <_.Source>' -ForEach $script:arrOwnXamlDocD {
        $_.Text | Should -Not -Match 'FontWeight(=|" Value=)"(SemiBold|Light|Medium|Normal|Regular)"'
    }

    It 'sets every font weight in the script and in the module to Bold' -ForEach $script:arrAppPsFileD {
        @(Get-NonBoldWeight -Path $Path) | Should -BeNullOrEmpty
    }

    It 'flags a font weight that is not Bold' {
        $strTemp = Write-TempScript "`$a.FontWeight = [System.Windows.FontWeights]::SemiBold`n`$b.FontWeight = [System.Windows.FontWeights]::Bold`n"
        try { @(Get-NonBoldWeight -Path $strTemp).Count | Should -Be 1 }
        finally { Remove-Item -LiteralPath $strTemp -Force -ErrorAction SilentlyContinue }
    }

    It 'sets Bold on every heading of 14 pt or more in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        [xml]$xml = $_.Text
        $arrBad = foreach ($objText in @($xml.SelectNodes("//*[local-name()='TextBlock'][@FontSize]"))) {
            if ([double]$objText.GetAttribute('FontSize') -ge 14 -and $objText.GetAttribute('FontWeight') -ne 'Bold') { '{0} {1}' -f $objText.GetAttribute('Name', $script:strXamlNamespace), $objText.GetAttribute('Text') }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'uses no theme trigger on a font property in <_.Source>' -ForEach $script:arrXamlDocD {
        # A trigger on the selected tab or on the mouse is not a theme trigger. A trigger is a theme trigger when its own condition names the theme.
        [xml]$xml = $_.Text
        $arrBad = foreach ($objSetter in @($xml.SelectNodes("//*[local-name()='Setter']"))) {
            if ($script:arrThemeProperty -contains (Get-PropertyLeaf $objSetter.GetAttribute('Property'))) {
                $objParent = $objSetter.ParentNode
                if ($objParent.LocalName -match 'Trigger') {
                    $strCondition = '{0} {1} {2}' -f $objParent.GetAttribute('Property'), $objParent.GetAttribute('Binding'), $objParent.GetAttribute('Value')
                    if ($strCondition -match '(?i)theme|dark|light|IsDark') { $objParent.OuterXml.Substring(0, [Math]::Min(80, $objParent.OuterXml.Length)) }
                }
            }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'sets the title of a site code or SMS Provider box to bold 14 pt or more, and the value to normal weight and a size below 14 pt, in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        # This app has no connection box today. The rule applies when one is added.
        [xml]$xml = $_.Text
        foreach ($strName in 'txtSiteCode', 'txtSmsProvider', 'txtProvider', 'txtSiteServer') {
            $objElement = $xml.SelectSingleNode(("//*[@*[local-name()='Name']='{0}']" -f $strName))
            if (-not $objElement) { continue }
            $objTitle = $objElement.PreviousSibling
            while ($objTitle -and $objTitle.NodeType -ne 'Element') { $objTitle = $objTitle.PreviousSibling }
            $objTitle | Should -Not -BeNullOrEmpty -Because ('{0} has a title element before it' -f $strName)
            $objTitle.LocalName | Should -BeIn @('TextBlock', 'Label') -Because $strName
            [double]$objTitle.GetAttribute('FontSize') | Should -BeGreaterOrEqual 14 -Because ('the title of {0}' -f $strName)
            $objTitle.GetAttribute('FontWeight') | Should -Be 'Bold' -Because ('the title of {0}' -f $strName)
            $objElement.GetAttribute('FontWeight') | Should -Not -Be 'Bold' -Because ('the value of {0}' -f $strName)
            if ($objElement.GetAttribute('FontSize')) { [double]$objElement.GetAttribute('FontSize') | Should -BeLessThan 14 -Because ('the value of {0}' -f $strName) }
        }
    }

    It 'knows every connection box name of SuiteCommon' {
        $strText = Get-Content -LiteralPath (Join-Path -Path $script:strRepoRoot -ChildPath 'Lib\SuiteCommon\SuiteCommon.psm1') -Raw
        foreach ($strName in 'txtSiteCode', 'txtSmsProvider', 'txtProvider', 'txtSiteServer') { $strText | Should -Match $strName }
    }
}

Describe 'No banned word in the UI text and the documents (c)' {
    It 'finds the banned word <Word>' -ForEach @(@{ Word = 'simply' }, @{ Word = 'Helps you' }, @{ Word = 'streamlines' }, @{ Word = 'just' }, @{ Word = 'quickly' }) {
        $Word | Should -Match $script:strBannedPattern
    }

    It 'has no banned word in the XAML text of <_.Source>' -ForEach $script:arrXamlDocD {
        $arrBad = @(Get-XamlUiText -Text $_.Text | Where-Object { $_ -match $script:strBannedPattern })
        $arrBad | Should -BeNullOrEmpty
    }

    It 'has no banned word in the strings of <Name>' -ForEach $script:arrPsFileD {
        $arrBad = @(Get-ScriptString -Path $Path | Where-Object { $_ -match $script:strBannedPattern })
        $arrBad | Should -BeNullOrEmpty
    }

    It 'has no banned word in the README or the user guide' {
        $arrFile = @(Get-Item -LiteralPath (Join-Path -Path $script:strRepoRoot -ChildPath 'README.md')) + @(Get-ChildItem -LiteralPath (Join-Path -Path $script:strRepoRoot -ChildPath 'docs') -Filter '*.md' -File -Recurse)
        $arrFile.Count | Should -BeGreaterThan 10
        $arrBad = foreach ($objFile in $arrFile) {
            $intLine = 0
            foreach ($strLine in (Get-Content -LiteralPath $objFile.FullName)) {
                $intLine++
                if ($strLine -match $script:strBannedPattern) { '{0}:{1}: {2}' -f $objFile.Name, $intLine, $Matches[0] }
            }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'writes each tooltip as one short sentence in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        [xml]$xml = $_.Text
        $arrBad = foreach ($objElement in @($xml.SelectNodes('//*[@ToolTip]'))) {
            $strTip = $objElement.GetAttribute('ToolTip')
            if ($strTip -match '^\{') { continue }
            if ($strTip -cnotmatch '^[A-Z0-9].*\.$' -or $strTip -match '[.!?]\s+\S' -or $strTip.Length -gt 110) { $strTip }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'finds the tooltips of the main window' {
        $objMain = @($script:arrXamlDoc | Where-Object { $_.Source -eq 'MainWindow.xaml' })[0]
        [xml]$xml = $objMain.Text
        @($xml.SelectNodes('//*[@ToolTip]')).Count | Should -BeGreaterThan 15
    }

    It 'writes ConfigMgr and never MECM in the UI text and the documents' {
        $arrFile = @(Get-Item -LiteralPath (Join-Path -Path $script:strRepoRoot -ChildPath 'README.md')) + @(Get-ChildItem -LiteralPath (Join-Path -Path $script:strRepoRoot -ChildPath 'docs') -Filter '*.md' -File -Recurse)
        $arrBad = foreach ($objFile in $arrFile) { if ((Get-Content -LiteralPath $objFile.FullName -Raw) -cmatch '\bMECM\b') { $objFile.Name } }
        @($arrBad) | Should -BeNullOrEmpty
        $arrText = foreach ($objDoc in $script:arrOwnXamlDoc) { Get-XamlUiText -Text $objDoc.Text }
        @($arrText | Where-Object { $_ -cmatch '\bMECM\b' }) | Should -BeNullOrEmpty
    }
}

Describe 'Every button takes the shared themed style (d)' {
    It 'has no unthemed button and no literal button color in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        $arrBad = @(Get-ButtonThemeViolation -Text $_.Text -Source $_.Source)
        $arrBad | Should -BeNullOrEmpty
    }

    # The dialogs of SuiteCommon are vendored code. They are fixed in the suite repository (app-packager-suite), not here.
    # The test is skipped on purpose and shows in the result as Skipped with this reason.
    It 'SKIPPED until the suite repository fixes its dialogs: has no unthemed button in <_.Source>' -Skip -ForEach @($script:arrXamlDocD | Where-Object { $_.Source -match 'SuiteCommon' }) {
        $arrBad = @(Get-ButtonThemeViolation -Text $_.Text -Source $_.Source)
        $arrBad | Should -BeNullOrEmpty
    }

    It 'finds the buttons of the documents' {
        $intCount = 0
        foreach ($objDoc in $script:arrOwnXamlDoc) {
            [xml]$xml = $objDoc.Text
            $intCount += @($xml.SelectNodes("//*[local-name()='Button']")).Count
        }
        $intCount | Should -BeGreaterThan 15
    }

    It 'flags a button that has no style, a literal color and a style that is not shared' {
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Button x:Name=`"a`"/></Grid>" -Source 's').Count | Should -Be 1
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle<Style x:Key=`"S`" TargetType=`"Button`" BasedOn=`"{StaticResource ThemedButtonStyle}`"/></Grid.Resources><Button Style=`"{StaticResource S}`" Background=`"#1E1E1E`"/></Grid>" -Source 's').Count | Should -Be 1
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle<Style x:Key=`"S`" TargetType=`"Button`" BasedOn=`"{StaticResource MahApps.Styles.Button.Square.Accent}`"/></Grid.Resources><Button Style=`"{StaticResource S}`"/></Grid>" -Source 's').Count | Should -Be 2
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle<Style x:Key=`"S`" TargetType=`"Button`" BasedOn=`"{StaticResource ThemedButtonStyle}`"><Setter Property=`"Foreground`" Value=`"White`"/></Style></Grid.Resources><Button Style=`"{StaticResource S}`"/></Grid>" -Source 's').Count | Should -Be 1
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle<Style x:Key=`"S`" TargetType=`"Button`" BasedOn=`"{StaticResource ThemedButtonStyle}`"><Setter Property=`"Foreground`" Value=`"{DynamicResource MahApps.Brushes.ThemeForeground}`"/></Style></Grid.Resources><Button Style=`"{StaticResource S}`"/></Grid>" -Source 's').Count | Should -Be 0
    }

    It 'flags a named color and a color in a style or template of another control' {
        foreach ($strName in 'Orange', 'Silver', 'WhiteSmoke') {
            $strStyle = '<Style x:Key="T" TargetType="TextBlock"><Setter Property="Foreground" Value="' + $strName + '"/></Style>'
            @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle$strStyle</Grid.Resources></Grid>" -Source 's').Count | Should -Be 1 -Because $strName
        }
        $strTemplate = '<ControlTemplate TargetType="ListBoxItem"><Border Background="Silver"/></ControlTemplate>'
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle$strTemplate</Grid.Resources></Grid>" -Source 's').Count | Should -Be 1
        $strOk = '<Style x:Key="T" TargetType="TextBlock"><Setter Property="Foreground" Value="{DynamicResource MahApps.Brushes.Gray1}"/></Style>'
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle$strOk</Grid.Resources></Grid>" -Source 's').Count | Should -Be 0
    }

    It 'flags a literal color in a qualified brush property and in a nested brush of a button template' {
        $strStyle = '<Style x:Key="S" TargetType="Button" BasedOn="{StaticResource ThemedButtonStyle}"><Setter Property="Controls:ControlsHelper.MouseOverBorderBrush" Value="#3A3A3A"/></Style>'
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle$strStyle</Grid.Resources><Button Style=`"{StaticResource S}`"/></Grid>" -Source 's').Count | Should -Be 1
        $strNested = '<ControlTemplate TargetType="Button"><Border><Border.Background><SolidColorBrush Color="#3A3A3A"/></Border.Background></Border></ControlTemplate>'
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle$strNested</Grid.Resources></Grid>" -Source 's').Count | Should -Be 1
        $strSetter = '<Style x:Key="S" TargetType="Button" BasedOn="{StaticResource ThemedButtonStyle}"><Setter Property="Background"><Setter.Value><SolidColorBrush Color="#3A3A3A"/></Setter.Value></Setter></Style>'
        @(Get-ButtonThemeViolation -Text "<Grid $script:strNamespace><Grid.Resources>$script:strThemedStyle$strSetter</Grid.Resources><Button Style=`"{StaticResource S}`"/></Grid>" -Source 's').Count | Should -Be 1
    }

    It 'uses no Opacity in a button style or a button template of <_.Source>' -ForEach $script:arrOwnXamlDocD {
        @(Get-ButtonOpacityViolation -Text $_.Text -Source $_.Source) | Should -BeNullOrEmpty
    }

    It 'flags an Opacity setter in a button trigger and an Opacity attribute in a button template' {
        $strTrigger = '<ControlTemplate TargetType="Button"><Border Name="Bd"/><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.8"/></Trigger></ControlTemplate.Triggers></ControlTemplate>'
        @(Get-ButtonOpacityViolation -Text "<Grid $script:strNamespace><Grid.Resources>$strTrigger</Grid.Resources></Grid>" -Source 's').Count | Should -Be 1
        $strAttribute = '<ControlTemplate TargetType="Button"><Border Name="Bd" Opacity="0.5"/></ControlTemplate>'
        @(Get-ButtonOpacityViolation -Text "<Grid $script:strNamespace><Grid.Resources>$strAttribute</Grid.Resources></Grid>" -Source 's').Count | Should -Be 1
        $strStyle = '<Style x:Key="S" TargetType="Button"><Style.Triggers><Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger></Style.Triggers></Style>'
        @(Get-ButtonOpacityViolation -Text "<Grid $script:strNamespace><Grid.Resources>$strStyle</Grid.Resources></Grid>" -Source 's').Count | Should -Be 1
        $strOk = '<Style x:Key="S" TargetType="Button"><Setter Property="Foreground" Value="{DynamicResource MahApps.Brushes.ThemeForeground}"/></Style><Style TargetType="Border"><Setter Property="Opacity" Value="0.5"/></Style>'
        @(Get-ButtonOpacityViolation -Text "<Grid $script:strNamespace><Grid.Resources>$strOk</Grid.Resources></Grid>" -Source 's').Count | Should -Be 0
    }

    It 'shows hover and focus as the theme foreground border and pressed as swapped theme colors in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        @(Get-ButtonStateViolation -Text $_.Text -Source $_.Source) | Should -BeNullOrEmpty
    }

    It 'flags a button template without the hover, focus or pressed rule' {
        $strHover = '<Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource MahApps.Brushes.ThemeForeground}"/></Trigger>'
        $strFocus = '<Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource MahApps.Brushes.ThemeForeground}"/></Trigger>'
        $strPressed = '<Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Background" Value="{DynamicResource MahApps.Brushes.ThemeForeground}"/><Setter TargetName="Cp" Property="TextElement.Foreground" Value="{DynamicResource MahApps.Brushes.ThemeBackground}"/></Trigger>'
        $strOpen = "<Grid $script:strNamespace><Grid.Resources><ControlTemplate x:Key=`"ThemedButtonTemplate`" TargetType=`"Button`"><Border Name=`"Bd`"/><ControlTemplate.Triggers>"
        $strClose = '</ControlTemplate.Triggers></ControlTemplate></Grid.Resources></Grid>'
        @(Get-ButtonStateViolation -Text ($strOpen + $strHover + $strFocus + $strPressed + $strClose) -Source 's').Count | Should -Be 0
        @(Get-ButtonStateViolation -Text ($strOpen + $strFocus + $strPressed + $strClose) -Source 's').Count | Should -Be 1
        @(Get-ButtonStateViolation -Text ($strOpen + $strHover + $strPressed + $strClose) -Source 's').Count | Should -Be 1
        @(Get-ButtonStateViolation -Text ($strOpen + $strHover + $strFocus + $strClose) -Source 's').Count | Should -Be 2
        @(Get-ButtonStateViolation -Text "<Grid $script:strNamespace/>" -Source 's').Count | Should -Be 1
    }

    It 'has one gray secondary style and one primary style in the dialog, documented, of one size, and no other button style that sets a Background in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        @(Get-DialogButtonViolation -Text $_.Text -Source $_.Source) | Should -BeNullOrEmpty
    }

    It 'defines the dialog button styles in exactly one document, with the Cancel button of that dialog' {
        $arrDoc = @($script:arrOwnXamlDoc | Where-Object { $_.Text -match 'x:Key="DialogButton"' })
        $arrDoc.Count | Should -Be 1
        $arrDoc[0].Text | Should -Match 'x:Key="DialogAccentButton"'
        @($script:arrOwnXamlDoc | Where-Object { $_.Text -match 'x:Key="DialogAccentButton"' }).Count | Should -Be 1
        [xml]$xml = $arrDoc[0].Text
        $objCancel = $xml.SelectSingleNode("//*[local-name()='Button'][@*[local-name()='Name']='btnCancel']")
        $objCancel | Should -Not -BeNullOrEmpty
        $objCancel.GetAttribute('Style') | Should -Be '{StaticResource DialogButton}'
    }

    It 'flags a dialog button that sets its own size and a dialog button that the script sizes in code' {
        $strBase = '<Style x:Key="ThemedButtonStyle" TargetType="Button" BasedOn="{StaticResource MahApps.Styles.Button.Square}"/>'
        $strSecondary = '<Style x:Key="DialogButton" TargetType="Button" BasedOn="{StaticResource ThemedButtonStyle}"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Gray10}"/><Setter Property="MinWidth" Value="140"/><Setter Property="Height" Value="32"/></Style>'
        $strPrimary = '<Style x:Key="DialogAccentButton" TargetType="Button" BasedOn="{StaticResource ThemedButtonStyle}"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Highlight}"/><Setter Property="MinWidth" Value="140"/><Setter Property="Height" Value="32"/></Style>'
        $strOpen = "<Grid $script:strNamespace><Grid.Resources>" + $strBase + '<!-- The one secondary dialog style. -->' + $strSecondary + $strPrimary + '</Grid.Resources>'
        @(Get-DialogButtonViolation -Text ($strOpen + '<Button Style="{StaticResource DialogButton}"/></Grid>') -Source 's').Count | Should -Be 0
        foreach ($strAttribute in 'Width="200"', 'MinWidth="90"', 'Height="28"', 'Padding="12,0"') {
            @(Get-DialogButtonViolation -Text ($strOpen + '<Button Style="{StaticResource DialogButton}" ' + $strAttribute + '/></Grid>') -Source 's').Count | Should -Be 1 -Because $strAttribute
        }
        $strTemp = Write-TempScript "function A {`n  `$b = New-Object System.Windows.Controls.Button`n  `$b.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'DialogButton')`n  `$b.Padding = [System.Windows.Thickness]::new(12,0,12,0)`n  `$b.MinWidth = 140`n}`n"
        try { @(Get-CodeButtonViolation -Path $strTemp -AllowedKey @('DialogButton')).Count | Should -Be 2 }
        finally { Remove-Item -LiteralPath $strTemp -Force -ErrorAction SilentlyContinue }
    }

    It 'flags a second secondary style, a size that differs, a missing comment and a literal color in the dialog styles' {
        $strBase = '<Style x:Key="ThemedButtonStyle" TargetType="Button" BasedOn="{StaticResource MahApps.Styles.Button.Square}"/>'
        $strSecondary = '<Style x:Key="DialogButton" TargetType="Button" BasedOn="{StaticResource ThemedButtonStyle}"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Gray10}"/><Setter Property="MinWidth" Value="90"/><Setter Property="Height" Value="32"/></Style>'
        $strPrimary = '<Style x:Key="DialogAccentButton" TargetType="Button" BasedOn="{StaticResource ThemedButtonStyle}"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Highlight}"/><Setter Property="MinWidth" Value="90"/><Setter Property="Height" Value="32"/></Style>'
        $strComment = '<!-- The one secondary dialog style. -->'
        $strOpen = "<Grid $script:strNamespace><Grid.Resources>"
        $strClose = '</Grid.Resources><Button x:Name="btnCancel" IsCancel="True" Style="{StaticResource DialogButton}"/></Grid>'
        @(Get-DialogButtonViolation -Text ($strOpen + $strBase + $strComment + $strSecondary + $strPrimary + $strClose) -Source 's').Count | Should -Be 0
        $strCopy = '<Style x:Key="BrowseButton" TargetType="Button" BasedOn="{StaticResource ThemedButtonStyle}"><Setter Property="Background" Value="{DynamicResource MahApps.Brushes.Gray10}"/></Style>'
        @(Get-DialogButtonViolation -Text ($strOpen + $strBase + $strComment + $strSecondary + $strPrimary + $strCopy + $strClose) -Source 's').Count | Should -Be 1
        @(Get-DialogButtonViolation -Text ($strOpen + $strBase + $strComment + $strSecondary.Replace('Value="32"', 'Value="28"') + $strPrimary + $strClose) -Source 's').Count | Should -Be 1
        @(Get-DialogButtonViolation -Text ($strOpen + $strBase + $strComment + $strSecondary.Replace('Value="90"', 'Value="80"') + $strPrimary + $strClose) -Source 's').Count | Should -Be 1
        @(Get-DialogButtonViolation -Text ($strOpen + $strBase + $strSecondary + $strPrimary + $strClose) -Source 's').Count | Should -Be 1
        @(Get-DialogButtonViolation -Text ($strOpen + $strBase + $strComment + $strSecondary.Replace('{DynamicResource MahApps.Brushes.Gray10}', '#EEEEEE') + $strPrimary + $strClose) -Source 's').Count | Should -Be 1
        @(Get-DialogButtonViolation -Text ($strOpen + $strBase + $strComment + $strSecondary + $strPrimary + $strClose.Replace('DialogButton', 'ThemedButtonStyle')) -Source 's').Count | Should -Be 1
    }

    It 'gives every button that the script builds in code one of the themed styles, and no literal color' -ForEach $script:arrAppPsFileD {
        @(Get-CodeButtonViolation -Path $Path -AllowedKey @('DialogButton', 'DialogAccentButton', 'BreadcrumbButtonStyle', 'ThemedButtonStyle')) | Should -BeNullOrEmpty
    }

    It 'builds the buttons of the Options panels with DialogButton and the breadcrumb buttons with BreadcrumbButtonStyle' {
        $objAst = [System.Management.Automation.Language.Parser]::ParseFile($script:strShellPath, [ref]$null, [ref]$null)
        $hashExpected = @{ 'New-PathPickerPanel' = 'DialogButton'; 'New-LoggingPanel' = 'DialogButton'; 'Update-BreadcrumbBar' = 'BreadcrumbButtonStyle' }
        foreach ($strFunction in $hashExpected.Keys) {
            $objFunction = $objAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $strFunction }, $true)
            $objFunction | Should -Not -BeNullOrEmpty -Because $strFunction
            $objFunction.Extent.Text | Should -Match ("New-Object System\.Windows\.Controls\.Button") -Because $strFunction
            $objFunction.Extent.Text | Should -Match ("SetResourceReference\(\[System\.Windows\.Controls\.Button\]::StyleProperty, '{0}'\)" -f $hashExpected[$strFunction]) -Because $strFunction
        }
        $arrKey = foreach ($objDoc in $script:arrOwnXamlDoc) { [xml]$xml = $objDoc.Text; foreach ($objStyle in @($xml.SelectNodes("//*[local-name()='Style'][@TargetType='Button']"))) { $objStyle.GetAttribute('Key', $script:strXamlNamespace) } }
        $arrKey | Should -Contain 'DialogButton'
        $arrKey | Should -Contain 'BreadcrumbButtonStyle'
    }

    It 'flags a button that the script builds without a themed style and a button with a literal color' {
        $strTemp = Write-TempScript ("function A {`n  `$b = New-Object System.Windows.Controls.Button`n  `$b.Content = 'x'`n}`nfunction B {`n  `$b = New-Object System.Windows.Controls.Button`n  `$b.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'MahApps.Styles.Button.Square')`n}`n" +
            "function C {`n  `$b = New-Object System.Windows.Controls.Button`n  `$b.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'DialogButton')`n  `$b.Foreground = 'White'`n  `$b.FontWeight = [System.Windows.FontWeights]::SemiBold`n}`n" +
            "function D {`n  `$b = New-Object System.Windows.Controls.Button`n  `$b.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'DialogButton')`n  `$b.FontWeight = [System.Windows.FontWeights]::Bold`n}`n")
        try { @(Get-CodeButtonViolation -Path $strTemp -AllowedKey @('DialogButton')).Count | Should -Be 4 }
        finally { Remove-Item -LiteralPath $strTemp -Force -ErrorAction SilentlyContinue }
    }

    It 'defines the button template and the button style once in each document and no per-dialog button style besides them' {
        foreach ($objDoc in $script:arrOwnXamlDoc) {
            [xml]$xml = $objDoc.Text
            @($xml.SelectNodes("//*[local-name()='Style'][@*[local-name()='Key']='ThemedButtonStyle']")).Count | Should -Be 1 -Because $objDoc.Source
            @($xml.SelectNodes("//*[local-name()='ControlTemplate'][@*[local-name()='Key']='ThemedButtonTemplate']")).Count | Should -Be 1 -Because $objDoc.Source
            @($xml.SelectNodes("//*[local-name()='ControlTemplate'][@TargetType='Button' or @TargetType='ButtonBase']")).Count | Should -Be 1 -Because $objDoc.Source
        }
    }

    It 'uses the same button template and the same button style in every document' {
        $arrTemplate = foreach ($objDoc in $script:arrOwnXamlDoc) {
            [xml]$xml = $objDoc.Text
            $objNode = $xml.SelectSingleNode("//*[local-name()='ControlTemplate'][@*[local-name()='Key']='ThemedButtonTemplate']")
            ($objNode.InnerXml -replace '\s+', ' ')
        }
        @($arrTemplate | Sort-Object -Unique).Count | Should -Be 1
        $arrStyle = foreach ($objDoc in $script:arrOwnXamlDoc) {
            [xml]$xml = $objDoc.Text
            $objNode = $xml.SelectSingleNode("//*[local-name()='Style'][@*[local-name()='Key']='ThemedButtonStyle']")
            ($objNode.InnerXml -replace '\s+', ' ')
        }
        @($arrStyle | Sort-Object -Unique).Count | Should -Be 1
    }

    It 'themes the buttons of the window in both themes through SuiteCommon' {
        $strShell = Get-Content -LiteralPath $script:strShellPath -Raw
        $strShell | Should -Match '-ViewButtons\s+\$script:ViewButtons'
        $strShell | Should -Match '-OptionsButton\s+\$btnOptions'
        ([regex]::Matches($strShell, 'Update-SidebarButtonTheme')).Count | Should -BeGreaterOrEqual 3
    }
}

Describe 'Titles are in Title Case (d)' {
    It 'recognizes Title Case' {
        Test-TitleCase 'Copy Summary' | Should -BeTrue
        Test-TitleCase 'Open in New Window' | Should -BeTrue
        Test-TitleCase 'Extract to Temp Folder' | Should -BeTrue
        Test-TitleCase 'Browse...' | Should -BeTrue
        Test-TitleCase 'Export JSON' | Should -BeTrue
        Test-TitleCase 'Hash This Entry (SHA-256)' | Should -BeTrue
        Test-TitleCase ([string][char]0x2190 + ' Back') | Should -BeTrue
        Test-TitleCase ([string][char]0x2190 + ' back') | Should -BeFalse
        Test-TitleCase 'Copy summary' | Should -BeFalse
        Test-TitleCase 'Open in new window' | Should -BeFalse
        Test-TitleCase 'LOG output' | Should -BeFalse
        Test-TitleCase 'enable Actions' | Should -BeFalse
    }

    It 'has Title Case for every button, header, tab, menu item, field label and window title in <_.Source>' -ForEach $script:arrOwnXamlDocD {
        $arrBad = @(Get-XamlTitle -Text $_.Text | Where-Object { -not (Test-TitleCase $_) })
        $arrBad | Should -BeNullOrEmpty
    }

    It 'finds titles to check in the main window' {
        $objMain = @($script:arrXamlDoc | Where-Object { $_.Source -eq 'MainWindow.xaml' })[0]
        @(Get-XamlTitle -Text $objMain.Text).Count | Should -BeGreaterThan 40
    }

    It 'has Title Case in the title of every message box, confirmation, panel heading and panel name of the script' {
        $objAst = [System.Management.Automation.Language.Parser]::ParseFile($script:strShellPath, [ref]$null, [ref]$null)
        $arrCall = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in 'Show-ThemedMessage', 'Show-ConfirmDialog', 'New-OptionsSection', 'New-PathPickerPanel' }, $true)
        @($arrCall).Count | Should -BeGreaterThan 3
        $arrBad = foreach ($objCall in $arrCall) {
            $arrElement = @($objCall.CommandElements)
            for ($intIndex = 0; $intIndex -lt $arrElement.Count - 1; $intIndex++) {
                if ($arrElement[$intIndex] -is [System.Management.Automation.Language.CommandParameterAst] -and $arrElement[$intIndex].ParameterName -in 'Title', 'Heading', 'Name' -and $arrElement[$intIndex + 1] -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $strTitle = [string]$arrElement[$intIndex + 1].Value
                    if (-not (Test-TitleCase $strTitle)) { $strTitle }
                }
            }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'has Title Case in the progress titles of the script' {
        $objAst = [System.Management.Automation.Language.Parser]::ParseFile($script:strShellPath, [ref]$null, [ref]$null)
        $arrAssign = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$txtProgressTitle.Text' -and $n.Right.Extent.Text -match "^'[^']*'$" }, $true)
        @($arrAssign).Count | Should -BeGreaterThan 1
        $arrBad = foreach ($objAssign in $arrAssign) {
            $strTitle = $objAssign.Right.Extent.Text.Trim("'")
            if (-not (Test-TitleCase $strTitle)) { $strTitle }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }
}

Describe 'No raw exception text in the window (e)' {
    It 'finds the UI calls of the script' {
        $objAst = [System.Management.Automation.Language.Parser]::ParseFile($script:strShellPath, [ref]$null, [ref]$null)
        @($objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in 'Add-LogLine', 'Set-StatusText', 'Show-ThemedMessage' }, $true)).Count | Should -BeGreaterThan 50
    }

    It 'shows no exception text in a log line, the status text or a message box of start-installeranalysis.ps1' {
        $arrBad = @(Get-UiExceptionText -Path $script:strShellPath)
        $arrBad | Should -BeNullOrEmpty
    }

    It 'writes exception text only to the log file (-Quiet) in start-installeranalysis.ps1' {
        $objAst = [System.Management.Automation.Language.Parser]::ParseFile($script:strShellPath, [ref]$null, [ref]$null)
        $arrCall = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Write-Log' }, $true)
        @($arrCall).Count | Should -BeGreaterThan 5
        $arrBad = foreach ($objCall in $arrCall) {
            $strText = $objCall.Extent.Text
            if ($strText -match '\$_|Exception\.Message|ErrorMsg|DetailMsg|\$err\b' -and $strText -notmatch '-Quiet') { '{0}: {1}' -f $objCall.Extent.StartLineNumber, $strText }
        }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'puts no exception text in a property that the window shows, in <Name>' -ForEach $script:arrAppPsFileD {
        @(Get-ExceptionPropertyAssignment -Path $Path) | Should -BeNullOrEmpty
    }

    It 'flags exception text in a UI call' {
        $strTemp = Write-TempScript "try { 1 } catch { Add-LogLine (`$_.Exception.Message) }`ntry { 1 } catch { Show-ThemedMessage -Message `$script:State.ErrorMsg }`nAdd-LogLine 'The step failed.'`n"
        try {
            @(Get-UiExceptionText -Path $strTemp).Count | Should -Be 2
            [System.IO.File]::WriteAllText($strTemp, "`$txtStatus.Text = `$state.ErrorMessage`n`$txtLog.Text = `$r.Detail`n`$txtLog.Text = `$e.Error`n`$txtLog.Text = 'Ready.'`nSet-StatusText `$r.Detail`nSet-StatusText `$s.DetailMsg`n")
            @(Get-UiExceptionText -Path $strTemp).Count | Should -Be 5
        }
        finally { Remove-Item -LiteralPath $strTemp -Force -ErrorAction SilentlyContinue }
    }

    It 'flags exception text in a Note, a Message or a Text property and in a hashtable entry' {
        $strTemp = Write-TempScript "`$r.Note = 'Could not read: ' + `$_.Exception.Message`n`$r.Message = `$_`n`$r.Detail = `$err`n`$x = @{ Note = 'x ' + `$_.Exception.Message }`n`$r.Note = 'The log file has the details.'`n`$State.ErrorMsg = `$_.Exception.Message`n"
        try { @(Get-ExceptionPropertyAssignment -Path $strTemp).Count | Should -Be 4 }
        finally { Remove-Item -LiteralPath $strTemp -Force -ErrorAction SilentlyContinue }
    }

    It 'shows a fixed note and keeps the exception text in the log file for the notes of the module' {
        $strModule = Get-Content -LiteralPath $script:strModulePath -Raw
        foreach ($strNote in 'Velopack metadata unavailable. The log file has the details.', 'Setup entry lists could not be decoded. The log file has the details.', 'Registry tables could not be read. The log file has the details.') {
            $strModule | Should -Match ([regex]::Escape($strNote))
        }
        $strModule | Should -Not -Match "Note = '[^']*' \+ \`$_\.Exception"
    }
}

Describe 'Every test file requires Pester 5.1.0 (g)' {
    It 'finds the test files' {
        @(Get-RepoFile -Filter '*.Tests.ps1').Count | Should -BeGreaterThan 15
        @(Get-RepoFile -Filter '*.Tests.ps1' | Where-Object { $_.Relative -like 'Module\*' }).Count | Should -BeGreaterThan 0
    }

    It 'has #Requires for Pester ModuleVersion 5.1.0 in every test file' {
        $arrBad = foreach ($objItem in @(Get-RepoFile -Filter '*.Tests.ps1')) { Get-PesterRequiresViolation -Path $objItem.File.FullName }
        @($arrBad) | Should -BeNullOrEmpty
    }

    It 'flags a test file without the requirement, with an old version or with the module name only' {
        foreach ($hashCase in @(@{ Text = "Describe 'x' {}"; Count = 1 }, @{ Text = "#Requires -Modules Pester`nDescribe 'x' {}"; Count = 1 }, @{ Text = "#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }`nDescribe 'x' {}"; Count = 1 }, @{ Text = "#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }`nDescribe 'x' {}"; Count = 0 })) {
            $strTemp = Write-TempScript $hashCase.Text
            try { @(Get-PesterRequiresViolation -Path $strTemp).Count | Should -Be $hashCase.Count -Because $hashCase.Text }
            finally { Remove-Item -LiteralPath $strTemp -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Path filters of the repository scripts work on the repository root (f)' {
    It 'has no FullName comparison with a path pattern in <_>' -ForEach @(
        'Invoke-Checks.ps1', 'Tests\WindowGuard.Tests.ps1', 'Tests\Theme.Guard.Tests.ps1', 'Tests\ThemeGuardHelpers.ps1', 'Tests\Release.Tests.ps1',
        'Tests\Documentation.Tests.ps1', 'Tests\TestHelpers.ps1', 'Tests\WindowConfig.ps1', 'tools\guide-capture\Invoke-GuideCapture.ps1', 'tools\guide-capture\steps-guide.ps1'
    ) {
        $strPath = Join-Path -Path $script:strRepoRoot -ChildPath $_
        Test-Path -LiteralPath $strPath | Should -BeTrue -Because $_
        @(Get-AbsolutePathFilter -Path $strPath) | Should -BeNullOrEmpty
    }

    It 'flags a FullName comparison with a path pattern' {
        $strTemp = Write-TempScript "Get-ChildItem | Where-Object { `$_.FullName -notlike '*\.git\*' }`nGet-ChildItem | Where-Object { `$_.FullName -match '\\Tests\\' }`nGet-ChildItem | Where-Object { `$_.FullName -ne `$x -and `$_.Name -like '*.ps1' }`n"
        try { @(Get-AbsolutePathFilter -Path $strTemp).Count | Should -Be 2 }
        finally { Remove-Item -LiteralPath $strTemp -Force -ErrorAction SilentlyContinue }
    }

    It 'walks no .claude folder in Invoke-Checks.ps1 and in the window guard test' {
        foreach ($strName in 'Invoke-Checks.ps1', 'Tests\WindowGuard.Tests.ps1') {
            $strPath = Join-Path -Path $script:strRepoRoot -ChildPath $strName
            $objAst = [System.Management.Automation.Language.Parser]::ParseFile($strPath, [ref]$null, [ref]$null)
            $arrString = @($objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -eq '.claude' }, $true))
            $arrString.Count | Should -BeGreaterThan 0 -Because $strName
        }
    }

    It 'skips the .claude folder in the repository file walk of the guard helpers' {
        $arrRoot = @(Get-RepoFile -Filter '*.ps1' | ForEach-Object { $_.Top } | Sort-Object -Unique)
        $arrRoot | Should -Not -Contain '.claude'
        $arrRoot | Should -Not -Contain '.git'
        @(Get-RepoFile -Filter '*.xaml').Count | Should -BeGreaterThan 0
    }
}
