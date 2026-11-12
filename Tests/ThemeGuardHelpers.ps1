# Helpers of Theme.Guard.Tests.ps1. Dot-source from BeforeDiscovery and from BeforeAll.
# The helpers parse files. They create no WPF control, so they run on Windows PowerShell 5.1 and PowerShell 7.

$script:strRepoRoot = Split-Path -Path $PSScriptRoot -Parent
$script:arrThemeProperty = @('FontSize', 'FontWeight', 'FontStyle', 'TextDecorations', 'FontFamily', 'FontStretch')
$script:strBannedPattern = '(?i)\b(easily|simply|seamless(ly)?|powerful|robust|streamline[sd]?|streamlining|quickly|just|effortless(ly)?|intuitive(ly)?|handy|helps you|allows you to)\b'
$script:strXamlNamespace = 'http://schemas.microsoft.com/winfx/2006/xaml'

# The leaf of a property name: Border.Background, Controls:ControlsHelper.MouseOverBorderBrush and Background give the last word.
function Get-PropertyLeaf {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return '' }
    return ($Name -split '[.:]')[-1]
}

# True when a brush value names an accent or a blue color.
function Test-BlueBrush {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -match 'MahApps\.(Brushes|Colors)\.(Accent\d*|AccentBase|Highlight\d*|Button\.Flat\.Background\.Pressed)\b') { return $true }
    if ($Value -match 'SystemColors\.Highlight(Brush|Color)Key') { return $true }
    if ($Value -match '(?i)^\s*(blue|dodgerblue|royalblue|steelblue|navy|mediumblue|darkblue|cornflowerblue|deepskyblue|lightskyblue|skyblue)\s*$') { return $true }
    $strHex = $Value.Trim()
    if ($strHex -match '^#([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])$') { $strHex = '#{0}{0}{1}{1}{2}{2}' -f $Matches[1], $Matches[2], $Matches[3] }
    if ($strHex -match '^#(?:[0-9A-Fa-f]{2})?([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})$') {
        $dblRed = [Convert]::ToInt32($Matches[1], 16) / 255.0
        $dblGreen = [Convert]::ToInt32($Matches[2], 16) / 255.0
        $dblBlue = [Convert]::ToInt32($Matches[3], 16) / 255.0
        $dblMax = [Math]::Max($dblRed, [Math]::Max($dblGreen, $dblBlue))
        $dblMin = [Math]::Min($dblRed, [Math]::Min($dblGreen, $dblBlue))
        $dblDelta = $dblMax - $dblMin
        if ($dblDelta -lt 0.2 -or $dblMax -eq 0) { return $false }
        if ($dblMax -ne $dblBlue) { return $false }
        $dblHue = 60.0 * (4.0 + (($dblRed - $dblGreen) / $dblDelta))
        return ($dblHue -ge 190 -and $dblHue -le 260)
    }
    return $false
}

function Test-WhiteBrush {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -match '(?i)^\s*(white|#FFFFFF|#FFFFFFFF|#FFF)\s*$' -or $Value -match 'MahApps\.Brushes\.(Ideal|ThemeIdeal)Foreground')
}

# The value of a Setter: the Value attribute, or the Color attribute of a nested brush element at any depth.
function Get-SetterValue {
    param($Setter)
    if ($Setter.HasAttribute('Value')) { return $Setter.GetAttribute('Value') }
    $objNode = $Setter.SelectSingleNode('.//*[@Color]')
    if ($objNode) { return $objNode.GetAttribute('Color') }
    return ''
}

# The direct Setter children of a node whose property leaf matches a pattern.
function Get-SetterChild {
    param($Node, [string]$LeafPattern)
    if (-not $Node) { return @() }
    return @($Node.ChildNodes | Where-Object { $_.LocalName -eq 'Setter' -and (Get-PropertyLeaf $_.GetAttribute('Property')) -match $LeafPattern })
}

# The files of the repository below a folder, with the path relative to the repository root. The filter works on the
# relative path, so a worktree below .claude does not exclude itself.
function Get-RepoFile {
    param([string]$Filter, [string[]]$Skip = @('.claude', '.git', 'TestOutput', 'Logs', 'Reports'))
    $strRoot = $script:strRepoRoot.TrimEnd('\')
    # The top level is read first, so that a skipped folder (.claude holds worktrees) is never walked.
    foreach ($objTop in @(Get-ChildItem -LiteralPath $strRoot -Force)) {
        if ($Skip -contains $objTop.Name) { continue }
        $arrFile = @()
        if ($objTop.PSIsContainer) { $arrFile = @(Get-ChildItem -LiteralPath $objTop.FullName -Filter $Filter -File -Recurse) }
        elseif ($objTop.Name -like $Filter) { $arrFile = @($objTop) }
        foreach ($objFile in $arrFile) {
            $strRelative = $objFile.FullName.Substring($strRoot.Length + 1)
            [PSCustomObject]@{ File = $objFile; Relative = $strRelative; Top = ($strRelative -split '\\')[0] }
        }
    }
}

# Every XAML document of the repository: the XAML files and the XAML here-strings of the scripts.
function Get-XamlDocument {
    $arrDoc = @()
    foreach ($objItem in @(Get-RepoFile -Filter '*.xaml')) {
        $arrDoc += [PSCustomObject]@{ Source = $objItem.File.Name; Text = (Get-Content -LiteralPath $objItem.File.FullName -Raw) }
    }
    foreach ($strFilter in '*.ps1', '*.psm1') {
        foreach ($objItem in @(Get-RepoFile -Filter $strFilter -Skip @('.claude', '.git', 'Tests', 'tools', 'TestOutput', 'Logs', 'Reports'))) {
            $strRaw = Get-Content -LiteralPath $objItem.File.FullName -Raw
            $intIndex = 0
            foreach ($objMatch in [regex]::Matches($strRaw, "(?s)@'\r?\n(\s*<[^\r\n]*Window.*?)\r?\n'@")) {
                $intIndex++
                $arrDoc += [PSCustomObject]@{ Source = ('{0} here-string {1}' -f $objItem.File.Name, $intIndex); Text = $objMatch.Groups[1].Value }
            }
        }
    }
    return $arrDoc
}

# Resolves {StaticResource Key} to the key.
function Get-ResourceKey {
    param([string]$Value)
    if ($Value -match '^\{(?:Static|Dynamic)Resource\s+([^}\s]+)\}$') { return $Matches[1] }
    return ''
}

# A Foreground setter of the same scope is white: a sibling Setter, or a Setter of the enclosing Style.
function Test-WhiteForegroundInScope {
    param($Setter)
    $arrScope = @($Setter.ParentNode)
    $objStyle = $Setter.ParentNode
    while ($objStyle -and $objStyle.LocalName -ne 'Style' -and $objStyle.LocalName -ne 'ControlTemplate') { $objStyle = $objStyle.ParentNode }
    if ($objStyle) { $arrScope += $objStyle }
    foreach ($objScope in $arrScope) {
        foreach ($objForeground in @(Get-SetterChild -Node $objScope -LeafPattern 'Foreground$')) {
            if (Test-WhiteBrush (Get-SetterValue $objForeground)) { return $true }
        }
    }
    return $false
}

# Returns one text per blue-background rule that has no white foreground. It reads Setter nodes of styles, templates and
# triggers (also with a qualified property such as Border.Background or Controls:ControlsHelper.MouseOverBackground and with a nested brush
# whose Color attribute is at any depth), attributes of elements, and property elements such as <Border.Background>.
function Get-BlueWithoutWhite {
    param([string]$Text, [string]$Source)
    [xml]$xml = $Text
    $listFound = New-Object System.Collections.Generic.List[string]
    $strContainer = '^(Border|Grid|StackPanel|DockPanel|WrapPanel|Canvas|UniformGrid)$'
    foreach ($objElement in @($xml.SelectNodes('//*'))) {
        if ($objElement.LocalName -eq 'Setter') {
            if ((Get-PropertyLeaf $objElement.GetAttribute('Property')) -match 'Background$') {
                $strValue = Get-SetterValue $objElement
                if ((Test-BlueBrush $strValue) -and -not (Test-WhiteForegroundInScope $objElement)) {
                    [void]$listFound.Add(('{0}: Setter {1} {2} in <{3}> has no white Foreground' -f $Source, $objElement.GetAttribute('Property'), $strValue, $objElement.ParentNode.LocalName))
                }
            }
            continue
        }
        if ($objElement.LocalName -match '\.\w*Background$') {
            $objBrush = $objElement.SelectSingleNode('.//*[@Color]')
            if ($objBrush -and (Test-BlueBrush $objBrush.GetAttribute('Color')) -and $objElement.ParentNode -and -not (Test-WhiteBrush $objElement.ParentNode.GetAttribute('Foreground'))) {
                [void]$listFound.Add(('{0}: <{1}> has a blue brush and its owner has no white Foreground' -f $Source, $objElement.LocalName))
            }
            continue
        }
        foreach ($objAttribute in @($objElement.Attributes | Where-Object { (Get-PropertyLeaf $_.Name) -match 'Background$' })) {
            if (-not (Test-BlueBrush $objAttribute.Value)) { continue }
            $strOwnForeground = ''
            foreach ($objForeground in @($objElement.Attributes | Where-Object { (Get-PropertyLeaf $_.Name) -match 'Foreground$' })) {
                if (Test-WhiteBrush $objForeground.Value) { $strOwnForeground = $objForeground.Value }
            }
            if ($strOwnForeground) { continue }
            # A container has no Foreground. Its text elements must carry the white foreground themselves.
            if ($objElement.LocalName -match $strContainer) {
                $arrText = @($objElement.SelectNodes(".//*[local-name()='TextBlock' or local-name()='Label' or local-name()='ContentPresenter']"))
                $boolAllWhite = ($arrText.Count -gt 0)
                foreach ($objText in $arrText) { if (-not (Test-WhiteBrush $objText.GetAttribute('Foreground'))) { $boolAllWhite = $false } }
                if ($boolAllWhite) { continue }
            }
            [void]$listFound.Add(('{0}: <{1}> {2} {3} has no white Foreground' -f $Source, $objElement.LocalName, $objAttribute.Name, $objAttribute.Value))
        }
    }
    return $listFound.ToArray()
}

# Returns the text of a script without comment lines and block comments, so that a match cannot come from a comment.
function Remove-ScriptComment {
    param([string]$Text)
    $strText = [regex]::Replace($Text, '(?s)<#.*?#>', '')
    return (($strText -split "\r?\n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n")
}

# Every string of a script: the constant strings and the text parts of expandable strings.
function Get-ScriptString {
    param([string]$Path)
    $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $arrNode = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)
    foreach ($objNode in $arrNode) { [string]$objNode.Value }
}

# The text a user can read in a XAML document: tooltips and text attributes.
function Get-XamlUiText {
    param([string]$Text)
    [xml]$xml = $Text
    foreach ($objElement in @($xml.SelectNodes('//*'))) {
        foreach ($objAttribute in @($objElement.Attributes)) {
            if ($objAttribute.LocalName -match '^(ToolTip|Text|Content|Header|Title|Watermark|OnContent|OffContent|ToolTipService.*)$' -or $objAttribute.Name -match 'Watermark$') {
                if ($objAttribute.Value -notmatch '^\{') { $objAttribute.Value }
            }
        }
    }
}

# Returns one text per assignment of a blue string literal to a Background property in a script.
function Get-ScriptBlueBackground {
    param([string]$Path)
    $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $arrAssign = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)
    foreach ($objAssign in $arrAssign) {
        if ([string]$objAssign.Left.Member.Value -ne 'Background') { continue }
        # A white or ideal foreground set on the same control in the same block makes the blue background safe.
        $strTarget = $objAssign.Left.Expression.Extent.Text
        $arrSibling = @()
        if ($objAssign.Parent.PSObject.Properties['Statements']) { $arrSibling = @($objAssign.Parent.Statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left -is [System.Management.Automation.Language.MemberExpressionAst] }) }
        $arrWhite = @($arrSibling | Where-Object { [string]$_.Left.Member.Value -eq 'Foreground' -and $_.Left.Expression.Extent.Text -eq $strTarget -and $_.Right.Extent.Text -match '(?i)IdealForeground|White|#FFFFFF' })
        if ($arrWhite.Count -gt 0) { continue }
        $arrString = $objAssign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
        foreach ($objString in $arrString) {
            if (Test-BlueBrush ([string]$objString.Value)) { '{0}:{1}: Background {2}' -f (Split-Path -Leaf $Path), $objAssign.Extent.StartLineNumber, $objString.Value }
        }
    }
}

# Returns one text per style that is based on a MahApps accent button and has no white foreground.
function Get-AccentButtonWithoutWhite {
    param([string]$Text, [string]$Source)
    [xml]$xml = $Text
    $listFound = New-Object System.Collections.Generic.List[string]
    foreach ($objStyle in @($xml.SelectNodes("//*[local-name()='Style']"))) {
        if ($objStyle.GetAttribute('BasedOn') -notmatch 'Button\.(Square\.|Flat\.)?Accent') { continue }
        $objForeground = Get-SetterChild -Node $objStyle -LeafPattern '^Foreground$' | Select-Object -First 1
        if (-not $objForeground -or -not (Test-WhiteBrush (Get-SetterValue $objForeground))) {
            [void]$listFound.Add(('{0}: accent button style {1} has no white Foreground' -f $Source, $objStyle.GetAttribute('Key', $script:strXamlNamespace)))
        }
    }
    return $listFound.ToArray()
}

# True when a style node has a trigger on the property (IsSelected, IsHighlighted) that sets a blue Background and a white Foreground.
function Test-StateTrigger {
    param($Style, [string]$Property)
    foreach ($objTrigger in @($Style.SelectNodes(".//*[local-name()='Trigger'][@Property='$Property']"))) {
        $objBackground = Get-SetterChild -Node $objTrigger -LeafPattern '^Background$' | Select-Object -First 1
        $objForeground = Get-SetterChild -Node $objTrigger -LeafPattern '^Foreground$' | Select-Object -First 1
        if ($objBackground -and (Test-BlueBrush (Get-SetterValue $objBackground)) -and $objForeground -and (Test-WhiteBrush (Get-SetterValue $objForeground))) { return $true }
    }
    return $false
}

# Returns one text per list, combo box, tree, grid row or grid cell without a selected-state style. Each item control of a
# document takes an explicit item container style (a base style is not enough, MahApps sets its own); the style has a
# blue background with a white foreground for IsSelected, and for a combo box item also for IsHighlighted.
function Get-SelectedStateViolation {
    param([string]$Text, [string]$Source)
    [xml]$xml = $Text
    $listFound = New-Object System.Collections.Generic.List[string]
    $hashStyle = @{}
    foreach ($objStyle in @($xml.SelectNodes("//*[local-name()='Style'][@*[local-name()='Key']]"))) { $hashStyle[$objStyle.GetAttribute('Key', $script:strXamlNamespace)] = $objStyle }
    $hashRule = @(
        @{ Control = 'ListBox'; Attribute = 'ItemContainerStyle'; Item = 'ListBoxItem'; Property = @('IsSelected') }
        @{ Control = 'ListView'; Attribute = 'ItemContainerStyle'; Item = 'ListViewItem'; Property = @('IsSelected') }
        @{ Control = 'ComboBox'; Attribute = 'ItemContainerStyle'; Item = 'ComboBoxItem'; Property = @('IsSelected', 'IsHighlighted') }
        @{ Control = 'TreeView'; Attribute = 'ItemContainerStyle'; Item = 'TreeViewItem'; Property = @('IsSelected') }
        @{ Control = 'DataGrid'; Attribute = 'CellStyle'; Item = 'DataGridCell'; Property = @('IsSelected') }
    )
    foreach ($hashControl in $hashRule) {
        foreach ($objElement in @($xml.SelectNodes(("//*[local-name()='{0}']" -f $hashControl.Control)))) {
            $strName = $objElement.GetAttribute('Name', $script:strXamlNamespace)
            $strKey = Get-ResourceKey $objElement.GetAttribute($hashControl.Attribute)
            if (-not $strKey -or -not $hashStyle.ContainsKey($strKey)) {
                [void]$listFound.Add(('{0}: {1} {2} has no {3}' -f $Source, $hashControl.Control, $strName, $hashControl.Attribute))
                continue
            }
            foreach ($strProperty in $hashControl.Property) {
                if (-not (Test-StateTrigger -Style $hashStyle[$strKey] -Property $strProperty)) {
                    [void]$listFound.Add(('{0}: style {1} of {2} {3} has no blue Background with white Foreground for {4}' -f $Source, $strKey, $hashControl.Control, $strName, $strProperty))
                }
            }
        }
    }
    foreach ($objElement in @($xml.SelectNodes("//*[local-name()='DataGrid']"))) {
        $strName = $objElement.GetAttribute('Name', $script:strXamlNamespace)
        $strGridStyle = Get-ResourceKey $objElement.GetAttribute('Style')
        $objRowStyle = $null
        if ($strGridStyle -and $hashStyle.ContainsKey($strGridStyle)) {
            $objRowSetter = Get-SetterChild -Node $hashStyle[$strGridStyle] -LeafPattern '^RowStyle$' | Select-Object -First 1
            if ($objRowSetter) { $strRowKey = Get-ResourceKey $objRowSetter.GetAttribute('Value'); if ($strRowKey -and $hashStyle.ContainsKey($strRowKey)) { $objRowStyle = $hashStyle[$strRowKey] } }
        }
        if (-not $objRowStyle -or -not (Test-StateTrigger -Style $objRowStyle -Property 'IsSelected')) {
            [void]$listFound.Add(('{0}: DataGrid {1} has no row style with a blue Background and a white Foreground for IsSelected' -f $Source, $strName))
        }
    }
    return $listFound.ToArray()
}

# Returns one text per button problem in a XAML document. Every Button has a Style whose chain of BasedOn
# styles ends at ThemedButtonStyle. ThemedButtonStyle is the only button style that is based on MahApps directly.
# No button, button style or button template has a literal color. Qualified properties and the Color attribute of a nested
# brush at any depth count.
function Get-ButtonThemeViolation {
    param([string]$Text, [string]$Source)
    [xml]$xml = $Text
    $listFound = New-Object System.Collections.Generic.List[string]
    # A literal color is a hex value or any bare alphabetic value (White, Orange, Silver, WhiteSmoke). A value in braces is a resource.
    $scriptIsLiteral = { param($v) ($v -match '^\s*#[0-9A-Fa-f]{3,8}\s*$') -or ($v -match '^\s*[A-Za-z]+\s*$') }
    $hashStyle = @{}
    foreach ($objStyle in @($xml.SelectNodes("//*[local-name()='Style'][@TargetType='Button']"))) { $hashStyle[$objStyle.GetAttribute('Key', $script:strXamlNamespace)] = $objStyle.GetAttribute('BasedOn') }
    $scriptResolve = {
        param($key)
        $hashSeen = @{}
        while ($key -and -not $hashSeen.ContainsKey($key)) {
            if ($key -eq 'ThemedButtonStyle') { return $true }
            $hashSeen[$key] = $true
            if (-not $hashStyle.ContainsKey($key)) { return $false }
            $key = Get-ResourceKey $hashStyle[$key]
        }
        return $false
    }
    foreach ($strKey in @($hashStyle.Keys)) {
        if ($strKey -ne 'ThemedButtonStyle' -and $hashStyle[$strKey] -match 'MahApps\.') { [void]$listFound.Add(('{0}: Button style {1} is based on MahApps and not on ThemedButtonStyle' -f $Source, $strKey)) }
    }
    foreach ($objButton in @($xml.SelectNodes("//*[local-name()='Button']"))) {
        $strName = $objButton.GetAttribute('Name', $script:strXamlNamespace)
        $strKey = Get-ResourceKey $objButton.GetAttribute('Style')
        if (-not $strKey -or -not (& $scriptResolve $strKey)) {
            [void]$listFound.Add(('{0}: Button {1} does not take ThemedButtonStyle' -f $Source, $strName))
        }
        foreach ($objAttribute in @($objButton.Attributes)) {
            if ((Get-PropertyLeaf $objAttribute.Name) -match '(Background|Foreground|Brush)$' -and (& $scriptIsLiteral $objAttribute.Value)) { [void]$listFound.Add(('{0}: Button {1} sets {2} to the literal {3}' -f $Source, $strName, $objAttribute.Name, $objAttribute.Value)) }
        }
    }
    # Every Style and every ControlTemplate of the document, not only those of a button.
    $arrScope = @($xml.SelectNodes("//*[local-name()='Style']")) + @($xml.SelectNodes("//*[local-name()='ControlTemplate']"))
    foreach ($objScope in $arrScope) {
        $strKey = $objScope.GetAttribute('Key', $script:strXamlNamespace)
        foreach ($objNode in @($objScope.SelectNodes('descendant-or-self::*'))) {
            foreach ($objAttribute in @($objNode.Attributes)) {
                $strLeaf = Get-PropertyLeaf $objAttribute.Name
                if ($strLeaf -eq 'Value') {
                    if ((Get-PropertyLeaf $objNode.GetAttribute('Property')) -notmatch '(Background|Foreground|Brush)$') { continue }
                }
                elseif ($strLeaf -notmatch '^(Color|Fill|Stroke)$' -and $strLeaf -notmatch '(Background|Foreground|Brush)$') { continue }
                if (& $scriptIsLiteral $objAttribute.Value) { [void]$listFound.Add(('{0}: {1} {2} uses the literal color {3}' -f $Source, $objScope.LocalName, $strKey, $objAttribute.Value)) }
            }
        }
    }
    return $listFound.ToArray()
}

# True when a UI title is in Title Case: each word starts with a capital letter or a digit, except the small words in the
# middle. A word of capitals (JSON) and a word with a dot (sms01.example.com) pass. The text may end with dots.
function Test-TitleCase {
    param([string]$Text)
    $strClean = ($Text -replace '\.\.\.$', '').Trim()
    if ([string]::IsNullOrWhiteSpace($strClean)) { return $true }
    $arrSmall = @('a', 'an', 'the', 'and', 'or', 'of', 'to', 'in', 'on', 'for', 'per', 'by', 'at', 'as', 'but', 'nor', 'with', 'from')
    $arrWord = @($strClean -split '\s+')
    for ($intIndex = 0; $intIndex -lt $arrWord.Count; $intIndex++) {
        $strWord = $arrWord[$intIndex].Trim(',', ':', '(', ')')
        # A word with no letter and no digit (an arrow, a bullet, a dash) is a symbol and has no case.
        if (-not $strWord -or $strWord -cnotmatch '[A-Za-z0-9]') { continue }
        $boolEdge = ($intIndex -eq 0 -or $intIndex -eq $arrWord.Count - 1)
        if (-not $boolEdge -and ($arrSmall -contains $strWord)) { continue }
        if ($strWord -cnotmatch '^[A-Z0-9#<\[\(]') { return $false }
    }
    return $true
}

# The titles of a XAML document that must be in Title Case: button content, tab and column headers, field labels, window
# titles, check box, radio button and switch text. A binding or a name with a dot stays out.
function Get-XamlTitle {
    param([string]$Text)
    [xml]$xml = $Text
    foreach ($objElement in @($xml.SelectNodes('//*'))) {
        $strName = $objElement.LocalName
        $strValue = ''
        if ($strName -in 'Button', 'CheckBox', 'RadioButton', 'ToggleButton') { $strValue = $objElement.GetAttribute('Content') }
        elseif ($strName -in 'MenuItem', 'TabItem', 'GroupBox', 'Expander') { $strValue = $objElement.GetAttribute('Header') }
        elseif ($strName -in 'DataGridTextColumn', 'DataGridCheckBoxColumn', 'DataGridTemplateColumn') { $strValue = $objElement.GetAttribute('Header') }
        elseif ($strName -eq 'ToggleSwitch') { $strValue = $objElement.GetAttribute('Header') }
        elseif ($strName -eq 'MetroWindow' -or $strName -eq 'Window') { $strValue = $objElement.GetAttribute('Title') }
        elseif ($strName -eq 'TextBlock' -and ($objElement.GetAttribute('Style') -match 'FieldLabelStyle|OptLabel' -or $objElement.ParentNode.LocalName -eq 'TabItem.Header')) { $strValue = $objElement.GetAttribute('Text') }
        if ($strValue -and $strValue -notmatch '^\{' -and $strValue -notmatch '^(On|Off)$') { $strValue }
    }
}

# Returns one text per call of a UI command (a log line, the status text, a message box, a confirmation) that carries the
# text of an exception: $_, an Exception property, an error message variable.
function Get-UiExceptionText {
    param([string]$Path, [string[]]$Command = @('Add-LogLine', 'Set-StatusText', 'Show-ThemedMessage', 'Show-ConfirmDialog'))
    $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $strPattern = '\$_(?![\w])|\$PSItem|Exception|ErrorMsg|ErrorMessage|DetailMsg|\.Error\b|\.Detail\b|\$err\b|\$ex\b'
    $arrCall = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $Command -contains $n.GetCommandName() }, $true)
    foreach ($objCall in $arrCall) {
        if ($objCall.Extent.Text -match $strPattern) { '{0}:{1}: {2}' -f (Split-Path -Leaf $Path), $objCall.Extent.StartLineNumber, $objCall.Extent.Text }
    }
    # An assignment to the Text property of a control is a UI write too.
    $arrAssign = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and [string]$n.Left.Member.Value -eq 'Text' }, $true)
    foreach ($objAssign in $arrAssign) {
        if ($objAssign.Right.Extent.Text -match $strPattern) { '{0}:{1}: {2}' -f (Split-Path -Leaf $Path), $objAssign.Extent.StartLineNumber, $objAssign.Extent.Text }
    }
}

# Returns one text per Opacity setter or Opacity attribute in a Button style or a Button template. A hover, pressed or
# disabled state that fades the button with Opacity lowers the text contrast below the limit. The states use the theme
# foreground and the theme background instead.
function Get-ButtonOpacityViolation {
    param([string]$Text, [string]$Source)
    [xml]$xml = $Text
    $listFound = New-Object System.Collections.Generic.List[string]
    $arrScope = @($xml.SelectNodes("//*[local-name()='Style'][@TargetType='Button' or @TargetType='ButtonBase']")) + @($xml.SelectNodes("//*[local-name()='ControlTemplate'][@TargetType='Button' or @TargetType='ButtonBase']"))
    foreach ($objScope in $arrScope) {
        $strKey = $objScope.GetAttribute('Key', $script:strXamlNamespace)
        foreach ($objNode in @($objScope.SelectNodes('descendant-or-self::*'))) {
            if ($objNode.LocalName -eq 'Setter') {
                if ((Get-PropertyLeaf $objNode.GetAttribute('Property')) -eq 'Opacity') { [void]$listFound.Add(('{0}: {1} {2} sets Opacity' -f $Source, $objScope.LocalName, $strKey)) }
            }
            elseif ($objNode.HasAttribute('Opacity')) { [void]$listFound.Add(('{0}: {1} {2} has an Opacity attribute on <{3}>' -f $Source, $objScope.LocalName, $strKey, $objNode.LocalName)) }
        }
    }
    return $listFound.ToArray()
}

# True when a template trigger on the property sets the named template part to a theme resource.
function Test-TemplateTriggerSetter {
    param($Template, [string]$Trigger, [string]$Target, [string]$Property, [string]$Value)
    foreach ($objTrigger in @($Template.SelectNodes(".//*[local-name()='Trigger'][@Property='$Trigger']"))) {
        foreach ($objSetter in @($objTrigger.ChildNodes | Where-Object { $_.LocalName -eq 'Setter' })) {
            if ($objSetter.GetAttribute('TargetName') -eq $Target -and $objSetter.GetAttribute('Property') -eq $Property -and $objSetter.GetAttribute('Value') -eq $Value) { return $true }
        }
    }
    return $false
}

# Returns one text per rule of the button template that a document breaks: the hover and the keyboard focus show the theme
# foreground as the border color, a pressed button swaps the theme foreground and the theme background.
function Get-ButtonStateViolation {
    param([string]$Text, [string]$Source)
    [xml]$xml = $Text
    $listFound = New-Object System.Collections.Generic.List[string]
    $objTemplate = $xml.SelectSingleNode("//*[local-name()='ControlTemplate'][@*[local-name()='Key']='ThemedButtonTemplate']")
    if (-not $objTemplate) { return @(('{0}: no ThemedButtonTemplate' -f $Source)) }
    $strForeground = '{DynamicResource MahApps.Brushes.ThemeForeground}'
    $strBackground = '{DynamicResource MahApps.Brushes.ThemeBackground}'
    if (-not (Test-TemplateTriggerSetter -Template $objTemplate -Trigger 'IsMouseOver' -Target 'Bd' -Property 'BorderBrush' -Value $strForeground)) { [void]$listFound.Add(('{0}: hover does not set the border to the theme foreground' -f $Source)) }
    if (-not (Test-TemplateTriggerSetter -Template $objTemplate -Trigger 'IsKeyboardFocused' -Target 'Bd' -Property 'BorderBrush' -Value $strForeground)) { [void]$listFound.Add(('{0}: keyboard focus does not set the border to the theme foreground' -f $Source)) }
    if (-not (Test-TemplateTriggerSetter -Template $objTemplate -Trigger 'IsPressed' -Target 'Bd' -Property 'Background' -Value $strForeground)) { [void]$listFound.Add(('{0}: pressed does not set the background to the theme foreground' -f $Source)) }
    if (-not (Test-TemplateTriggerSetter -Template $objTemplate -Trigger 'IsPressed' -Target 'Cp' -Property 'TextElement.Foreground' -Value $strBackground)) { [void]$listFound.Add(('{0}: pressed does not set the text to the theme background' -f $Source)) }
    return $listFound.ToArray()
}

# True when a node is a XML comment that is the previous element sibling of the style (whitespace is skipped).
function Test-DocumentedByComment {
    param($Node, [string]$Pattern)
    $objPrevious = $Node.PreviousSibling
    while ($objPrevious -and $objPrevious.NodeType -in 'Whitespace', 'SignificantWhitespace') { $objPrevious = $objPrevious.PreviousSibling }
    return ($objPrevious -and $objPrevious.NodeType -eq 'Comment' -and $objPrevious.Value -match $Pattern)
}

# Returns one text per break of the dialog button rule in one document. The dialog has ONE secondary style (DialogButton:
# gray fill, documented by a comment) and ONE primary style (DialogAccentButton). They have the same Height and MinWidth.
# No other button style sets a Background. A button that is a Cancel button takes DialogButton. The values of the secondary
# style are theme resources. The cross-document rule (defined once) is checked by the caller.
function Get-DialogButtonViolation {
    param([string]$Text, [string]$Source)
    [xml]$xml = $Text
    $listFound = New-Object System.Collections.Generic.List[string]
    $arrAllowed = @('DialogAccentButton', 'DialogButton')
    $hashStyle = @{}
    foreach ($objStyle in @($xml.SelectNodes("//*[local-name()='Style'][@TargetType='Button']"))) {
        $strKey = $objStyle.GetAttribute('Key', $script:strXamlNamespace)
        $hashStyle[$strKey] = $objStyle
        if (@(Get-SetterChild -Node $objStyle -LeafPattern '^Background$').Count -gt 0 -and $arrAllowed -notcontains $strKey) {
            [void]$listFound.Add(('{0}: button style {1} sets a Background and is not a dialog button style' -f $Source, $strKey))
        }
    }
    if (-not ($hashStyle.ContainsKey('DialogButton') -or $hashStyle.ContainsKey('DialogAccentButton'))) { return $listFound.ToArray() }
    foreach ($strKey in $arrAllowed) {
        if (-not $hashStyle.ContainsKey($strKey)) { [void]$listFound.Add(('{0}: style {1} is missing' -f $Source, $strKey)); continue }
        if ($hashStyle[$strKey].GetAttribute('BasedOn') -ne '{StaticResource ThemedButtonStyle}') { [void]$listFound.Add(('{0}: style {1} is not based on ThemedButtonStyle' -f $Source, $strKey)) }
    }
    if (-not ($hashStyle.ContainsKey('DialogButton') -and $hashStyle.ContainsKey('DialogAccentButton'))) { return $listFound.ToArray() }
    if (-not (Test-DocumentedByComment -Node $hashStyle['DialogButton'] -Pattern '(?i)secondary')) { [void]$listFound.Add(('{0}: style DialogButton has no comment that documents it as the secondary style' -f $Source)) }
    foreach ($strProperty in 'Height', 'MinWidth') {
        $arrValue = foreach ($strKey in $arrAllowed) {
            $objSetter = Get-SetterChild -Node $hashStyle[$strKey] -LeafPattern ('^{0}$' -f $strProperty) | Select-Object -First 1
            if ($objSetter) { $objSetter.GetAttribute('Value') } else { '' }
        }
        if (@($arrValue | Where-Object { -not $_ }).Count -gt 0 -or @($arrValue | Sort-Object -Unique).Count -ne 1) { [void]$listFound.Add(('{0}: the dialog button styles do not have the same {1}' -f $Source, $strProperty)) }
    }
    foreach ($objSetter in @(Get-SetterChild -Node $hashStyle['DialogButton'] -LeafPattern '(Background|Foreground|Brush)$')) {
        if ($objSetter.GetAttribute('Value') -notmatch '^\{DynamicResource MahApps\.Brushes\.') { [void]$listFound.Add(('{0}: DialogButton sets {1} to a value that is not a theme resource' -f $Source, $objSetter.GetAttribute('Property'))) }
    }
    # A dialog button takes its size from the style only: no own size, padding or font size.
    foreach ($objButton in @($xml.SelectNodes("//*[local-name()='Button']"))) {
        if ($arrAllowed -notcontains (Get-ResourceKey $objButton.GetAttribute('Style'))) { continue }
        foreach ($strAttribute in 'Width', 'MinWidth', 'MaxWidth', 'Height', 'MinHeight', 'MaxHeight', 'Padding', 'FontSize') {
            if ($objButton.HasAttribute($strAttribute)) { [void]$listFound.Add(('{0}: dialog button {1} sets {2} itself' -f $Source, $objButton.GetAttribute('Name', $script:strXamlNamespace), $strAttribute)) }
        }
    }
    foreach ($objButton in @($xml.SelectNodes("//*[local-name()='Button'][@IsCancel='True']"))) {
        if ((Get-ResourceKey $objButton.GetAttribute('Style')) -ne 'DialogButton') { [void]$listFound.Add(('{0}: Cancel button {1} does not take DialogButton' -f $Source, $objButton.GetAttribute('Name', $script:strXamlNamespace))) }
    }
    return $listFound.ToArray()
}

# Returns one text per Button that a script builds in code and does not theme: it takes the style from one of the allowed
# style keys with SetResourceReference in the same function, it sets no literal Foreground, Background or BorderBrush, and
# it sets no font weight other than Bold.
function Get-CodeButtonViolation {
    param([string]$Path, [string[]]$AllowedKey)
    $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $arrCreate = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.Right.Extent.Text -match 'New-Object\s+(-TypeName\s+)?System\.Windows\.Controls\.Button\b' }, $true)
    foreach ($objCreate in $arrCreate) {
        $strVariable = $objCreate.Left.VariablePath.UserPath
        $objScope = $objCreate.Parent
        while ($objScope -and $objScope -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $objScope = $objScope.Parent }
        if (-not $objScope) { $objScope = $objAst }
        $arrStyle = $objScope.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Value -eq 'SetResourceReference' -and $n.Expression.Extent.Text -eq ('$' + $strVariable) -and $n.Arguments.Count -eq 2 -and $n.Arguments[0].Extent.Text -match 'StyleProperty' }, $true)
        $boolThemed = $false
        foreach ($objStyle in $arrStyle) {
            if ($objStyle.Arguments[1] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $AllowedKey -contains [string]$objStyle.Arguments[1].Value) { $boolThemed = $true }
        }
        if (-not $boolThemed) { '{0}:{1}: Button ${2} does not take one of the themed styles {3}' -f (Split-Path -Leaf $Path), $objCreate.Extent.StartLineNumber, $strVariable, ($AllowedKey -join ', ') }
        $arrSet = $objScope.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Left.Expression.Extent.Text -eq ('$' + $strVariable) }, $true)
        foreach ($objSet in $arrSet) {
            $strMember = [string]$objSet.Left.Member.Value
            if ($strMember -in 'Background', 'Foreground', 'BorderBrush') { '{0}:{1}: Button ${2} sets {3} in code' -f (Split-Path -Leaf $Path), $objSet.Extent.StartLineNumber, $strVariable, $strMember }
            if ($strMember -in 'Width', 'MinWidth', 'MaxWidth', 'Height', 'MinHeight', 'MaxHeight', 'Padding' -and @($AllowedKey | Where-Object { $_ -like 'Dialog*' }).Count -gt 0 -and @($arrStyle | Where-Object { $_.Arguments[1].Extent.Text -match "^'Dialog" }).Count -gt 0) { '{0}:{1}: dialog button ${2} sets {3} in code' -f (Split-Path -Leaf $Path), $objSet.Extent.StartLineNumber, $strVariable, $strMember }
            if ($strMember -eq 'FontWeight' -and $objSet.Right.Extent.Text -notmatch 'FontWeights\]::Bold\b') { '{0}:{1}: Button ${2} sets a font weight other than Bold' -f (Split-Path -Leaf $Path), $objSet.Extent.StartLineNumber, $strVariable }
        }
    }
}

# Returns one text per font weight assignment in a script that is not Bold.
function Get-NonBoldWeight {
    param([string]$Path)
    $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $arrAssign = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and [string]$n.Left.Member.Value -eq 'FontWeight' }, $true)
    foreach ($objAssign in $arrAssign) {
        if ($objAssign.Right.Extent.Text -notmatch 'FontWeights\]::Bold\b') { '{0}:{1}: {2}' -f (Split-Path -Leaf $Path), $objAssign.Extent.StartLineNumber, $objAssign.Extent.Text }
    }
}

# Returns one text per property assignment or hashtable entry whose name is one that a window shows (Note, Message, Text,
# Status, Summary) and whose value carries the text of an exception. The hand-off to a log call (ErrorMsg, DetailMsg) is not
# in the list, because only the log file shows it.
function Get-ExceptionPropertyAssignment {
    param([string]$Path, [string[]]$Member = @('Note', 'Message', 'Text', 'Status', 'Summary', 'ErrorMessage', 'Error', 'Detail'))
    $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $strPattern = '\$_(?![\w])|\$PSItem|\.Exception\b|\$err\b|\$ex\b|\bErrorMsg\b|\bDetailMsg\b'
    $arrAssign = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and $Member -contains [string]$n.Left.Member.Value }, $true)
    foreach ($objAssign in $arrAssign) {
        if ($objAssign.Right.Extent.Text -match $strPattern) { '{0}:{1}: {2}' -f (Split-Path -Leaf $Path), $objAssign.Extent.StartLineNumber, $objAssign.Extent.Text }
    }
    $arrTable = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
    foreach ($objTable in $arrTable) {
        foreach ($objPair in $objTable.KeyValuePairs) {
            if ($Member -contains [string]$objPair.Item1.Extent.Text -and $objPair.Item2.Extent.Text -match $strPattern) { '{0}:{1}: {2} = {3}' -f (Split-Path -Leaf $Path), $objPair.Item1.Extent.StartLineNumber, $objPair.Item1.Extent.Text, $objPair.Item2.Extent.Text }
        }
    }
}

# Returns one text per comparison of a FullName with an absolute-style wildcard or pattern, such as -notlike '*\.git\*'.
# Such a filter matches the repository folder itself and the worktrees below .claude. A path filter works on the path
# relative to the repository root.
function Get-AbsolutePathFilter {
    param([string]$Path)
    $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $arrCompare = $objAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator -in 'Like', 'NotLike', 'Match', 'NotMatch', 'Clike', 'Cnotlike', 'Cmatch', 'Cnotmatch', 'Ilike', 'Inotlike', 'Imatch', 'Inotmatch' -and $n.Left.Extent.Text -match 'FullName\s*$' }, $true)
    foreach ($objCompare in $arrCompare) {
        if ($objCompare.Right -is [System.Management.Automation.Language.StringConstantExpressionAst] -and ([string]$objCompare.Right.Value) -match '\\|/') { '{0}:{1}: {2}' -f (Split-Path -Leaf $Path), $objCompare.Extent.StartLineNumber, $objCompare.Extent.Text }
    }
}

# Runs a script block in a new single-threaded apartment runspace and returns its output. A WPF control needs an STA thread.
# No window is created.
function Invoke-StaBlock {
    param([scriptblock]$Script, [object[]]$Argument = @())
    $objRunspace = [runspacefactory]::CreateRunspace()
    $objRunspace.ApartmentState = [System.Threading.ApartmentState]::STA
    $objRunspace.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $objRunspace.Open()
    $objShell = $null
    try {
        $objShell = [powershell]::Create()
        $objShell.Runspace = $objRunspace
        [void]$objShell.AddScript($Script.ToString())
        foreach ($objArgument in $Argument) { [void]$objShell.AddArgument($objArgument) }
        $arrOutput = @($objShell.Invoke())
        if ($objShell.HadErrors) { throw (($objShell.Streams.Error | Select-Object -First 1).ToString()) }
        return $arrOutput
    }
    finally {
        if ($objShell) { $objShell.Dispose() }
        $objRunspace.Dispose()
    }
}

# Returns one text per element outside a Style and a ControlTemplate that sets a literal color (a hex value or a bare color
# name) as Foreground, Background, BorderBrush, Fill or Stroke, and one text per element that has an Opacity attribute and a
# blue Background (a faded blue box lowers the contrast of its text). Values in braces are resources.
function Get-ElementColorViolation {
    param([string]$Text, [string]$Source)
    [xml]$xml = $Text
    $listFound = New-Object System.Collections.Generic.List[string]
    foreach ($objElement in @($xml.SelectNodes('//*'))) {
        $boolInside = $false
        $objParent = $objElement
        while ($objParent -and $objParent.NodeType -eq 'Element') {
            if ($objParent.LocalName -in 'Style', 'ControlTemplate', 'DataTemplate') { $boolInside = $true; break }
            $objParent = $objParent.ParentNode
        }
        if ($boolInside) { continue }
        foreach ($objAttribute in @($objElement.Attributes)) {
            if ((Get-PropertyLeaf $objAttribute.Name) -match '^(Foreground|Background|BorderBrush|Fill|Stroke)$' -and ($objAttribute.Value -match '^\s*#[0-9A-Fa-f]{3,8}\s*$' -or $objAttribute.Value -match '^\s*[A-Za-z]+\s*$')) {
                [void]$listFound.Add(('{0}: <{1}> {2} is the literal color {3}' -f $Source, $objElement.LocalName, $objAttribute.Name, $objAttribute.Value))
            }
        }
        if ($objElement.HasAttribute('Opacity') -and (Test-BlueBrush $objElement.GetAttribute('Background'))) { [void]$listFound.Add(('{0}: <{1}> has a blue Background and an Opacity' -f $Source, $objElement.LocalName)) }
    }
    return $listFound.ToArray()
}

# Returns one text for a script file that does not require Pester 5.1.0 or later in its #Requires statement. The check reads
# the script requirements of the syntax tree.
function Get-PesterRequiresViolation {
    param([string]$Path)
    $objAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $arrModule = @()
    if ($objAst.ScriptRequirements) { $arrModule = @($objAst.ScriptRequirements.RequiredModules | Where-Object { $_.Name -eq 'Pester' }) }
    if ($arrModule.Count -ne 1 -or -not $arrModule[0].Version -or $arrModule[0].Version -ne [version]'5.1.0') { '{0}: no #Requires for Pester ModuleVersion 5.1.0' -f (Split-Path -Leaf $Path) }
}
