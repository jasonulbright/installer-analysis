#Requires -Modules Pester
# Logic of start-installeranalysis.ps1. The script cannot be dot-sourced (it opens the
# window), so each function is cut out of its syntax tree and defined here, with plain
# objects in place of the window controls.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    Import-AppModule
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:ShellPath = Join-Path $script:AppRoot 'start-installeranalysis.ps1'
    $script:ShellScriptPath = 'C:\Program Files\Suite\Installer Analysis\start-installeranalysis.ps1'
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ShellPath, [ref]$null, [ref]$null)
    $wanted = 'Get-IatPreferences', 'Save-IatPreferences', 'Add-LogLine', 'Set-StatusText', 'Set-ActiveView',
        'Show-OverviewText', 'Show-MsiPropertiesGrid', 'Show-PayloadGrid', 'Show-EmbeddedGrid', 'Show-StringsGrid',
        'ConvertTo-FileBrowserIndex', 'Get-FileBrowserEntriesUnder', 'New-FileBrowserTreeItem', 'Show-FileBrowserFolder',
        'Show-FileBrowser', 'Get-FileBrowserSelectedNames', 'Invoke-FileBrowserExtract', 'Show-RegistryGrid',
        'ConvertTo-RegistryRowText', 'Set-ActionBarVisible', 'Get-InspectTempDir', 'Get-DrillTempDir', 'Resolve-SevenZipPath',
        'Invoke-7zExtractSingle', 'Push-AnalysisStack', 'Pop-AnalysisStack', 'ConvertTo-StringsGridRows', 'New-AnalysisDataTable',
        'Get-SelectedPayloadEntries', 'Invoke-PayloadExtractToTemp', 'Invoke-PayloadCopyName', 'Invoke-PayloadCopyPath',
        'Invoke-PayloadHash', 'Invoke-AnalyzeSelectedEmbedded', 'Open-EmbeddedInNewWindow', 'Invoke-PayloadExtractAll'
    foreach ($n in $wanted) {
        $def = $script:Ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
        if (-not $def) { throw "function $n not found in the script" }
        # A function cut out of the script has no $PSScriptRoot and no $PSCommandPath (an automatic
        # variable that a test cannot set); give it the repository folder and a script path with spaces.
        . ([scriptblock]::Create($def.Extent.Text.Replace('$PSScriptRoot', "'$($script:AppRoot -replace "'", "''")'").Replace('$PSCommandPath', '$script:ShellScriptPath')))
    }

    # Stand-ins for the controls: objects with the members that the functions use.
    function New-FakeTextBox {
        $o = [pscustomobject]@{ Text = '' }
        $o | Add-Member -MemberType ScriptMethod -Name AppendText -Value { param($t) $this.Text += $t }
        $o | Add-Member -MemberType ScriptMethod -Name ScrollToEnd -Value { }
        return $o
    }
    function New-FakeControl { [pscustomobject]@{ Text = ''; Content = ''; Visibility = [System.Windows.Visibility]::Visible; IsEnabled = $true; ItemsSource = $null } }
    function Update-SidebarButtonTheme { }
    function Update-BreadcrumbBar { }
    function Invoke-AnalysisPipeline { }
    function Reset-ShellFakes {
        $script:LastFileInfo = $null; $script:LastInstallerType = $null; $script:LastMsiProperties = $null
        $script:LastPackageMetadata = $null; $script:LastSwitches = $null; $script:LastDeployment = $null
        $script:LastPayload = $null; $script:LastEmbedded = $null; $script:LastMspMetadata = $null
        $script:LastInnerMsiData = $null; $script:LastInterestingStrings = $null; $script:LastRegistry = $null
        $script:ActiveView = 'Overview'; $script:FilesIndex = $null; $script:FilesCurrentFolder = ''
        $script:AnalysisStack = New-Object 'System.Collections.Generic.Stack[object]'
        $script:ViewMeta = @{
            'Overview' = @{ Title = 'Overview'; Subtitle = 'overview text' }; 'MSI Properties' = @{ Title = 'MSI Properties'; Subtitle = 'msi text' }
            'Payload' = @{ Title = 'Payload'; Subtitle = 'payload text' }; 'Inner Installers' = @{ Title = 'Inner Installers'; Subtitle = 'inner text' }
            'File Browser' = @{ Title = 'File Browser'; Subtitle = 'files text' }; 'Registry Settings' = @{ Title = 'Registry Settings'; Subtitle = 'registry text' }
            'Strings' = @{ Title = 'Strings'; Subtitle = 'strings text' }
        }
        $global:Prefs = @{ DarkMode = $true; SevenZipPath = ''; LastBrowseDir = ''; ReportsFolder = '' }
        $script:txtLog = New-FakeTextBox; $script:txtStatus = New-FakeControl
        foreach ($n in 'txtOverview', 'gridMsi', 'gridPayload', 'panelEmbedded', 'panelStrings', 'panelFiles', 'panelRegistry', 'gridEmbedded', 'gridStrings',
            'gridFiles', 'gridRegistry', 'btnViewEmbedded', 'btnViewFiles', 'btnViewRegistry', 'txtModuleTitle', 'txtModuleSubtitle', 'txtStringsFilter',
            'txtRegistryFilter', 'txtRegistryNote', 'txtFilesFolder', 'txtFilesFilter', 'txtFilePath', 'btnFilesUp', 'actionBar', 'btnExtractAll',
            'progressOverlay', 'txtProgressTitle', 'txtProgressStep') { Set-Variable -Name $n -Scope Script -Value (New-FakeControl) }
        $script:progressOverlay.Visibility = [System.Windows.Visibility]::Collapsed
        $dispatcher = [pscustomobject]@{}
        $dispatcher | Add-Member -MemberType ScriptMethod -Name Invoke -Value { param($a, $p) }
        $script:window = [pscustomobject]@{ Dispatcher = $dispatcher }
        $script:treeFiles = New-Object System.Windows.Controls.TreeView
        $script:Pasted = $null
        $script:Work = $null
    }
    # The functions look variables up through the scope chain; the fakes are script variables.
    function Get-Log { return [string]$script:txtLog.Text }
}

Describe 'Shell logic' {
BeforeEach {
    Reset-ShellFakes
    Mock Set-Clipboard { $script:Pasted = $Value }
    Mock Start-Process { }
}

Describe 'Add-LogLine and Set-StatusText' {
    It 'puts the first line in an empty log and appends later lines below it' {
        Add-LogLine 'first'
        Add-LogLine 'second'
        $lines = (Get-Log) -split "\r?\n"
        $lines.Count | Should -Be 2
        $lines[0] | Should -Match '^\d{2}:\d{2}:\d{2}  first$'
        $lines[1] | Should -Match '^\d{2}:\d{2}:\d{2}  second$'
    }

    It 'rejects an empty message' {
        { Add-LogLine '' } | Should -Throw
    }

    It 'sets the status text' {
        Set-StatusText 'Ready.'
        $script:txtStatus.Text | Should -Be 'Ready.'
    }
}

Describe 'Preferences' {
    BeforeEach { $global:PrefsPath = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-prefs-' + [guid]::NewGuid().ToString('N') + '.json') }
    AfterEach { Remove-Item -LiteralPath $global:PrefsPath -ErrorAction SilentlyContinue; Remove-Variable -Name PrefsPath -Scope Global -ErrorAction SilentlyContinue }
    AfterAll { Remove-Variable -Name Prefs -Scope Global -ErrorAction SilentlyContinue }

    It 'returns the defaults when no file exists' {
        $p = Get-IatPreferences
        $p['DarkMode'] | Should -BeTrue
        $p['SevenZipPath'] | Should -Be ''
        $p['LastBrowseDir'] | Should -Be ''
        $p['ReportsFolder'] | Should -Be ''
    }

    It 'saves the values and reads them back' {
        Save-IatPreferences -Prefs @{ DarkMode = $false; SevenZipPath = 'C:\Tools\7z.exe'; LastBrowseDir = 'D:\Setup Files'; ReportsFolder = 'D:\Reports' }
        $p = Get-IatPreferences
        $p['DarkMode'] | Should -BeFalse
        $p['SevenZipPath'] | Should -Be 'C:\Tools\7z.exe'
        $p['LastBrowseDir'] | Should -Be 'D:\Setup Files'
    }

    It 'keeps the defaults for a key that the file does not have' {
        Set-Content -LiteralPath $global:PrefsPath -Value '{ "DarkMode": false }'
        $p = Get-IatPreferences
        $p['DarkMode'] | Should -BeFalse
        $p['ReportsFolder'] | Should -Be ''
    }

    It 'returns the defaults for a file that is not valid JSON' {
        Set-Content -LiteralPath $global:PrefsPath -Value '{ this is not json'
        (Get-IatPreferences)['DarkMode'] | Should -BeTrue
    }
}

Describe 'Set-ActiveView' {
    It 'shows only the panel of <View> and sets the header' -ForEach @(
        @{ View = 'Overview'; Panel = 'txtOverview' }
        @{ View = 'MSI Properties'; Panel = 'gridMsi' }
        @{ View = 'Payload'; Panel = 'gridPayload' }
        @{ View = 'Inner Installers'; Panel = 'panelEmbedded' }
        @{ View = 'Strings'; Panel = 'panelStrings' }
        @{ View = 'File Browser'; Panel = 'panelFiles' }
        @{ View = 'Registry Settings'; Panel = 'panelRegistry' }
    ) {
        Set-ActiveView -View $View
        $panels = 'txtOverview', 'gridMsi', 'gridPayload', 'panelEmbedded', 'panelStrings', 'panelFiles', 'panelRegistry'
        foreach ($p in $panels) {
            $expected = if ($p -eq $Panel) { 'Visible' } else { 'Collapsed' }
            ([string](Get-Variable -Name $p -Scope Script -ValueOnly).Visibility) | Should -Be $expected -Because $p
        }
        $script:ActiveView | Should -Be $View
        $script:txtModuleTitle.Text | Should -Be $View
        $script:txtModuleSubtitle.Text | Should -Not -BeNullOrEmpty
    }

    It 'rejects a view that does not exist' {
        { Set-ActiveView -View 'Nothing' } | Should -Throw
    }
}

Describe 'Grids' {
    It 'Show-MsiPropertiesGrid lists the properties as text and empties the grid without properties' {
        Show-MsiPropertiesGrid
        @($script:gridMsi.ItemsSource).Count | Should -Be 0
        $script:LastMsiProperties = [ordered]@{ ProductName = 'Acme'; Number = 5; Empty = $null }
        Show-MsiPropertiesGrid
        $rows = @($script:gridMsi.ItemsSource)
        $rows.Count | Should -Be 3
        $rows[0].Property | Should -Be 'ProductName'
        $rows[1].Value | Should -Be '5'
        $rows[2].Value | Should -Be ''
    }

    It 'Show-PayloadGrid shows the listing or nothing' {
        Show-PayloadGrid
        @($script:gridPayload.ItemsSource).Count | Should -Be 0
        $script:LastPayload = @([pscustomobject]@{ Name = 'a' }, [pscustomobject]@{ Name = 'b' })
        Show-PayloadGrid
        @($script:gridPayload.ItemsSource).Count | Should -Be 2
    }

    It 'Show-EmbeddedGrid shows the inner installer button with the count only when there are rows' {
        Show-EmbeddedGrid
        $script:btnViewEmbedded.Visibility | Should -Be ([System.Windows.Visibility]::Collapsed)
        $script:btnViewEmbedded.Content | Should -Be 'Inner Installers'
        $script:LastEmbedded = @([pscustomobject]@{ Name = 'a.msi' }, [pscustomobject]@{ Name = 'b.msi' }, [pscustomobject]@{ Name = 'c.msi' })
        Show-EmbeddedGrid
        $script:btnViewEmbedded.Visibility | Should -Be ([System.Windows.Visibility]::Visible)
        $script:btnViewEmbedded.Content | Should -Be 'Inner Installers (3)'
    }

    It 'Show-StringsGrid filters "<Filter>" case insensitively and gives <Count> rows' -ForEach @(
        @{ Filter = ''; Count = 4 }, @{ Filter = 'HTTP'; Count = 2 }, @{ Filter = 'zzz'; Count = 0 }, @{ Filter = 'guid'; Count = 1 }
    ) {
        $script:LastInterestingStrings = @(
            [pscustomobject]@{ Category = 'URLs'; Value = 'https://example.test/a' }, [pscustomobject]@{ Category = 'URLs'; Value = 'http://example.test/b' },
            [pscustomobject]@{ Category = 'GUIDs'; Value = '{GUID-1}' }, [pscustomobject]@{ Category = 'Empty'; Value = $null })
        Show-StringsGrid -Filter $Filter
        @($script:gridStrings.ItemsSource).Count | Should -Be $Count
    }

    It 'Show-RegistryGrid shows the entries, the filter result and the nav button for <Case>' -ForEach @(
        @{ Case = 'no result'; Reg = $null; Filter = ''; Note = ''; Visible = 'Collapsed'; Content = 'Registry Settings'; Rows = 0 }
        @{ Case = 'an MSI without entries'; Reg = [pscustomobject]@{ Format = 'MSI'; Entries = @(); Note = '' }; Filter = ''; Note = 'No registry settings are compiled into this installer.'; Visible = 'Visible'; Content = 'Registry Settings'; Rows = 0 }
        @{ Case = 'an unsupported format'; Reg = [pscustomobject]@{ Format = 'Squirrel'; Entries = @(); Note = 'Only MSI, NSIS and Inno Setup.' }; Filter = ''; Note = 'Only MSI, NSIS and Inno Setup.'; Visible = 'Collapsed'; Content = 'Registry Settings'; Rows = 0 }
        @{ Case = 'two NSIS entries'; Reg = [pscustomobject]@{ Format = 'NSIS'; Entries = @([pscustomobject]@{ Key = 'SOFTWARE\Acme'; Name = 'A'; Value = '1'; Section = 's'; Root = 'HKLM' }, [pscustomobject]@{ Key = 'SOFTWARE\Other'; Name = 'B'; Value = '2'; Section = 's'; Root = 'HKCU' }); Note = '' }; Filter = ''; Note = ''; Visible = 'Visible'; Content = 'Registry Settings (2)'; Rows = 2 }
        @{ Case = 'a filter that matches one'; Reg = [pscustomobject]@{ Format = 'InnoSetup'; Entries = @([pscustomobject]@{ Key = 'SOFTWARE\Acme'; Name = 'A'; Value = '1'; Section = 's'; Root = 'HKLM' }, [pscustomobject]@{ Key = 'SOFTWARE\Other'; Name = 'B'; Value = '2'; Section = 's'; Root = 'HKCU' }); Note = '' }; Filter = 'ACME'; Note = '1 of 2 settings match.'; Visible = 'Visible'; Content = 'Registry Settings (2)'; Rows = 1 }
    ) {
        $script:LastRegistry = $Reg
        Show-RegistryGrid -Filter $Filter
        @($script:gridRegistry.ItemsSource).Count | Should -Be $Rows
        $script:txtRegistryNote.Text | Should -Be $Note
        [string]$script:btnViewRegistry.Visibility | Should -Be $Visible
        $script:btnViewRegistry.Content | Should -Be $Content
    }

    It 'Set-ActionBarVisible shows the bar after an analysis and the extract button only with a payload' -ForEach @(
        @{ Analyzed = $false; Payload = $false; Bar = 'Collapsed'; Extract = 'Collapsed' }
        @{ Analyzed = $true; Payload = $false; Bar = 'Visible'; Extract = 'Collapsed' }
        @{ Analyzed = $true; Payload = $true; Bar = 'Visible'; Extract = 'Visible' }
        @{ Analyzed = $false; Payload = $true; Bar = 'Collapsed'; Extract = 'Collapsed' }
    ) {
        Set-ActionBarVisible -Analyzed:$Analyzed -HasPayload:$Payload
        [string]$script:actionBar.Visibility | Should -Be $Bar
        [string]$script:btnExtractAll.Visibility | Should -Be $Extract
    }
}

Describe 'ConvertTo-StringsGridRows' {
    It 'flattens a hashtable of lists and skips empty values' {
        $rows = ConvertTo-StringsGridRows -Interesting @{ URLs = @('a', '', ' ', 'b'); GUIDs = 'g' }
        @($rows).Count | Should -Be 3
        @($rows | Where-Object Category -eq 'URLs').Count | Should -Be 2
    }

    It 'flattens an object with list properties' {
        $rows = ConvertTo-StringsGridRows -Interesting ([pscustomobject]@{ URLs = @('a'); RegistryPaths = @('HKLM\x', 'HKCU\y') })
        @($rows).Count | Should -Be 3
    }

    It 'returns an empty list for nothing' {
        $rows = ConvertTo-StringsGridRows -Interesting $null
        $rows.Count | Should -Be 0
    }
}

Describe 'ConvertTo-RegistryRowText' {
    It 'writes one tab separated line per row, with the root only for a root key' {
        $text = ConvertTo-RegistryRowText -Rows @(
            [pscustomobject]@{ Root = 'HKLM'; Key = 'SOFTWARE\Acme'; Name = 'N'; Type = 'REG_SZ'; Value = 'v'; Action = 'write'; Flags = ''; View = '64'; Section = 'c'; Source = 'Registry table' }
            [pscustomobject]@{ Root = 'HKCU'; Key = ''; Name = ''; Type = ''; Value = ''; Action = 'create key'; Flags = ''; View = ''; Section = ''; Source = '' })
        $lines = $text -split "\r?\n"
        $lines.Count | Should -Be 2
        $lines[0] | Should -Be "HKLM\SOFTWARE\Acme`tN`tREG_SZ`tv`twrite`t`t64`tc`tRegistry table"
        ($lines[1] -split "`t")[0] | Should -Be 'HKCU'
    }

    It 'returns an empty string for no rows' {
        ConvertTo-RegistryRowText -Rows @() | Should -Be ''
    }
}

Describe 'File browser index' {
    BeforeEach {
        $script:Payload = @(
            [pscustomobject]@{ Name = 'setup.exe'; IsDirectory = $false; Size = 10; SizeFormatted = '10 B' }
            [pscustomobject]@{ Name = 'bin/app.dll'; IsDirectory = $false; Size = 20; SizeFormatted = '20 B' }
            [pscustomobject]@{ Name = 'bin\sub\deep.txt'; IsDirectory = $false; Size = 30; SizeFormatted = '30 B' }
            [pscustomobject]@{ Name = 'docs\'; IsDirectory = $true; Size = 0; SizeFormatted = '0 B' }
            [pscustomobject]@{ Name = '   '; IsDirectory = $false; Size = 0; SizeFormatted = '0 B' })
    }

    It 'builds a folder for every path prefix and skips blank names' {
        $index = ConvertTo-FileBrowserIndex -Payload $script:Payload
        $index.Count | Should -Be 5
        @($index.Folders.Keys | Sort-Object) | Should -Be @('', 'bin', 'bin\sub', 'docs')
        $index.Folders[''].Files.Count | Should -Be 1
        $index.Folders['bin'].Files.Count | Should -Be 1
        @($index.Folders[''].Subfolders | Sort-Object) | Should -Be @('bin', 'docs')
    }

    It 'handles an empty payload' {
        $index = ConvertTo-FileBrowserIndex -Payload @()
        $index.Folders.ContainsKey('') | Should -BeTrue
        $index.Folders[''].Files.Count | Should -Be 0
    }

    It 'lists the names of all files under a folder' {
        $script:FilesIndex = ConvertTo-FileBrowserIndex -Payload $script:Payload
        @(Get-FileBrowserEntriesUnder -Folder 'bin' | Sort-Object) | Should -Be @('bin/app.dll', 'bin\sub\deep.txt')
        @(Get-FileBrowserEntriesUnder -Folder '').Count | Should -Be 3
        @(Get-FileBrowserEntriesUnder -Folder 'nope').Count | Should -Be 0
    }

    It 'returns nothing without an index' {
        @(Get-FileBrowserEntriesUnder -Folder '').Count | Should -Be 0
    }

    It 'shows the folders first, then the files, and filters by name' {
        $script:FilesIndex = ConvertTo-FileBrowserIndex -Payload $script:Payload
        Show-FileBrowserFolder -Folder ''
        $rows = @($script:gridFiles.ItemsSource)
        @($rows | ForEach-Object Name) | Should -Be @('bin', 'docs', 'setup.exe')
        $rows[0].Kind | Should -Be 'Folder'
        $rows[0].Size | Should -Be '2 item(s)'
        $script:txtFilesFolder.Text | Should -Be '\'
        $script:btnFilesUp.IsEnabled | Should -BeFalse
        Show-FileBrowserFolder -Folder 'bin' -Filter 'APP'
        @($script:gridFiles.ItemsSource | ForEach-Object Name) | Should -Be @('app.dll')
        $script:btnFilesUp.IsEnabled | Should -BeTrue
        $script:txtFilesFolder.Text | Should -Be '\bin'
    }

    It 'goes to the root for a folder that does not exist' {
        $script:FilesIndex = ConvertTo-FileBrowserIndex -Payload $script:Payload
        Show-FileBrowserFolder -Folder 'missing\folder'
        $script:FilesCurrentFolder | Should -Be ''
    }

    It 'shows an empty grid without an index' {
        Show-FileBrowserFolder -Folder ''
        @($script:gridFiles.ItemsSource).Count | Should -Be 0
    }

    It 'fills the tree, shows the count on the nav button and expands folders on demand' {
        $script:LastPayload = $script:Payload
        $script:txtFilePath.Text = 'C:\Setup\product.exe'
        Show-FileBrowser
        $script:btnViewFiles.Content | Should -Be 'File Browser (5)'
        [string]$script:btnViewFiles.Visibility | Should -Be 'Visible'
        $script:treeFiles.Items.Count | Should -Be 1
        $root = $script:treeFiles.Items[0]
        $root.Header | Should -Be 'product.exe'
        @($root.Items | ForEach-Object Header) | Should -Be @('bin', 'docs')
    }

    It 'hides the nav button when there is no payload' {
        Show-FileBrowser
        $script:btnViewFiles.Content | Should -Be 'File Browser'
        [string]$script:btnViewFiles.Visibility | Should -Be 'Collapsed'
        $script:treeFiles.Items.Count | Should -Be 0
    }

    It 'collects the selected names, with the files under a selected folder, without duplicates' {
        $script:FilesIndex = ConvertTo-FileBrowserIndex -Payload $script:Payload
        $script:gridFiles = [pscustomobject]@{ SelectedItems = @(
                [pscustomobject]@{ IsFolder = $true; Path = 'bin' }
                [pscustomobject]@{ IsFolder = $false; Path = 'bin/app.dll' }
                [pscustomobject]@{ IsFolder = $false; Path = 'setup.exe' }) }
        @(Get-FileBrowserSelectedNames | Sort-Object) | Should -Be @('bin/app.dll', 'bin\sub\deep.txt', 'setup.exe')
    }

    It 'collects nothing for no selection' {
        $script:gridFiles = [pscustomobject]@{ SelectedItems = @() }
        @(Get-FileBrowserSelectedNames).Count | Should -Be 0
    }
}

Describe 'Invoke-FileBrowserExtract' {
    BeforeEach {
        $script:LastFileInfo = [pscustomobject]@{ FullPath = 'C:\Setup\product.exe'; SHA256 = 'ABCDEF0123456789ABCDEF' }
        Mock Find-7ZipPath { 'C:\7z\7z.exe' }
        Mock Expand-InstallerEntries { 0 }
    }

    It 'logs that nothing is selected and does not start 7-Zip' {
        Invoke-FileBrowserExtract -Names @() -Target 'D:\Out' -What 'Selected'
        Get-Log | Should -BeLike '*Extract Selected: nothing selected.*'
        Should -Invoke Expand-InstallerEntries -Times 0 -Exactly
    }

    It 'logs that there is no analysis result' {
        $script:LastFileInfo = $null
        Invoke-FileBrowserExtract -Names @('a.txt') -Target 'D:\Out' -What 'Selected'
        Get-Log | Should -BeLike '*no analysis result yet*'
        Should -Invoke Expand-InstallerEntries -Times 0 -Exactly
    }

    It 'logs that 7-Zip is missing' {
        Mock Find-7ZipPath { $null }
        Invoke-FileBrowserExtract -Names @('a.txt') -Target 'D:\Out' -What 'Selected'
        Get-Log | Should -BeLike '*7z.exe not found*'
        Should -Invoke Expand-InstallerEntries -Times 0 -Exactly
    }

    It 'extracts the names and reports success' {
        $names = @('a.txt', 'b.txt')
        $target = 'D:\Out'
        Invoke-FileBrowserExtract -Names $names -Target $target -What 'Selected'
        Should -Invoke Expand-InstallerEntries -Times 1 -Exactly -ParameterFilter { $Path -eq 'C:\Setup\product.exe' -and $OutputPath -eq $target -and $EntryName.Count -eq 2 -and $SevenZipPath -eq 'C:\7z\7z.exe' }
        Get-Log | Should -BeLike '*Extract Selected: 2 entries -> D:\Out*'
        $script:txtStatus.Text | Should -Be 'Extracted 2 entries to D:\Out'
        [string]$script:progressOverlay.Visibility | Should -Be 'Collapsed'
    }

    It 'prefers the 7-Zip path of the preferences when the file exists' {
        $global:Prefs['SevenZipPath'] = (Get-Command powershell.exe).Source
        $expected = $global:Prefs['SevenZipPath']
        Invoke-FileBrowserExtract -Names @('a.txt') -Target 'D:\Out' -What 'Selected'
        Should -Invoke Expand-InstallerEntries -Times 1 -Exactly -ParameterFilter { $SevenZipPath -eq $expected }
        Should -Invoke Find-7ZipPath -Times 0 -Exactly
    }

    It 'reports the exit code when 7-Zip does not finish with 0' {
        Mock Expand-InstallerEntries { 2 }
        Invoke-FileBrowserExtract -Names @('a.txt') -Target 'D:\Out' -What 'Folder'
        Get-Log | Should -BeLike '*7z exit code 2*'
        $script:txtStatus.Text | Should -Be 'Extraction finished with 7z exit code 2.'
        Get-Log | Should -Not -BeLike '*entries -> D:\Out'
    }

    It 'logs the error and hides the progress overlay when the extraction throws' {
        Mock Expand-InstallerEntries { throw 'disk full' }
        Invoke-FileBrowserExtract -Names @('a.txt') -Target 'D:\Out' -What 'Selected'
        Get-Log | Should -BeLike '*Extract Selected failed: disk full*'
        [string]$script:progressOverlay.Visibility | Should -Be 'Collapsed'
    }
}

Describe 'Invoke-PayloadExtractAll' {
    BeforeEach {
        $script:LastFileInfo = [pscustomobject]@{ FullPath = 'C:\Setup\product.exe'; SHA256 = 'ABCDEF0123456789' }
        Mock Find-7ZipPath { 'C:\7z\7z.exe' }
    }

    It 'reports success when the extraction returns the folder' {
        Mock Expand-InstallerPayload { 'D:\Out' }
        Invoke-PayloadExtractAll -Target 'D:\Out'
        Should -Invoke Expand-InstallerPayload -Times 1 -Exactly -ParameterFilter { $OutputPath -eq 'D:\Out' -and $Path -eq 'C:\Setup\product.exe' }
        Get-Log | Should -BeLike '*Extract Payload: complete.*'
        $script:txtStatus.Text | Should -Be 'Extracted: D:\Out'
        [string]$script:progressOverlay.Visibility | Should -Be 'Collapsed'
    }

    It 'reports a failure and not a success when 7-Zip failed' {
        Mock Expand-InstallerPayload { $null }
        Invoke-PayloadExtractAll -Target 'D:\Out'
        Get-Log | Should -BeLike '*Extract Payload failed*'
        Get-Log | Should -Not -BeLike '*complete*'
        $script:txtStatus.Text | Should -BeLike 'Extract failed*'
        [string]$script:progressOverlay.Visibility | Should -Be 'Collapsed'
    }

    It 'reports an exception and hides the overlay' {
        Mock Expand-InstallerPayload { throw 'access denied' }
        Invoke-PayloadExtractAll -Target 'D:\Out'
        Get-Log | Should -BeLike '*Extract Payload failed: access denied*'
        $script:txtStatus.Text | Should -BeLike 'Extract failed*' -Because 'the status bar must not keep showing Extracting to ...'
        [string]$script:progressOverlay.Visibility | Should -Be 'Collapsed'
    }

    It 'stops with a message when 7-Zip is missing' {
        Mock Find-7ZipPath { $null }
        Mock Expand-InstallerPayload { 'D:\Out' }
        Invoke-PayloadExtractAll -Target 'D:\Out'
        Get-Log | Should -BeLike '*7z.exe not found*'
        Should -Invoke Expand-InstallerPayload -Times 0 -Exactly
    }
}

Describe 'Temp folders' {
    BeforeEach {
        $script:AnalysisTempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-temp-' + [guid]::NewGuid().ToString('N'))
    }
    AfterEach { Remove-Item -LiteralPath $script:AnalysisTempRoot -Recurse -Force -ErrorAction SilentlyContinue }

    It 'Get-InspectTempDir creates one folder per file hash and reuses it' {
        $a = Get-InspectTempDir -Sha256 'ABCDEF0123456789ABCDEF'
        $a | Should -Be (Join-Path $script:AnalysisTempRoot 'inspect\ABCDEF0123456789')
        Test-Path -LiteralPath $a -PathType Container | Should -BeTrue
        Set-Content -LiteralPath (Join-Path $a 'keep.txt') -Value 'x'
        Get-InspectTempDir -Sha256 'ABCDEF0123456789ABCDEF' | Should -Be $a
        Test-Path -LiteralPath (Join-Path $a 'keep.txt') | Should -BeTrue
    }

    It 'Get-InspectTempDir accepts a hash shorter than 16 characters' {
        Get-InspectTempDir -Sha256 'ABC' | Should -Be (Join-Path $script:AnalysisTempRoot 'inspect\ABC')
    }

    It 'Get-InspectTempDir rejects an empty hash' {
        { Get-InspectTempDir -Sha256 '' } | Should -Throw
    }

    It 'Get-DrillTempDir gives every depth its own folder and empties it on the next call' {
        $d1 = Get-DrillTempDir -Sha256 'ABCDEF0123456789ABCDEF' -Depth 1
        $d2 = Get-DrillTempDir -Sha256 'ABCDEF0123456789ABCDEF' -Depth 2
        $d1 | Should -Not -Be $d2
        Set-Content -LiteralPath (Join-Path $d1 'old.txt') -Value 'x'
        (Get-DrillTempDir -Sha256 'ABCDEF0123456789ABCDEF' -Depth 1) | Should -Be $d1
        Test-Path -LiteralPath (Join-Path $d1 'old.txt') | Should -BeFalse
        Test-Path -LiteralPath $d2 | Should -BeTrue
    }
}

Describe 'Resolve-SevenZipPath and Invoke-7zExtractSingle' {
    It 'takes the path of the preferences when the file exists, else looks it up' {
        $global:Prefs['SevenZipPath'] = (Get-Command powershell.exe).Source
        Resolve-SevenZipPath | Should -Be $global:Prefs['SevenZipPath']
        Mock Find-7ZipPath { 'C:\found\7z.exe' }
        $global:Prefs['SevenZipPath'] = 'C:\does\not\exist\7z.exe'
        Resolve-SevenZipPath | Should -Be 'C:\found\7z.exe'
    }

    It 'tells the user when 7-Zip is missing' {
        Mock Find-7ZipPath { $null }
        Invoke-7zExtractSingle -ArchivePath 'a.exe' -EntryName 'x.msi' -OutputDir 'D:\Out' | Should -BeNullOrEmpty
        Get-Log | Should -BeLike '*7-Zip not found*'
    }

    It 'returns the extracted path' {
        Mock Find-7ZipPath { 'C:\7z\7z.exe' }
        Mock Expand-PayloadEntry { 'D:\Out\x.msi' }
        Invoke-7zExtractSingle -ArchivePath 'a.exe' -EntryName 'x.msi' -OutputDir 'D:\Out' | Should -Be 'D:\Out\x.msi'
        Get-Log | Should -BeNullOrEmpty
    }

    It 'logs a failed extraction' {
        Mock Find-7ZipPath { 'C:\7z\7z.exe' }
        Mock Expand-PayloadEntry { $null }
        Invoke-7zExtractSingle -ArchivePath 'a.exe' -EntryName 'x.msi' -OutputDir 'D:\Out' | Should -BeNullOrEmpty
        Get-Log | Should -BeLike '*Extract failed for x.msi*'
    }
}

Describe 'Analysis stack' {
    BeforeEach {
        Mock Show-OverviewText { }
        Mock Show-MsiPropertiesGrid { }
        Mock Show-PayloadGrid { }
        Mock Show-EmbeddedGrid { }
        Mock Show-StringsGrid { }
        Mock Show-FileBrowser { }
        Mock Show-RegistryGrid { }
        Mock Set-ActionBarVisible { }
        $script:txtFilePath.Text = 'C:\Setup\outer.exe'
        $script:LastFileInfo = [pscustomobject]@{ FileName = 'outer.exe' }
        $script:LastInstallerType = 'NSIS'
        $script:LastDeployment = [pscustomobject]@{ DisplayName = 'Outer Product' }
        $script:ActiveView = 'Payload'
    }

    It 'pushes a snapshot of the current result' {
        Push-AnalysisStack | Should -BeTrue
        $script:AnalysisStack.Count | Should -Be 1
        $frame = $script:AnalysisStack.Peek()
        $frame.Path | Should -Be 'C:\Setup\outer.exe'
        $frame.InstallerType | Should -Be 'NSIS'
        $frame.ActiveView | Should -Be 'Payload'
    }

    It 'refuses a sixth level and says so' {
        1..5 | ForEach-Object { Push-AnalysisStack | Out-Null }
        Push-AnalysisStack | Should -BeFalse
        $script:AnalysisStack.Count | Should -Be 5
        Get-Log | Should -BeLike '*Max drill-down depth (5) reached*'
    }

    It 'restores the previous result, the view and the status on pop' {
        Push-AnalysisStack | Out-Null
        $script:txtFilePath.Text = 'C:\Temp\inner.msi'
        $script:LastFileInfo = [pscustomobject]@{ FileName = 'inner.msi' }
        $script:LastInstallerType = 'MSI'
        $script:ActiveView = 'Strings'
        Pop-AnalysisStack
        $script:AnalysisStack.Count | Should -Be 0
        $script:txtFilePath.Text | Should -Be 'C:\Setup\outer.exe'
        $script:LastInstallerType | Should -Be 'NSIS'
        $script:ActiveView | Should -Be 'Payload'
        $script:txtStatus.Text | Should -Be 'Restored: Outer Product  [NSIS]'
        Should -Invoke Show-OverviewText -Times 1 -Exactly
        Should -Invoke Show-FileBrowser -Times 1 -Exactly
        Should -Invoke Set-ActionBarVisible -Times 1 -Exactly -ParameterFilter { $Analyzed -eq $true -and $HasPayload -eq $false }
    }

    It 'falls back to the file name in the status and to the Overview for an unknown view' {
        $script:LastDeployment = $null
        $script:ActiveView = 'Gone'
        Push-AnalysisStack | Out-Null
        Pop-AnalysisStack
        $script:ActiveView | Should -Be 'Overview'
        $script:txtStatus.Text | Should -Be 'Restored: outer.exe  [NSIS]'
    }

    It 'does nothing when the stack is empty' {
        Pop-AnalysisStack
        Should -Invoke Show-OverviewText -Times 0 -Exactly
    }
}

Describe 'New-AnalysisDataTable' {
    It 'has the three columns and a type row when nothing is analyzed' {
        $dt = New-AnalysisDataTable
        @($dt.Columns | ForEach-Object ColumnName) | Should -Be @('Section', 'Property', 'Value')
        $dt.Rows.Count | Should -Be 1
        $dt.Rows[0].Property | Should -Be 'InstallerType'
    }

    It 'lists source, application, deployment, MSI and package metadata rows' {
        $script:LastFileInfo = [pscustomobject]@{ FileName = 'a.msi'; FullPath = 'C:\a.msi'; FileSize = 5; SHA256 = 'AB'; Architecture = 'x64'; SignatureStatus = 'Valid'; SignerSubject = 'CN=Acme'; SignerIssuer = ''; SignerThumbprint = 'T'; FileVersion = ''; ProductVersion = '1.0'; ProductName = 'Acme'; CompanyName = '' }
        $script:LastInstallerType = 'MSI'
        $script:LastDeployment = [pscustomobject]@{ DisplayName = 'Acme'; DisplayVersion = '1.0'; Vendor = 'Acme Inc'; SilentUninstallString = 'msiexec /x {X} /qn' }
        $script:LastSwitches = [pscustomobject]@{ Install = 'msiexec /i a.msi /qn'; Uninstall = 'msiexec /x {X}'; Notes = 'n' }
        $script:LastMsiProperties = [ordered]@{ ProductCode = '{X}' }
        $script:LastPackageMetadata = [pscustomobject]@{ Name = 'pkg'; Tags = @('a', 'b'); Extra = @{ k2 = 'v2'; k1 = 'v1' }; Nothing = $null }
        $dt = New-AnalysisDataTable
        $rows = @($dt.Rows | ForEach-Object { '{0}|{1}|{2}' -f $_.Section, $_.Property, $_.Value })
        $rows | Should -Contain 'Source|FileName|a.msi'
        $rows | Should -Contain 'Source|SignerSubject|CN=Acme'
        $rows | Should -Not -Contain 'Source|SignerIssuer|'
        $rows | Should -Contain 'Application|Publisher|Acme Inc'
        $rows | Should -Contain 'Deployment|InstallCommand|msiexec /i a.msi /qn'
        $rows | Should -Contain 'Deployment|UninstallCommand.Resolved|msiexec /x {X} /qn'
        $rows | Should -Contain 'MsiProperty|ProductCode|{X}'
        $rows | Should -Contain 'PackageMetadata|Tags|(2 items)'
        $rows | Should -Contain 'PackageMetadata|Extra.k1|v1'
        ($rows | Where-Object { $_ -like 'PackageMetadata|Nothing*' }) | Should -BeNullOrEmpty
    }
}

Describe 'Context menu actions on the payload' {
    BeforeEach {
        $script:LastFileInfo = [pscustomobject]@{ FullPath = 'C:\Setup\product.exe'; SHA256 = 'ABCDEF0123456789ABCDEF'; FileName = 'product.exe' }
        $script:AnalysisTempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-menu-' + [guid]::NewGuid().ToString('N'))
        $script:Entries = @([pscustomobject]@{ Name = 'a.msi' }, [pscustomobject]@{ Name = 'dir\b.dll' })
    }
    AfterEach { Remove-Item -LiteralPath $script:AnalysisTempRoot -Recurse -Force -ErrorAction SilentlyContinue }

    It 'copies the names, one per line' {
        Invoke-PayloadCopyName -Entries $script:Entries
        $script:Pasted | Should -Be ('a.msi' + [Environment]::NewLine + 'dir\b.dll')
        $script:txtStatus.Text | Should -Be 'Copied 2 name(s).'
    }

    It 'copies the in-archive paths, one per line' {
        Invoke-PayloadCopyPath -Entries $script:Entries
        $script:Pasted | Should -Be ('a.msi' + [Environment]::NewLine + 'dir\b.dll')
        $script:txtStatus.Text | Should -Be 'Copied 2 path(s).'
    }

    It 'copies nothing for an empty selection' {
        Invoke-PayloadCopyName -Entries @()
        Invoke-PayloadCopyPath -Entries @()
        Should -Invoke Set-Clipboard -Times 0 -Exactly
    }

    It 'extracts selected entries to the temp folder and counts the successes' {
        Mock Resolve-SevenZipPath { 'C:\7z\7z.exe' }
        $script:ExtractCall = 0
        Mock Invoke-7zExtractSingle { $script:ExtractCall++; if ($EntryName -eq 'a.msi') { 'D:\x\a.msi' } else { $null } }
        Invoke-PayloadExtractToTemp -Entries $script:Entries
        Get-Log | Should -BeLike '*Extracted 1/2 entries to *'
        $script:txtStatus.Text | Should -Be 'Extracted 1 entries to inspect folder'
    }

    It 'says when no row is selected or no file is analyzed' {
        Invoke-PayloadExtractToTemp -Entries @()
        Get-Log | Should -BeLike '*no rows selected*'
        $script:LastFileInfo = $null
        Invoke-PayloadExtractToTemp -Entries $script:Entries
        Get-Log | Should -BeLike '*no analysis result yet*'
    }

    It 'hashes the extracted files, copies the result and logs a failed extraction' {
        $good = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-hash-' + [guid]::NewGuid().ToString('N') + '.bin')
        [System.IO.File]::WriteAllBytes($good, [byte[]](1, 2, 3))
        try {
            $expected = (Get-FileHash -LiteralPath $good -Algorithm SHA256).Hash
            Mock Invoke-7zExtractSingle { if ($EntryName -eq 'a.msi') { $global:HashFile } else { $null } }
            $global:HashFile = $good
            Invoke-PayloadHash -Entries $script:Entries
            $script:Pasted | Should -Be ('{0}  a.msi' -f $expected)
            Get-Log | Should -BeLike '*SHA256 *a.msi*'
            Get-Log | Should -BeLike '*Hash: extraction failed for dir\b.dll*'
            $script:txtStatus.Text | Should -Be 'Hashed 1 entries; SHA-256 copied to clipboard.'
        }
        finally { Remove-Item -LiteralPath $good -ErrorAction SilentlyContinue; Remove-Variable -Name HashFile -Scope Global -ErrorAction SilentlyContinue }
    }

    It 'copies no hash when every extraction failed' {
        Mock Invoke-7zExtractSingle { $null }
        Invoke-PayloadHash -Entries $script:Entries
        Should -Invoke Set-Clipboard -Times 0 -Exactly
    }

    It 'returns an empty list for a missing grid' {
        @(Get-SelectedPayloadEntries -Grid $null).Count | Should -Be 0
    }
}

Describe 'Invoke-AnalyzeSelectedEmbedded' {
    BeforeEach {
        $script:LastFileInfo = [pscustomobject]@{ FullPath = 'C:\Setup\product.exe'; SHA256 = 'ABCDEF0123456789ABCDEF'; FileName = 'product.exe' }
        $script:AnalysisTempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-drill-' + [guid]::NewGuid().ToString('N'))
        Mock Invoke-AnalysisPipeline { }
    }
    AfterEach { Remove-Item -LiteralPath $script:AnalysisTempRoot -Recurse -Force -ErrorAction SilentlyContinue }

    It 'logs <Case> and does not start an analysis' -ForEach @(
        @{ Case = 'no selected row'; Entry = $null; Text = '*no row selected*' }
        @{ Case = 'an entry that is not analyzable'; Entry = [pscustomobject]@{ Name = 'x.cab'; IsAnalyzable = $false }; Text = '*not analyzable (x.cab)*' }
    ) {
        Invoke-AnalyzeSelectedEmbedded -Entry $Entry
        Get-Log | Should -BeLike $Text
        Should -Invoke Invoke-AnalysisPipeline -Times 0 -Exactly
    }

    It 'logs that no analysis result exists' {
        $script:LastFileInfo = $null
        Invoke-AnalyzeSelectedEmbedded -Entry ([pscustomobject]@{ Name = 'x.msi'; IsAnalyzable = $true })
        Get-Log | Should -BeLike '*no analysis result yet*'
    }

    It 'stops when the extraction fails and keeps the stack' {
        Mock Invoke-7zExtractSingle { $null }
        Invoke-AnalyzeSelectedEmbedded -Entry ([pscustomobject]@{ Name = 'x.msi'; IsAnalyzable = $true })
        Get-Log | Should -BeLike '*extraction failed for x.msi*'
        $script:txtStatus.Text | Should -Be 'Analyze Selected: extraction failed.'
        $script:AnalysisStack.Count | Should -Be 0
        Should -Invoke Invoke-AnalysisPipeline -Times 0 -Exactly
    }

    It 'pushes the current result, sets the path and starts the analysis of the inner file' {
        Mock Invoke-7zExtractSingle { 'D:\drill\x.msi' }
        Invoke-AnalyzeSelectedEmbedded -Entry ([pscustomobject]@{ Name = 'x.msi'; IsAnalyzable = $true })
        $script:AnalysisStack.Count | Should -Be 1
        $script:txtFilePath.Text | Should -Be 'D:\drill\x.msi'
        Should -Invoke Invoke-AnalysisPipeline -Times 1 -Exactly
    }

    It 'does not start an analysis at the depth limit' {
        Mock Invoke-7zExtractSingle { 'D:\drill\x.msi' }
        1..5 | ForEach-Object { $script:AnalysisStack.Push([pscustomobject]@{ Path = "p$_" }) }
        Invoke-AnalyzeSelectedEmbedded -Entry ([pscustomobject]@{ Name = 'x.msi'; IsAnalyzable = $true })
        Should -Invoke Invoke-AnalysisPipeline -Times 0 -Exactly
    }
}

Describe 'Open-EmbeddedInNewWindow' {
    BeforeEach {
        $script:LastFileInfo = [pscustomobject]@{ FullPath = 'C:\Setup\product.exe'; SHA256 = 'ABCDEF0123456789ABCDEF' }
        $script:AnalysisTempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-open-' + [guid]::NewGuid().ToString('N'))
    }

    It 'starts a second instance with the extracted file, and quotes paths that contain spaces' {
        Mock Invoke-7zExtractSingle { 'C:\Users\Jane Doe\AppData\Local\InstallerAnalysis\Temp\inspect\ABCD\inner setup.msi' }
        Open-EmbeddedInNewWindow -Entry ([pscustomobject]@{ Name = 'inner setup.msi' })
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $line = $ArgumentList -join ' '
            $line -match '-File "[^"]+start-[^"]+\.ps1" -StartupFile "C:\\Users\\Jane Doe\\[^"]+inner setup\.msi"$'
        }
        Get-Log | Should -BeLike '*Spawned analyzer for*'
    }

    It 'logs <Case> and starts nothing' -ForEach @(
        @{ Case = 'a missing row'; Entry = $null; Text = '*no row / file context*' }
    ) {
        Open-EmbeddedInNewWindow -Entry $Entry
        Get-Log | Should -BeLike $Text
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'logs a failed extraction and starts nothing' {
        Mock Invoke-7zExtractSingle { $null }
        Open-EmbeddedInNewWindow -Entry ([pscustomobject]@{ Name = 'inner.msi' })
        Get-Log | Should -BeLike '*extraction failed for inner.msi*'
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'logs the error when the new process cannot start' {
        Mock Invoke-7zExtractSingle { 'D:\x\inner.msi' }
        Mock Start-Process { throw 'cannot start' }
        Open-EmbeddedInNewWindow -Entry ([pscustomobject]@{ Name = 'inner.msi' })
        Get-Log | Should -BeLike '*Open in new window failed: cannot start*'
    }
}

Describe 'Start-up re-launch under STA' {
    BeforeAll {
        # The guard at the top of the script builds the argument list for a new process.
        # Evaluate its two statements with a path that holds spaces.
        $assignments = $script:Ast.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$fwd'
            }, $true)
        $script:FwdAssignments = @($assignments | Sort-Object { $_.Extent.StartLineNumber })
    }

    It 'finds the statements that build the argument list' {
        $script:FwdAssignments.Count | Should -BeGreaterOrEqual 2
    }

    It 'quotes the script path and the startup file' {
        $scriptPath = 'C:\Program Files\Suite\Installer Analysis\start-installeranalysis.ps1'
        $StartupFile = 'C:\Users\Jane Doe\Setup Files\product.msi'
        $fwd = $null
        foreach ($a in $script:FwdAssignments) { . ([scriptblock]::Create($a.Extent.Text.Replace('$PSCommandPath', '$scriptPath'))) }
        $line = $fwd -join ' '
        $line | Should -BeLike '*-File "C:\Program Files\Suite\Installer Analysis\start-installeranalysis.ps1"*'
        $line | Should -BeLike '*-StartupFile "C:\Users\Jane Doe\Setup Files\product.msi"'
    }
}
}
