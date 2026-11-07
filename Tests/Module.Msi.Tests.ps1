#Requires -Modules Pester
# Reading of Windows Installer databases. The MSI files are built with the Windows Installer
# COM API (New-TestMsi in TestHelpers.ps1), so the code reads files that Windows accepts.

BeforeDiscovery {
    $script:TemplateCases = @(
        @{ Template = 'x64;1033';       Expected = 'x64' }
        @{ Template = 'Intel;1033';     Expected = 'x86' }
        @{ Template = 'Intel64;1033';   Expected = 'x64' }
        @{ Template = 'Arm64;1033';     Expected = 'arm64' }
        @{ Template = 'Intel;2064';     Expected = 'x86' }
        @{ Template = 'Intel;1033,1064'; Expected = 'x86' }
        @{ Template = 'x64;1064';       Expected = 'x64' }
        @{ Template = 'Intel;';         Expected = 'x86' }
        @{ Template = 'Arm64;';         Expected = 'arm64' }
    )
    $script:RegistryValueCases = @(
        @{ Value = '#x0102ff';       Name = 'N'; Type = 'REG_BINARY';    Text = '0102ff';       Action = 'write' }
        @{ Value = '#%%ProgramFiles%\x'; Name = 'N'; Type = 'REG_EXPAND_SZ'; Text = '%ProgramFiles%\x'; Action = 'write' }
        @{ Value = '##literal';      Name = 'N'; Type = 'REG_SZ';        Text = '#literal';     Action = 'write' }
        @{ Value = '#42';            Name = 'N'; Type = 'REG_DWORD';     Text = '42';           Action = 'write' }
        @{ Value = '#-7';            Name = 'N'; Type = 'REG_DWORD';     Text = '-7';           Action = 'write' }
        @{ Value = 'a[~]b[~]c';      Name = 'N'; Type = 'REG_MULTI_SZ';  Text = 'a[~]b[~]c';    Action = 'write' }
        @{ Value = 'plain text';     Name = 'N'; Type = 'REG_SZ';        Text = 'plain text';   Action = 'write' }
        @{ Value = '';               Name = 'N'; Type = 'REG_SZ';        Text = '';             Action = 'write' }
        @{ Value = '#12abc';         Name = 'N'; Type = 'REG_SZ';        Text = '#12abc';       Action = 'write' }
        @{ Value = $null;            Name = '+'; Type = '';              Text = '';             Action = 'create key' }
        @{ Value = $null;            Name = '-'; Type = '';              Text = '';             Action = 'delete key on uninstall' }
        @{ Value = $null;            Name = '*'; Type = '';              Text = '';             Action = 'create key; delete on uninstall' }
        @{ Value = $null;            Name = 'N'; Type = 'REG_SZ';        Text = '';             Action = 'write' }
    )
}

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    Import-AppModule
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-msi-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    $script:Basic = Join-Path $script:Work 'basic.msi'
    New-TestMsi -Path $script:Basic -Property ([ordered]@{
            ProductName    = 'Acme Tool'
            ProductVersion = '1.2.3'
            Manufacturer   = "O'Brien & Sons"
            ProductCode    = '{11111111-2222-3333-4444-555555555555}'
            Quote          = 'say "hi" [PROPERTY] caf' + [char]0xE9
        }) -Summary @{ Template = 'x64;1033'; Subject = 'Subject text'; Author = 'Author text'; Comments = 'Comment text'; Revision = '{22222222-3333-4444-5555-666666666666}' }

    $script:Garbage = Join-Path $script:Work 'garbage.msi'
    [System.IO.File]::WriteAllBytes($script:Garbage, ([byte[]](1..200)))
    $script:Empty = Join-Path $script:Work 'zero.msi'
    [System.IO.File]::WriteAllBytes($script:Empty, ([byte[]]@()))
    $script:Files = @{ Garbage = $script:Garbage; Empty = $script:Empty; Missing = (Join-Path $script:Work 'missing.msi') }
    $script:Spaced = Join-Path $script:Work "o'brien setup (x64).msi"
    New-TestMsi -Path $script:Spaced -Property ([ordered]@{ ProductName = 'Spaced' }) -Summary @{ Template = 'Intel;1033' }
}

AfterAll {
    Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Get-MsiProperties through Windows Installer' {
    BeforeAll { Mock -ModuleName InstallerAnalysisCommon Test-MsiModuleAvailable { $false } }

    It 'reads every row of the Property table in order' {
        $p = Get-MsiProperties -MsiPath $script:Basic
        @($p.Keys) | Should -Be @('ProductName', 'ProductVersion', 'Manufacturer', 'ProductCode', 'Quote')
        $p['ProductName'] | Should -Be 'Acme Tool'
        $p['Manufacturer'] | Should -Be "O'Brien & Sons"
        $p['Quote'] | Should -Be ('say "hi" [PROPERTY] caf' + [char]0xE9)
    }

    It 'reads a file with spaces, an apostrophe and parentheses in its name' {
        (Get-MsiProperties -MsiPath $script:Spaced)['ProductName'] | Should -Be 'Spaced'
    }

    It 'returns an empty table and logs an error for <Case>' -ForEach @(
        @{ Case = 'a file that is not an MSI'; Name = 'Garbage' }
        @{ Case = 'an empty file'; Name = 'Empty' }
        @{ Case = 'a missing file'; Name = 'Missing' }
    ) {
        Mock -ModuleName InstallerAnalysisCommon Write-Log {}
        $p = Get-MsiProperties -MsiPath $script:Files[$Name]
        $p.Count | Should -Be 0
        Should -Invoke Write-Log -ModuleName InstallerAnalysisCommon -Times 1 -Exactly -ParameterFilter { $Level -eq 'ERROR' -and $Message -like 'Failed to read MSI properties*' }
    }

    It 'can read the same file again after the first read' {
        $null = Get-MsiProperties -MsiPath $script:Basic
        (Get-MsiProperties -MsiPath $script:Basic).Count | Should -Be 5
    }
}

Describe 'Get-MsiSummaryInfo through Windows Installer' {
    BeforeAll { Mock -ModuleName InstallerAnalysisCommon Test-MsiModuleAvailable { $false } }

    It 'reads the summary fields' {
        $s = Get-MsiSummaryInfo -MsiPath $script:Basic
        $s.Template | Should -Be 'x64;1033'
        $s.Subject | Should -Be 'Subject text'
        $s.Author | Should -Be 'Author text'
        $s.RevisionNumber | Should -Be '{22222222-3333-4444-5555-666666666666}'
        $s.Architecture | Should -Be 'x64'
    }

    It 'names the architecture <Expected> for the template "<Template>"' -ForEach $script:TemplateCases {
        $msi = Join-Path $script:Work ('tpl-' + [guid]::NewGuid().ToString('N') + '.msi')
        New-TestMsi -Path $msi -Property ([ordered]@{ ProductName = 'T' }) -Summary @{ Template = $Template }
        (Get-MsiSummaryInfo -MsiPath $msi).Architecture | Should -Be $Expected
    }

    It 'returns nothing and logs an error for <Case>' -ForEach @(
        @{ Case = 'a file that is not an MSI'; Name = 'Garbage' }
        @{ Case = 'an empty file'; Name = 'Empty' }
    ) {
        Mock -ModuleName InstallerAnalysisCommon Write-Log {}
        Get-MsiSummaryInfo -MsiPath $script:Files[$Name] | Should -BeNullOrEmpty
        Should -Invoke Write-Log -ModuleName InstallerAnalysisCommon -Times 1 -Exactly -ParameterFilter { $Level -eq 'ERROR' -and $Message -like 'Failed to read MSI summary*' }
    }
}

Describe 'The vendored MSI module (Lib\MSI), loaded by path as the script does' {
    BeforeAll {
        $manifest = Get-ChildItem -LiteralPath (Join-Path $script:AppRoot 'Lib\MSI') -Recurse -Filter 'MSI.psd1' | Select-Object -First 1
        Import-Module -Name $manifest.FullName -Force -DisableNameChecking -Global
        Mock -ModuleName InstallerAnalysisCommon Test-MsiModuleAvailable { $true }
    }
    AfterAll { Remove-Module MSI -Force -ErrorAction SilentlyContinue }

    It 'reads the properties without the fall-back to Windows Installer' {
        Mock -ModuleName InstallerAnalysisCommon Write-Log {}
        $p = Get-MsiProperties -MsiPath $script:Basic
        $p['ProductName'] | Should -Be 'Acme Tool'
        $p.Count | Should -Be 5
        Should -Invoke Write-Log -ModuleName InstallerAnalysisCommon -Times 0 -Exactly -ParameterFilter { $Level -eq 'WARN' }
        Should -Invoke Write-Log -ModuleName InstallerAnalysisCommon -Times 1 -Exactly -ParameterFilter { $Message -like 'Read * MSI properties via MSI module' }
    }

    It 'reads the summary without the fall-back to Windows Installer' {
        Mock -ModuleName InstallerAnalysisCommon Write-Log {}
        $s = Get-MsiSummaryInfo -MsiPath $script:Basic
        $s.Architecture | Should -Be 'x64'
        $s.Subject | Should -Be 'Subject text'
        $s.Comments | Should -Be 'Comment text'
        Should -Invoke Write-Log -ModuleName InstallerAnalysisCommon -Times 0 -Exactly -ParameterFilter { $Level -eq 'WARN' }
    }

    It 'names the architecture <Expected> for the template "<Template>"' -ForEach $script:TemplateCases {
        $msi = Join-Path $script:Work ('vtpl-' + [guid]::NewGuid().ToString('N') + '.msi')
        New-TestMsi -Path $msi -Property ([ordered]@{ ProductName = 'T' }) -Summary @{ Template = $Template }
        Mock -ModuleName InstallerAnalysisCommon Write-Log {}
        (Get-MsiSummaryInfo -MsiPath $msi).Architecture | Should -Be $Expected
    }

    It 'falls back to Windows Installer for a file that the module cannot read' {
        Mock -ModuleName InstallerAnalysisCommon Write-Log {}
        (Get-MsiProperties -MsiPath $script:Garbage).Count | Should -Be 0
        Should -Invoke Write-Log -ModuleName InstallerAnalysisCommon -Times 1 -Exactly -ParameterFilter { $Level -eq 'WARN' -and $Message -like 'MSI module failed*' }
    }
}

Describe 'Get-MsiRegistrySettings' {
    BeforeAll {
        $script:RegMsi = Join-Path $script:Work 'registry.msi'
        New-TestMsi -Path $script:RegMsi -Property ([ordered]@{ ProductName = 'Reg' }) `
            -Component @(@{ Name = 'Comp64'; Attributes = 256 }, @{ Name = 'Comp32'; Attributes = 0 }) `
            -Registry @(
            @{ Id = 'r1'; Root = 2; Key = 'SOFTWARE\Acme\Tool'; Name = 'Version'; Value = '1.2.3'; Component = 'Comp64' }
            @{ Id = 'r2'; Root = -1; Key = 'SOFTWARE\Acme\Tool'; Name = 'Count'; Value = '#5'; Component = 'Comp32' }
            @{ Id = 'r3'; Root = 0; Key = '.acme'; Name = $null; Value = 'AcmeFile'; Component = 'Comp32' }
            @{ Id = 'r4'; Root = 1; Key = 'SOFTWARE\Acme\Created'; Name = '+'; Value = $null; Component = 'Comp32' }
            @{ Id = 'r5'; Root = 9; Key = 'SOFTWARE\Odd'; Name = 'X'; Value = '[~]a[~]b'; Component = 'Comp32' }
        ) `
            -RemoveRegistry @(
            @{ Id = 'x1'; Root = 1; Key = 'SOFTWARE\Acme\Old'; Name = '-'; Component = 'Comp32' }
            @{ Id = 'x2'; Root = 2; Key = 'SOFTWARE\Acme\Old'; Name = 'Leftover'; Component = 'Comp64' }
        )
        $script:RegNoComponent = Join-Path $script:Work 'registry-nocomp.msi'
        New-TestMsi -Path $script:RegNoComponent -Registry @(@{ Id = 'r1'; Root = 2; Key = 'SOFTWARE\NoComp'; Name = 'V'; Value = 'x'; Component = 'Missing' })
    }

    It 'lists the Registry rows with root, type, value, action, view and component' {
        $r = Get-MsiRegistrySettings -MsiPath $script:RegMsi
        $r.Format | Should -Be 'MSI'
        $r.Note | Should -BeNullOrEmpty
        $rows = @($r.Entries)
        $rows.Count | Should -Be 7
        $version = $rows | Where-Object { $_.Name -eq 'Version' }
        $version.Root | Should -Be 'HKLM'
        $version.View | Should -Be '64'
        $version.Section | Should -Be 'Comp64'
        $version.Source | Should -Be 'Registry table'
        $count = $rows | Where-Object { $_.Name -eq 'Count' }
        $count.Root | Should -Be 'HKMU'
        $count.Type | Should -Be 'REG_DWORD'
        $count.Value | Should -Be '5'
        $count.View | Should -Be '32'
    }

    It 'describes a key row, a default value row and an unknown root' {
        $rows = @((Get-MsiRegistrySettings -MsiPath $script:RegMsi).Entries)
        ($rows | Where-Object { $_.Key -eq 'SOFTWARE\Acme\Created' }).Action | Should -Be 'create key'
        ($rows | Where-Object { $_.Key -eq 'SOFTWARE\Acme\Created' }).Name | Should -Be ''
        ($rows | Where-Object { $_.Key -eq '.acme' }).Root | Should -Be 'HKCR'
        ($rows | Where-Object { $_.Key -eq 'SOFTWARE\Odd' }).Root | Should -Be 'root 9'
    }

    It 'lists the RemoveRegistry rows as delete actions' {
        $rows = @((Get-MsiRegistrySettings -MsiPath $script:RegMsi).Entries | Where-Object { $_.Source -eq 'RemoveRegistry table' })
        $rows.Count | Should -Be 2
        ($rows | Where-Object { $_.Name -eq '' }).Action | Should -Be 'delete key'
        ($rows | Where-Object { $_.Name -eq 'Leftover' }).Action | Should -Be 'delete value'
    }

    It 'numbers the rows in the order read' {
        $rows = @((Get-MsiRegistrySettings -MsiPath $script:RegMsi).Entries)
        @($rows | ForEach-Object Order) | Should -Be @(0..($rows.Count - 1))
    }

    It 'returns no entries for a package without registry tables' {
        $r = Get-MsiRegistrySettings -MsiPath $script:Basic
        @($r.Entries).Count | Should -Be 0
        $r.Note | Should -BeNullOrEmpty
    }

    It 'reads registry rows of a package without a Component table, with an empty view' {
        $rows = @((Get-MsiRegistrySettings -MsiPath $script:RegNoComponent).Entries)
        $rows.Count | Should -Be 1
        $rows[0].View | Should -Be ''
    }

    It 'says that the package was not found' {
        (Get-MsiRegistrySettings -MsiPath (Join-Path $script:Work 'missing.msi')).Note | Should -BeLike 'Package not found*'
    }

    It 'explains that the tables could not be read from <Case>' -ForEach @(
        @{ Case = 'a file that is not an MSI'; Name = 'Garbage' }
        @{ Case = 'an empty file'; Name = 'Empty' }
    ) {
        $r = Get-MsiRegistrySettings -MsiPath $script:Files[$Name]
        @($r.Entries).Count | Should -Be 0
        $r.Note | Should -BeLike 'Registry tables could not be read*'
    }
}

Describe 'ConvertFrom-MsiRegistryValue' {
    It 'reads value "<Value>" with name "<Name>" as <Type> and action <Action>' -ForEach $script:RegistryValueCases {
        $r = & (Get-Module InstallerAnalysisCommon) { param($v, $n) ConvertFrom-MsiRegistryValue -Value $v -Name $n } $Value $Name
        $r.Type | Should -Be $Type
        $r.Text | Should -Be $Text
        $r.Action | Should -Be $Action
    }
}
