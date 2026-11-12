#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# The text summary (Copy Summary, Overview tab), the JSON digest (Copy JSON), the classification
# of inner installers, and the choice of the registry settings reader. These functions build
# strings from the analysis result, so the tests feed result objects of each shape and check
# the lines that come out.

BeforeDiscovery {
    $script:PackageCases = @(
        @{ Type = 'Chocolatey'; Pkg = @{ InstallerType = 'Chocolatey'; PackageId = 'acme'; ProjectUrl = 'https://example.test'; Tags = 'a b'; Description = ('x' * 200) }; Expect = @('Package Metadata (nuspec):', '  Id:            acme', '  Project URL:   https://example.test', ('  Description:   ' + ('x' * 137) + '...')) }
        @{ Type = 'Intunewin'; Pkg = @{ InstallerType = 'Intunewin'; SetupFile = 'setup.exe'; ToolVersion = '1.8.5'; EncryptionInfo = @{ Encrypted = $true }; MsiInfo = [pscustomobject]@{ MsiProductCode = '{P}'; MsiProductVersion = '2.0' } }; Expect = @('Package Metadata (IntuneWinPackage\Metadata\Detection.xml):', '  Setup File:    setup.exe', '  Tool Version:  1.8.5', '  Encrypted:     yes (payload keys live in Intune; cannot decrypt locally)', '  Source MSI:', '    MsiProductCode:        {P}') }
        @{ Type = 'MsixBundle'; Pkg = @{ InstallerType = 'MsixBundle'; Identity = [pscustomobject]@{ Publisher = 'CN=Acme'; ProcessorArchitecture = 'x64'; ResourceId = '' }; PropertiesDescription = 'Desc'; BundledPackages = @([pscustomobject]@{ Type = 'application'; Architecture = 'x64'; Version = '1.0.0.0'; ResourceId = 'en'; FileName = 'a.msix' }) }; Expect = @('Package Metadata (AppxManifest):', '    Publisher:             CN=Acme', '  Description:   Desc', '  Bundled Packages: 1', '    - [application]  arch=x64  v1.0.0.0  resource=en  a.msix') }
        @{ Type = 'PsadtV4'; Pkg = @{ InstallerType = 'PsadtV4'; ToolkitVariant = 'v4'; ToolkitVersion = '4.0.6'; AppMetadata = ([ordered]@{ AppArch = 'x64'; AppLang = 'EN'; ScriptAuthor = 'Me' }) }; Expect = @('Package Metadata (PSAppDeployToolkit v4 header):', '  Toolkit Ver:   4.0.6', '  App Header:', '    AppArch:           x64', '    ScriptAuthor:      Me') }
        @{ Type = 'PsadtV3'; Pkg = @{ InstallerType = 'PsadtV3'; ToolkitVariant = 'v3'; AppMetadata = [pscustomobject]@{ AppArch = 'x86' } }; Expect = @('  App Header:', '    AppArch:           x86') }
        @{ Type = 'MSP'; Pkg = @{ InstallerType = 'MSP'; PatchDisplayName = 'Acme Patch (2.1.0)'; TargetProductName = 'Acme'; InferredDisplayVersion = '2.1.0'; Classification = 'Update'; ManufacturerName = 'Acme Inc'; MoreInfoURL = 'https://example.test/p'; CreationTimeUTC = '2026-01-01'; PrimaryPatchCode = '{PC}'; PatchCodes = @('{A}', '{B}'); TargetProductCodes = @('{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}') }; Expect = @('Patch Metadata (MsiPatchMetadata):', '  Post-patch Version:      2.1.0  (parsed from DisplayName)', '  Patch Codes total:       2 (one per target product variant)', '  Target ProductCodes:     7 variant(s)', '    [4] {5}', '    ... (2 more; full list in JSON export)') }
        @{ Type = 'Velopack'; Pkg = @{ InstallerType = 'Velopack'; HeaderAvailable = $true; ProductCodeOrEquivalent = 'AcmeApp'; PackageVersion = '3.0.0'; Architecture = 'x64'; MainExe = 'acme.exe'; InstallContext = 'User'; InstallDir = '%LocalAppData%\Acme'; Note = 'A note' }; Expect = @('Package Metadata (Velopack Setup.exe):', '  Package ID:       AcmeApp', '  Main Executable:  acme.exe', '  Note: A note') }
        @{ Type = 'Squirrel'; Pkg = @{ InstallerType = 'Squirrel'; MarkersFound = @('SquirrelTemp', 'Update.exe'); NupkgReferences = @([pscustomobject]@{ FileName = 'A-1.0-delta.nupkg'; Kind = 'delta' }, [pscustomobject]@{ FileName = 'A-1.0-full.nupkg'; Kind = 'full' }); Confidence = 'High' }; Expect = @('  Markers:       2 found -> SquirrelTemp, Update.exe', '  Embedded nupkg: A-1.0-full.nupkg [full]', '  Other refs:    1 more -> A-1.0-delta.nupkg [delta]', '  Confidence:    High') }
        @{ Type = 'NSIS'; Pkg = @{ InstallerType = 'NSIS'; HeaderAvailable = $false; Note = 'solid stream' }; Expect = @('Package Metadata (NSIS compiled script):', '  Header:        not decoded (solid stream)') }
        @{ Type = 'NSIS'; Pkg = @{ InstallerType = 'NSIS'; HeaderAvailable = $true; Compression = 'LZMA'; Solid = $true; Unicode = $true; InstallDir = '$PROGRAMFILES\Acme'; InstallDirWindows = 'C:\Program Files\Acme'; InstallDirCandidates = @('a', 'b'); InstallDirRegKey = 'HKLM\Software\Acme'; UninstallerPath = '$INSTDIR\uninst.exe'; RegistryHive = 'HKLM'; RegistryView = '64'; ShellVarContext = 'all'; InstallContext = 'Machine'; ArpValues = @{ DisplayName = 'x'; Publisher = 'y' }; Note = 'n' }; Expect = @('  Stream:        LZMA solid, Unicode', '  InstallDir:    $PROGRAMFILES\Acme  ->  C:\Program Files\Acme', '  StrCpy INSTDIR: a | b', '  ARP hive:      HKLM (64-bit view)', '  ARP values:    DisplayName, Publisher', '  Note:          n') }
        @{ Type = 'InnoSetup'; Pkg = @{ InstallerType = 'InnoSetup'; HeaderAvailable = $false; Note = '' }; Expect = @('Package Metadata (Inno Setup compiled [Setup] header):', '  Header:        not decoded') }
        @{ Type = 'InnoSetup'; Pkg = @{ InstallerType = 'InnoSetup'; HeaderAvailable = $true; DataVersion = '6.2.0'; Compression = 'lzma2'; AppId = '{ID}'; AppName = 'Acme'; AppVersion = '1.0'; ArpDisplayName = 'Acme ARP'; DefaultDirName = '{autopf}\Acme'; InstallDirWindows = 'C:\Program Files\Acme'; PrivilegesRequired = 'admin'; PrivilegesRequiredOverridesAllowed = @('commandline', 'dialog'); ArchitecturesInstallIn64BitMode = 'x64'; Is64BitInstallMode = $true; MinWindowsVersion = '6.1'; RegistryHive = 'HKLM'; RegistryView = '64'; CreateUninstallRegKey = 'no'; Uninstallable = 'no' }; Expect = @('  Setup data:    6.2.0, lzma2', '  AppName:       Acme  (AppVersion 1.0)', '  ARP name:      Acme ARP', '  Privileges:    admin (overrides allowed: commandline, dialog)', '  64-bit mode:   x64 (x64 host installs 64-bit)', '  CreateUninstallRegKey: no', '  Uninstallable: no') }
        @{ Type = 'Other'; Pkg = @{ InstallerType = 'Other'; DisplayName = 'Generic'; DisplayVersion = '1.0'; Publisher = 'P'; Architecture = 'x64'; ProductCodeOrEquivalent = 'code' }; Expect = @('Package Metadata:', '  DisplayName:   Generic', '  ProductCodeOrEquivalent: code') }
    )
    $script:EmbeddedCases = @(
        @{ Name = 'a.msi'; Kind = 'MSI' }, @{ Name = 'a.msp'; Kind = 'MSP' }, @{ Name = 'a.cab'; Kind = 'CAB' }, @{ Name = 'a.exe'; Kind = 'EXE' }
        @{ Name = 'a.zip'; Kind = 'ZIP' }, @{ Name = 'a.nupkg'; Kind = 'NUPKG' }, @{ Name = 'a.appx'; Kind = 'APPX' }, @{ Name = 'a.appxbundle'; Kind = 'APPX' }
        @{ Name = 'a.msix'; Kind = 'MSIX' }, @{ Name = 'a.msixbundle'; Kind = 'MSIX' }, @{ Name = 'a.7z'; Kind = '7Z' }, @{ Name = '<inner.MSI>'; Kind = 'MSI' }
    )
}

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    Import-AppModule
    $script:FileInfo = [pscustomobject]@{
        FileName = 'setup.exe'; FullPath = 'C:\Setup\setup.exe'; FileSize = 2097152; FileSizeFormatted = '2.0 MB'; SHA256 = 'ABCDEF'
        Architecture = 'x64'; SignatureStatus = 'Valid'; SignerSubject = 'CN=Acme'; ProductName = 'Acme Tool'; ProductVersion = '1.2.3'
        FileVersion = '1.2.3.0'; CompanyName = 'Acme Inc'; FileDescription = 'Acme setup'; RequestedExecutionLevel = 'requireAdministrator'
    }
    $script:Deploy = [pscustomobject]@{ DisplayName = 'Acme Tool'; DisplayVersion = '1.2.3'; Vendor = 'Acme Inc'; SilentUninstallString = '"C:\Program Files\Acme\unins000.exe" /S'; UninstallRegistryKey = 'HKLM\...\Acme' }
    $script:Switches = [pscustomobject]@{ Install = 'setup.exe /S'; Uninstall = 'uninst.exe /S'; Notes = 'Note text' }
}

Describe 'New-AnalysisSummaryText' {
    It 'writes the file header, the elevation line, and the deployment block' {
        $text = New-AnalysisSummaryText -FileInfo $script:FileInfo -InstallerType 'NSIS' -Switches $script:Switches -DeploymentFields $script:Deploy
        $lines = $text -split "\r?\n"
        $lines[0] | Should -Be 'Installer Analysis: setup.exe'
        $lines | Should -Contain 'Type:         NSIS'
        $lines | Should -Contain 'Signed:       Valid (CN=Acme)'
        $lines | Should -Contain 'Elevation:    requireAdministrator (manifest requestedExecutionLevel)'
        $lines | Should -Contain '  SilentInstallString:   setup.exe /S'
        $lines | Should -Contain '  SilentUninstallString: "C:\Program Files\Acme\unins000.exe" /S'
    }

    It 'works with only the two mandatory inputs' {
        $text = New-AnalysisSummaryText -FileInfo ([pscustomobject]@{ FileName = 'x.exe' }) -InstallerType 'Unknown'
        $text | Should -BeLike 'Installer Analysis: x.exe*'
        $text | Should -Not -BeLike '*Deployment Fields*'
    }

    It 'rejects an empty installer type' {
        { New-AnalysisSummaryText -FileInfo $script:FileInfo -InstallerType '' } | Should -Throw
    }

    It 'lists the main MSI properties' {
        $text = New-AnalysisSummaryText -FileInfo $script:FileInfo -InstallerType 'MSI' -MsiProperties @{ ProductCode = '{PC}'; UpgradeCode = '{UC}'; ProductVersion = '1.0'; Manufacturer = 'Acme' }
        $text | Should -BeLike '*  Product Code:  {PC}*'
        $text | Should -BeLike '*  Upgrade Code:  {UC}*'
        $text | Should -BeLike '*  Manufacturer:  Acme*'
    }

    It 'renders the package block for <Type>' -ForEach $script:PackageCases {
        $pkg = [pscustomobject]$Pkg
        $text = New-AnalysisSummaryText -FileInfo $script:FileInfo -InstallerType $Type -PackageMetadata $pkg
        $lines = $text -split "\r?\n"
        foreach ($e in $Expect) { $lines | Should -Contain $e }
    }

    It 'adds the install mode lines when the setup has two install modes' {
        $pkg = [pscustomobject]@{
            InstallerType = 'InnoSetup'; HeaderAvailable = $true; DataVersion = '6'; InstallModes = @('AllUsers', 'CurrentUser'); InstallMode = 'AllUsers'
            AllUsersSwitch = '/ALLUSERS'; CurrentUserSwitch = '/CURRENTUSER'
            ModeVariants = @{ CurrentUser = [pscustomobject]@{ InstallArgs = '/CURRENTUSER'; InstallDirWindows = 'C:\Users\x\Acme'; SilentUninstallCommand = 'unins /S'; UninstallRegistryKey = 'HKCU\Acme'; RegistryView = '32' } }
        }
        $text = New-AnalysisSummaryText -FileInfo $script:FileInfo -InstallerType 'InnoSetup' -PackageMetadata $pkg
        $text | Should -BeLike '*  Install modes: AllUsers (default), CurrentUser via /CURRENTUSER*'
        $text | Should -BeLike '*    CurrentUser: args /CURRENTUSER  |  folder C:\Users\x\Acme  |  uninstall unins /S  |  key HKCU\Acme (32-bit view)*'
    }

    It 'adds the Inno Setup elevation note' {
        $fi = $script:FileInfo.PSObject.Copy()
        $pkg = [pscustomobject]@{ InstallerType = 'InnoSetup'; Format = 'InnoSetup'; PrivilegesRequired = 'lowest'; HeaderAvailable = $false }
        New-AnalysisSummaryText -FileInfo $fi -InstallerType 'InnoSetup' -PackageMetadata $pkg | Should -BeLike '*; setup elevates itself for PrivilegesRequired=lowest*'
    }

    It 'prefers the install command of the package metadata' {
        $pkg = [pscustomobject]@{ InstallerType = 'Chocolatey'; SilentInstallCommand = 'choco install x -y' }
        New-AnalysisSummaryText -FileInfo $script:FileInfo -InstallerType 'Chocolatey' -Switches $script:Switches -DeploymentFields $script:Deploy -PackageMetadata $pkg |
            Should -BeLike '*  SilentInstallString:   choco install x -y*'
    }

    It 'shows the post-patch detection target for patch <Arch> with the inner MSI architecture' -ForEach @(
        @{ Arch = 'x86'; Expect = '  UninstallRegistryKey:    HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{INNER}' }
        @{ Arch = 'x64'; Expect = '  UninstallRegistryKey:    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{INNER}' }
        @{ Arch = 'arm64'; Expect = '  UninstallRegistryKey:    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{INNER}' }
        @{ Arch = ''; Expect = '  UninstallRegistryKey x86: HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{INNER}' }
    ) {
        $msp = [pscustomobject]@{ TargetProductName = 'Acme'; TargetProductCodes = @('{T}'); InferredDisplayVersion = '2.1.0'; Classification = 'Update'; SourceFile = 'p.msp'; MoreInfoURL = 'https://example.test' }
        $inner = [pscustomobject]@{ ProductCode = '{INNER}'; ProductVersion = '2.0.0'; MsiArchitecture = $Arch }
        $text = New-AnalysisSummaryText -FileInfo $script:FileInfo -InstallerType 'Unknown' -MspMetadata @($msp, $msp) -InnerMsiData $inner
        $lines = $text -split "\r?\n"
        $lines | Should -Contain 'Effective Post-Patch Detection Target:'
        $lines | Should -Contain $Expect
        $lines | Should -Contain '  ProductCode:             {INNER}'
        $lines | Should -Contain '  BaseDisplayVersion:      2.0.0'
        $lines | Should -Contain '  Patches detected:        2'
        $lines | Should -Contain '  Source MSP:              p.msp'
        $lines | Should -Contain '  ARP value match:         DisplayVersion = 2.1.0'
    }

    It 'takes the product code of the patch target when there is no inner MSI' {
        $msp = [pscustomobject]@{ TargetProductCodes = @('{T1}', '{T2}'); InferredDisplayVersion = '' }
        (New-AnalysisSummaryText -FileInfo $script:FileInfo -InstallerType 'Unknown' -MspMetadata @($msp)) | Should -BeLike '*  ProductCode:             {T1}*'
    }
}

Describe 'ConvertTo-DeploymentJson' {
    It 'writes the schema with every field present, also when the inputs are minimal' {
        $json = ConvertTo-DeploymentJson -FileInfo ([pscustomobject]@{ FileName = 'x.exe' }) -InstallerType 'Unknown'
        $o = $json | ConvertFrom-Json
        $o.SchemaVersion | Should -Not -BeNullOrEmpty
        $o.Application.InstallerType | Should -Be 'Unknown'
        $o.Application.DisplayName | Should -Be ''
        $o.Application.DisplayVersion | Should -Be ''
        $o.Application.Publisher | Should -Be ''
    }

    It 'takes the product identity from deployment fields first, then package metadata, then file information' {
        $pkg = [pscustomobject]@{ DisplayName = 'Pkg Name'; DisplayVersion = '9.9'; Publisher = 'Pkg Pub'; ProductCodeOrEquivalent = 'pkg-code'; Architecture = 'x86' }
        $o = ConvertTo-DeploymentJson -FileInfo $script:FileInfo -InstallerType 'Chocolatey' -DeploymentFields $script:Deploy -PackageMetadata $pkg | ConvertFrom-Json
        $o.Application.DisplayName | Should -Be 'Acme Tool'
        $o = ConvertTo-DeploymentJson -FileInfo $script:FileInfo -InstallerType 'Chocolatey' -PackageMetadata $pkg | ConvertFrom-Json
        $o.Application.DisplayName | Should -Be 'Pkg Name'
        $o.Application.DisplayVersion | Should -Be '9.9'
        $o.Application.Publisher | Should -Be 'Pkg Pub'
        $o = ConvertTo-DeploymentJson -FileInfo $script:FileInfo -InstallerType 'NSIS' | ConvertFrom-Json
        $o.Application.DisplayName | Should -Be 'Acme Tool'
        $o.Application.DisplayVersion | Should -Be '1.2.3'
        $o.Application.Publisher | Should -Be 'Acme Inc'
    }

    It 'uses the MSI product code in the detection hint' {
        $o = ConvertTo-DeploymentJson -FileInfo $script:FileInfo -InstallerType 'MSI' -MsiProperties @{ ProductCode = '{PC}'; UpgradeCode = '{UC}' } | ConvertFrom-Json
        ($o | ConvertTo-Json -Depth 8) | Should -BeLike '*MSI ProductCode detection: {PC}*'
        ($o | ConvertTo-Json -Depth 8) | Should -BeLike '*{UC}*'
    }

    It 'says to read the product code from the Property table when there is none' {
        (ConvertTo-DeploymentJson -FileInfo $script:FileInfo -InstallerType 'MSI') | Should -BeLike '*use ProductCode from the MSI Property table*'
    }

    It 'lets the package metadata override the install and uninstall command' {
        $pkg = [pscustomobject]@{ SilentInstallCommand = 'choco install x'; SilentUninstallCommand = 'choco uninstall x' }
        $json = ConvertTo-DeploymentJson -FileInfo $script:FileInfo -InstallerType 'Chocolatey' -Switches $script:Switches -DeploymentFields $script:Deploy -PackageMetadata $pkg
        $json | Should -BeLike '*choco install x*'
        $json | Should -BeLike '*choco uninstall x*'
        $json | Should -Not -BeLike '*uninst.exe /S*'
    }

    It 'names the payload architecture of a Velopack setup' {
        $pkg = [pscustomobject]@{ Architecture = 'arm64' }
        $fi = [pscustomobject]@{ FileName = 'x.exe'; Architecture = 'x86' }
        (ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'Velopack' -PackageMetadata $pkg | ConvertFrom-Json).Application.Architecture | Should -Be 'arm64'
    }

    It 'writes valid JSON for text with quotes, backslashes, control characters and Unicode' {
        $fi = [pscustomobject]@{ FileName = "we`"ird\name`t.exe"; ProductName = "caf$([char]0xE9) `"quoted`" \ back`r`nline"; Architecture = 'x64' }
        $o = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'NSIS' | ConvertFrom-Json
        $o.Application.DisplayName | Should -Be "caf$([char]0xE9) `"quoted`" \ back`r`nline"
    }
}

Describe 'Get-EmbeddedInstallers' {
    It 'classifies <Name> as <Kind>' -ForEach $script:EmbeddedCases {
        $rows = @(Get-EmbeddedInstallers -Payload @([pscustomobject]@{ Name = $Name; Size = 10; IsDirectory = $false }) -Type 'Unknown' -ParentPath 'C:\p.exe')
        $rows.Count | Should -Be 1
        $rows[0].Kind | Should -Be $Kind
        $rows[0].Name | Should -Be $Name
        $rows[0].IsAnalyzable | Should -BeTrue
        $rows[0].ParentPath | Should -Be 'C:\p.exe'
    }

    It 'returns an empty list for no payload and for a payload without installers' {
        $none = Get-EmbeddedInstallers -Payload $null
        $none.Count | Should -Be 0
        $noInstaller = Get-EmbeddedInstallers -Payload @([pscustomobject]@{ Name = 'a.txt'; Size = 1; IsDirectory = $false }, [pscustomobject]@{ Name = 'dir.msi'; Size = 0; IsDirectory = $true }, [pscustomobject]@{ Name = ' '; Size = 0; IsDirectory = $false })
        $noInstaller.Count | Should -Be 0
    }

    It 'drops the internal streams of an MSI' {
        $payload = @('!Property', '[5]SummaryInformation', 'Binary.Icon', 'Icon.app', "$([char]1)Stream", 'feature.cab', 'real.exe') |
            ForEach-Object { [pscustomobject]@{ Name = $_; Size = 5; IsDirectory = $false } }
        $rows = Get-EmbeddedInstallers -Payload $payload -Type 'MSI'
        @($rows | ForEach-Object Name) | Should -Be @('real.exe', 'feature.cab')
    }

    It 'describes the file according to the outer type' -ForEach @(
        @{ Type = 'MSI'; Name = 'a.cab'; Text = 'MSI Media-table feature CAB' }
        @{ Type = 'WixBurn'; Name = 'a.msi'; Text = 'Burn bundle chained package' }
        @{ Type = 'WixBurn'; Name = 'a.cab'; Text = 'Burn container CAB' }
        @{ Type = 'Squirrel'; Name = 'a-1.0-full.nupkg'; Text = 'Squirrel app payload (.nupkg)' }
        @{ Type = 'Squirrel'; Name = 'Update.exe'; Text = 'Squirrel updater stub' }
        @{ Type = 'NSIS'; Name = 'uninst.exe'; Text = 'NSIS uninstaller stub' }
        @{ Type = 'NSIS'; Name = 'a.cab'; Text = 'NSIS-bundled CAB payload' }
        @{ Type = 'PsadtV3'; Name = 'Files\a.msi'; Text = 'PSADT Files\ payload' }
        @{ Type = 'PsadtV4'; Name = 'Files\a.exe'; Text = 'PSADT Files\ payload' }
        @{ Type = 'Chocolatey'; Name = 'tools\a.exe'; Text = 'Chocolatey tools\ payload' }
    ) {
        @(Get-EmbeddedInstallers -Payload @([pscustomobject]@{ Name = $Name; Size = 1; IsDirectory = $false }) -Type $Type)[0].Description | Should -Be $Text
    }

    It 'sorts wrapped installers first, then by size, largest first' {
        $payload = @(
            [pscustomobject]@{ Name = 'a.cab'; Size = 100; IsDirectory = $false }, [pscustomobject]@{ Name = 'b.exe'; Size = 5; IsDirectory = $false }
            [pscustomobject]@{ Name = 'c.msi'; Size = 1; IsDirectory = $false }, [pscustomobject]@{ Name = 'd.exe'; Size = 50; IsDirectory = $false })
        $rows = Get-EmbeddedInstallers -Payload $payload
        @($rows | ForEach-Object Name) | Should -Be @('c.msi', 'd.exe', 'b.exe', 'a.cab')
    }

    It 'formats sizes that the listing did not format' -ForEach @(
        @{ Size = 5; Text = '5 B' }, @{ Size = 2048; Text = '2 KB' }, @{ Size = 3145728; Text = '3.0 MB' }
    ) {
        @(Get-EmbeddedInstallers -Payload @([pscustomobject]@{ Name = 'a.msi'; Size = $Size; IsDirectory = $false }))[0].SizeFormatted | Should -Be $Text
    }
}

Describe 'Get-InstallerRegistrySettings' {
    It 'says that other formats are not read' {
        $r = Get-InstallerRegistrySettings -Path 'C:\x.exe' -InstallerType 'Squirrel'
        $r.Format | Should -Be 'Squirrel'
        @($r.Entries).Count | Should -Be 0
        $r.Note | Should -BeLike '*MSI, NSIS and Inno Setup*'
    }

    It 'routes <Type> to its reader' -ForEach @(
        @{ Type = 'MSI'; Command = 'Get-MsiRegistrySettings' }, @{ Type = 'InnoSetup'; Command = 'Get-InnoRegistrySettings' }
    ) {
        Mock -ModuleName InstallerAnalysisCommon -CommandName $Command { 'routed' }
        Get-InstallerRegistrySettings -Path 'C:\x' -InstallerType $Type | Should -Be 'routed'
    }

    It 'adds the entries of the extracted NSIS uninstaller' {
        Mock -ModuleName InstallerAnalysisCommon Get-NsisRegistrySettings {
            if ($Source -eq 'Uninstaller') { [pscustomobject]@{ Format = 'NSIS'; Entries = @([pscustomobject]@{ Key = 'u' }); Note = '' } }
            else { [pscustomobject]@{ Format = 'NSIS'; Entries = @([pscustomobject]@{ Key = 'i' }); Note = '' } }
        }
        Mock -ModuleName InstallerAnalysisCommon Expand-PayloadEntry { $env:PSModulePath.Length | Out-Null; (Get-Command powershell.exe).Source }
        $installer = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-nsis-' + [guid]::NewGuid().ToString('N') + '.exe')
        [System.IO.File]::WriteAllBytes($installer, [byte[]](1, 2, 3))
        try {
            $meta = [pscustomobject]@{ UninstallerPath = '"$INSTDIR\uninst.exe"'; Solid = $false }
            $payload = @([pscustomobject]@{ Name = 'sub\uninst.exe'; IsDirectory = $false })
            $r = Get-InstallerRegistrySettings -Path $installer -InstallerType 'NSIS' -PackageMetadata $meta -Payload $payload -SevenZipPath 'C:\7z.exe' -TempDir 'C:\tmp'
            @($r.Entries | ForEach-Object Key) | Should -Be @('i', 'u')
        }
        finally { Remove-Item -LiteralPath $installer -ErrorAction SilentlyContinue }
    }

    It 'keeps the installer entries and does not extract when no uninstaller is listed' {
        Mock -ModuleName InstallerAnalysisCommon Get-NsisRegistrySettings { [pscustomobject]@{ Format = 'NSIS'; Entries = @([pscustomobject]@{ Key = 'i' }); Note = '' } }
        Mock -ModuleName InstallerAnalysisCommon Expand-PayloadEntry { 'x' }
        $installer = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-nsis-' + [guid]::NewGuid().ToString('N') + '.exe')
        [System.IO.File]::WriteAllBytes($installer, [byte[]](1, 2, 3))
        try {
            $meta = [pscustomobject]@{ UninstallerPath = 'uninst.exe'; Solid = $false }
            $r = Get-InstallerRegistrySettings -Path $installer -InstallerType 'NSIS' -PackageMetadata $meta -Payload @() -SevenZipPath 'C:\7z.exe' -TempDir 'C:\tmp'
            @($r.Entries).Count | Should -Be 1
            Should -Invoke -ModuleName InstallerAnalysisCommon Expand-PayloadEntry -Times 0 -Exactly
        }
        finally { Remove-Item -LiteralPath $installer -ErrorAction SilentlyContinue }
    }
}

Describe 'Find-7ZipPath' {
    It 'returns the preferred path when it exists' {
        Find-7ZipPath -PreferredPath (Get-Command powershell.exe).Source | Should -Be (Get-Command powershell.exe).Source
    }

    It 'does not return a preferred path that does not exist' {
        $found = Find-7ZipPath -PreferredPath 'C:\does\not\exist\7z.exe'
        if ($found) { Test-Path -LiteralPath $found | Should -BeTrue }
    }
}
