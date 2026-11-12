#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Package formats that are ZIP files (Chocolatey, NuGet, Intunewin, MSIX, PSADT) and the code that
# turns an analysis result into text and JSON. The fixtures are small synthetic archives.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    Import-AppModule
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-formats-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    function script:New-Zip {
        param([string]$Name, [hashtable]$Entries)
        $path = Join-Path $script:Work $Name
        $archive = [System.IO.Compression.ZipFile]::Open($path, 'Create')
        try {
            foreach ($key in $Entries.Keys) {
                $entry = $archive.CreateEntry($key)
                $stream = $entry.Open()
                try {
                    $value = $Entries[$key]
                    [byte[]]$bytes = [byte[]]@()
                    if ($value -is [byte[]]) { $bytes = $value } else { $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes([string]$value) }
                    if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }
                }
                finally { $stream.Dispose() }
            }
        }
        finally { $archive.Dispose() }
        return $path
    }

    function script:New-Nuspec {
        param([string]$Namespace = 'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd', [string]$Id = 'acme.tool', [string]$Version = '1.2.3', [string]$Title = 'Acme Tool', [string]$Description = 'A tool.')
        $ns = if ($Namespace) { " xmlns=`"$Namespace`"" } else { '' }
        $titleXml = if ($Title) { "<title>$Title</title>" } else { '' }
        "<?xml version=`"1.0`"?><package$ns><metadata><id>$Id</id><version>$Version</version>$titleXml<authors>Acme Inc</authors><owners>Owner Name</owners><projectUrl>https://example.test/acme</projectUrl><tags>tool acme</tags><description>$Description</description><licenseUrl>https://example.test/license</licenseUrl></metadata></package>"
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'ZIP helpers' {
    BeforeAll {
        $script:Zip = New-Zip -Name 'helpers.zip' -Entries @{ 'root.txt' = 'root text'; 'dir/inner.txt' = 'inner'; 'Deep/Name.nuspec' = 'x'; 'top.nuspec' = 'y' }
        $script:NotZip = Join-Path $script:Work 'plain.zip'
        [System.IO.File]::WriteAllText($script:NotZip, 'this is not a zip file')
        $script:ShortFile = Join-Path $script:Work 'short.zip'
        [System.IO.File]::WriteAllBytes($script:ShortFile, [byte[]](0x50, 0x4B))
        $script:Missing = Join-Path $script:Work 'missing.zip'
    }

    It 'Test-IsZipFile is <Expected> for <Case>' -ForEach @(
        @{ Case = 'a zip'; Key = 'Zip'; Expected = $true }
        @{ Case = 'text'; Key = 'NotZip'; Expected = $false }
        @{ Case = 'a file shorter than the signature'; Key = 'ShortFile'; Expected = $false }
        @{ Case = 'a file that does not exist'; Key = 'Missing'; Expected = $false }
    ) {
        Test-IsZipFile -Path (Get-Variable -Name $Key -Scope Script -ValueOnly) | Should -Be $Expected
    }

    It 'Test-ZipEntryExists finds an entry by exact name, by pattern, and only at the root on request' {
        Test-ZipEntryExists -Path $script:Zip -EntryName 'dir/inner.txt' | Should -BeTrue
        Test-ZipEntryExists -Path $script:Zip -EntryName 'inner.txt' | Should -BeFalse
        Test-ZipEntryExists -Path $script:Zip -Pattern 'inner*' | Should -BeTrue
        Test-ZipEntryExists -Path $script:Zip -Pattern 'inner*' -RootOnly | Should -BeFalse
        Test-ZipEntryExists -Path $script:Zip -Pattern 'root*' -RootOnly | Should -BeTrue
        Test-ZipEntryExists -Path $script:Zip | Should -BeFalse
    }

    It 'Test-ZipEntryExists is false for a file that is not a zip and for a missing file' {
        Test-ZipEntryExists -Path $script:NotZip -EntryName 'x' | Should -BeFalse
        Test-ZipEntryExists -Path $script:Missing -EntryName 'x' | Should -BeFalse
    }

    It 'Get-ZipEntryText returns the text, and nothing for a missing entry, a non-zip and a missing file' {
        Get-ZipEntryText -Path $script:Zip -EntryName 'root.txt' | Should -Be 'root text'
        Get-ZipEntryText -Path $script:Zip -EntryName 'nope.txt' | Should -BeNullOrEmpty
        Get-ZipEntryText -Path $script:NotZip -EntryName 'x' | Should -BeNullOrEmpty
        Get-ZipEntryText -Path $script:Missing -EntryName 'x' | Should -BeNullOrEmpty
    }

    It 'Get-ZipRootEntryByPattern takes only root entries' {
        Get-ZipRootEntryByPattern -Path $script:Zip -Pattern '*.nuspec' | Should -Be 'top.nuspec'
        Get-ZipRootEntryByPattern -Path $script:Zip -Pattern '*.xml' | Should -BeNullOrEmpty
        Get-ZipRootEntryByPattern -Path $script:NotZip -Pattern '*' | Should -BeNullOrEmpty
    }

    It 'Get-ZipEntryPathByPattern returns the path of a nested entry' {
        Get-ZipEntryPathByPattern -Path $script:Zip -Pattern 'inner*' | Should -Be 'dir/inner.txt'
        Get-ZipEntryPathByPattern -Path $script:Zip -Pattern 'nothing*' | Should -BeNullOrEmpty
    }
}

Describe 'Get-ChocolateyMetadata' {
    It 'reads a Chocolatey package and builds the choco commands' {
        $p = New-Zip -Name 'choco.nupkg' -Entries @{ 'acme.tool.nuspec' = (New-Nuspec); 'tools/chocolateyInstall.ps1' = '# install' }
        $m = Get-ChocolateyMetadata -Path $p
        $m.InstallerType | Should -Be 'Chocolatey'
        $m.IsChocolatey | Should -BeTrue
        $m.PackageId | Should -Be 'acme.tool'
        $m.DisplayName | Should -Be 'Acme Tool'
        $m.DisplayVersion | Should -Be '1.2.3'
        $m.Publisher | Should -Be 'Acme Inc'
        $m.SilentInstallCommand | Should -BeLike 'choco install acme.tool --version=1.2.3 -y*'
        $m.SilentUninstallCommand | Should -Be 'choco uninstall acme.tool -y'
        $m.ProjectUrl | Should -Be 'https://example.test/acme'
    }

    It 'reads a plain NuGet package and says it is not an installer' {
        $p = New-Zip -Name 'plain.nupkg' -Entries @{ 'acme.tool.nuspec' = (New-Nuspec -Title ''); 'lib/net48/a.dll' = 'x' }
        $m = Get-ChocolateyMetadata -Path $p
        $m.InstallerType | Should -Be 'NuGet'
        $m.IsChocolatey | Should -BeFalse
        $m.DisplayName | Should -Be 'acme.tool'
        $m.SilentInstallCommand | Should -BeLike 'nuget install acme.tool -Version 1.2.3*'
        $m.SilentUninstallCommand | Should -BeLike 'N/A*'
    }

    It 'reads the nuspec with the namespace <Namespace>' -ForEach @(
        @{ Namespace = 'http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd' }
        @{ Namespace = 'http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd' }
        @{ Namespace = 'http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd' }
        @{ Namespace = 'http://schemas.microsoft.com/packaging/2017/09/nuspec.xsd' }
        @{ Namespace = '' }
    ) {
        $p = New-Zip -Name ('ns-' + [guid]::NewGuid().ToString('N') + '.nupkg') -Entries @{ 'a.nuspec' = (New-Nuspec -Namespace $Namespace) }
        (Get-ChocolateyMetadata -Path $p).PackageId | Should -Be 'acme.tool'
    }

    It 'reads a nuspec that starts with a byte order mark' {
        $bom = [byte[]]([System.Text.Encoding]::UTF8.GetPreamble() + [System.Text.Encoding]::UTF8.GetBytes((New-Nuspec)))
        $p = New-Zip -Name 'bom.nupkg' -Entries @{ 'a.nuspec' = $bom }
        (Get-ChocolateyMetadata -Path $p).PackageId | Should -Be 'acme.tool'
    }

    It 'returns nothing for <Case>' -ForEach @(
        @{ Case = 'a file that is not a zip'; Entries = $null }
        @{ Case = 'a zip without a nuspec'; Entries = @{ 'readme.txt' = 'x' } }
        @{ Case = 'a nuspec that is not XML'; Entries = @{ 'a.nuspec' = '<package><metadata>' } }
        @{ Case = 'a nuspec without metadata'; Entries = @{ 'a.nuspec' = '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><other/></package>' } }
        @{ Case = 'an empty nuspec'; Entries = @{ 'a.nuspec' = '' } }
        @{ Case = 'a nuspec that is only in a folder'; Entries = @{ 'dir/a.nuspec' = '<package><metadata><id>x</id></metadata></package>' } }
    ) {
        $path = if ($null -eq $Entries) { $f = Join-Path $script:Work ('bad-' + [guid]::NewGuid().ToString('N') + '.nupkg'); [System.IO.File]::WriteAllText($f, 'not a zip'); $f } else { New-Zip -Name ('bad-' + [guid]::NewGuid().ToString('N') + '.nupkg') -Entries $Entries }
        Get-ChocolateyMetadata -Path $path | Should -BeNullOrEmpty
    }

    It 'keeps hostile text in the fields as plain text' {
        $p = New-Zip -Name 'hostile.nupkg' -Entries @{ 'a.nuspec' = (New-Nuspec -Id 'x$(calc)' -Title '&lt;b&gt;Title&lt;/b&gt;' -Description '=cmd|calc') }
        $m = Get-ChocolateyMetadata -Path $p
        $m.PackageId | Should -Be 'x$(calc)'
        $m.DisplayName | Should -Be '<b>Title</b>'
        $m.Description | Should -Be '=cmd|calc'
    }
}

Describe 'Get-IntunewinMetadata' {
    BeforeAll {
        $script:Detection = {
            param([string]$Msi = '', [string]$Context = 'System', [string]$Enc = '<EncryptionInfo><EncryptionKey>SECRETKEY</EncryptionKey><MacKey>SECRETMAC</MacKey><InitializationVector>IV</InitializationVector><Mac>MAC</Mac><ProfileIdentifier>ProfileVersion1</ProfileIdentifier><FileDigest>DIGEST</FileDigest><FileDigestAlgorithm>SHA256</FileDigestAlgorithm></EncryptionInfo>')
            $msiXml = if ($Msi) { "<MsiInfo><MsiProductCode>{AAAAAAAA-0000-0000-0000-000000000001}</MsiProductCode><MsiProductVersion>$Msi</MsiProductVersion><MsiUpgradeCode>{BBBBBBBB-0000-0000-0000-000000000002}</MsiUpgradeCode><MsiExecutionContext>$Context</MsiExecutionContext><MsiRequiresReboot>false</MsiRequiresReboot><MsiPublisher>Acme Inc</MsiPublisher></MsiInfo>" } else { '' }
            "<?xml version=`"1.0`" encoding=`"utf-8`"?><ApplicationInfo ToolVersion=`"1.8.5`"><Name>Acme</Name><UnencryptedContentSize>1234</UnencryptedContentSize><FileName>IntunePackage.intunewin</FileName><SetupFile>setup.exe</SetupFile>$Enc$msiXml</ApplicationInfo>"
        }
    }

    It 'redacts the key material unless it is asked for' {
        $p = New-Zip -Name 'redact.intunewin' -Entries @{ 'IntuneWinPackage/Metadata/Detection.xml' = (& $script:Detection) }
        $m = Get-IntunewinMetadata -Path $p
        $m.EncryptionInfo.Encrypted | Should -BeTrue
        $m.EncryptionInfo.EncryptionKey | Should -Be '<redacted>'
        $m.EncryptionInfo.MacKey | Should -Be '<redacted>'
        $m.EncryptionInfo.InitializationVector | Should -Be '<redacted>'
        $m.EncryptionInfo.Mac | Should -Be '<redacted>'
        $m.EncryptionInfo.FileDigest | Should -Be 'DIGEST'
        ($m | ConvertTo-Json -Depth 5) | Should -Not -BeLike '*SECRETKEY*'
    }

    It 'returns the key material when it is asked for' {
        $p = New-Zip -Name 'keys.intunewin' -Entries @{ 'IntuneWinPackage/Metadata/Detection.xml' = (& $script:Detection) }
        $m = Get-IntunewinMetadata -Path $p -IncludeIntunewinKeyMaterial
        $m.EncryptionInfo.EncryptionKey | Should -Be 'SECRETKEY'
        $m.EncryptionInfo.MacKey | Should -Be 'SECRETMAC'
    }

    It 'does not pass key material through the dispatcher unless asked' {
        $p = New-Zip -Name 'dispatch.intunewin' -Entries @{ 'IntuneWinPackage/Metadata/Detection.xml' = (& $script:Detection) }
        (Get-PackageMetadataFor -Path $p -InstallerType 'Intunewin').EncryptionInfo.EncryptionKey | Should -Be '<redacted>'
        (Get-PackageMetadataFor -Path $p -InstallerType 'Intunewin' -IncludeIntunewinKeyMaterial).EncryptionInfo.EncryptionKey | Should -Be 'SECRETKEY'
    }

    It 'describes an MSI source with execution context <Context> as "<Arch>"' -ForEach @(
        @{ Context = 'System'; Arch = 'Per-machine (MSI)' }
        @{ Context = 'User'; Arch = 'Per-user (MSI)' }
        @{ Context = 'Any'; Arch = 'Per-machine or per-user (MSI)' }
        @{ Context = 'Odd'; Arch = 'N/A (see embedded setup file)' }
    ) {
        $p = New-Zip -Name ('msi-' + [guid]::NewGuid().ToString('N') + '.intunewin') -Entries @{ 'IntuneWinPackage/Metadata/Detection.xml' = (& $script:Detection -Msi '2.0.0' -Context $Context) }
        $m = Get-IntunewinMetadata -Path $p
        $m.IsMsiSource | Should -BeTrue
        $m.Architecture | Should -Be $Arch
        $m.DisplayVersion | Should -Be '2.0.0'
        $m.Publisher | Should -Be 'Acme Inc'
        $m.SilentInstallCommand | Should -BeLike 'msiexec.exe /i*'
        $m.SilentUninstallCommand | Should -Be 'msiexec.exe /x "{AAAAAAAA-0000-0000-0000-000000000001}" /qn /norestart'
    }

    It 'describes a package without MsiInfo and without encryption info' {
        $p = New-Zip -Name 'nomsi.intunewin' -Entries @{ 'IntuneWinPackage/Metadata/Detection.xml' = (& $script:Detection -Enc '') }
        $m = Get-IntunewinMetadata -Path $p
        $m.IsMsiSource | Should -BeFalse
        @($m.EncryptionInfo.Keys).Count | Should -Be 0
        $m.SilentUninstallCommand | Should -BeLike 'N/A*'
        $m.DisplayName | Should -Be 'Acme'
    }

    It 'returns nothing for <Case>' -ForEach @(
        @{ Case = 'a file that is not a zip'; Entries = $null }
        @{ Case = 'a zip without Detection.xml'; Entries = @{ 'x.txt' = 'x' } }
        @{ Case = 'Detection.xml that is not XML'; Entries = @{ 'IntuneWinPackage/Metadata/Detection.xml' = '<ApplicationInfo' } }
        @{ Case = 'Detection.xml without the ApplicationInfo root'; Entries = @{ 'IntuneWinPackage/Metadata/Detection.xml' = '<Other/>' } }
    ) {
        $path = if ($null -eq $Entries) { $f = Join-Path $script:Work ('bad-' + [guid]::NewGuid().ToString('N') + '.intunewin'); [System.IO.File]::WriteAllText($f, 'not a zip'); $f } else { New-Zip -Name ('bad-' + [guid]::NewGuid().ToString('N') + '.intunewin') -Entries $Entries }
        Get-IntunewinMetadata -Path $path | Should -BeNullOrEmpty
    }
}

Describe 'Get-InstallerType for archives' {
    It 'names <Expected> for <Name>' -ForEach @(
        @{ Name = 'a.nupkg'; Entries = @{ 'a.nuspec' = 'x'; 'tools/chocolateyInstall.ps1' = 'x' }; Expected = 'Chocolatey' }
        @{ Name = 'b.nupkg'; Entries = @{ 'b.nuspec' = 'x' }; Expected = 'NuGet' }
        @{ Name = 'c.intunewin'; Entries = @{ 'IntuneWinPackage/Metadata/Detection.xml' = 'x' }; Expected = 'Intunewin' }
        @{ Name = 'd.msixbundle'; Entries = @{ 'AppxMetadata/AppxBundleManifest.xml' = 'x' }; Expected = 'MsixBundle' }
        @{ Name = 'e.appxbundle'; Entries = @{ 'AppxMetadata/AppxBundleManifest.xml' = 'x' }; Expected = 'MsixBundle' }
        @{ Name = 'f.msix'; Entries = @{ 'AppxManifest.xml' = 'x' }; Expected = 'Msix' }
        @{ Name = 'g.appx'; Entries = @{ 'AppxManifest.xml' = 'x' }; Expected = 'Msix' }
        @{ Name = 'h.zip'; Entries = @{ 'Invoke-AppDeployToolkit.ps1' = 'x' }; Expected = 'PsadtV4' }
        @{ Name = 'i.zip'; Entries = @{ 'PSAppDeployToolkit.psd1' = 'x' }; Expected = 'PsadtV4' }
        @{ Name = 'j.zip'; Entries = @{ 'Deploy-Application.ps1' = 'x'; 'AppDeployToolkit/AppDeployToolkitMain.ps1' = 'x' }; Expected = 'PsadtV3' }
        @{ Name = 'k.zip'; Entries = @{ 'Deploy-Application.ps1' = 'x'; 'Invoke-AppDeployToolkit.ps1' = 'x' }; Expected = 'PsadtV4' }
        @{ Name = 'l.msi'; Entries = @{ 'x' = 'x' }; Expected = 'MSI' }
        @{ Name = 'm.MSP'; Entries = @{ 'x' = 'x' }; Expected = 'MSP' }
    ) {
        $p = New-Zip -Name $Name -Entries $Entries
        Get-InstallerType -Path $p | Should -Be $Expected
    }

    It 'does not name an archive format for an extension with the wrong content: <Name>' -ForEach @(
        @{ Name = 'wrong1.intunewin' }, @{ Name = 'wrong2.msix' }, @{ Name = 'wrong3.msixbundle' }, @{ Name = 'wrong4.nupkg' }, @{ Name = 'wrong5.zip' }
    ) {
        $p = New-Zip -Name $Name -Entries @{ 'readme.txt' = 'nothing here' }
        Get-InstallerType -Path $p | Should -Be 'Unknown'
    }
}

Describe 'Get-PackageMetadataFor' {
    It 'returns nothing for a type without an extractor' {
        Get-PackageMetadataFor -Path 'C:\x.exe' -InstallerType 'Unknown' | Should -BeNullOrEmpty
        Get-PackageMetadataFor -Path 'C:\x.msi' -InstallerType 'MSI' | Should -BeNullOrEmpty
    }

    It 'routes <Type> to its extractor' -ForEach @(
        @{ Type = 'Chocolatey'; Command = 'Get-ChocolateyMetadata' }, @{ Type = 'NuGet'; Command = 'Get-ChocolateyMetadata' }
        @{ Type = 'Msix'; Command = 'Get-MsixManifest' }, @{ Type = 'MsixBundle'; Command = 'Get-MsixManifest' }
        @{ Type = 'PsadtV3'; Command = 'Get-PsadtMetadata' }, @{ Type = 'PsadtV4'; Command = 'Get-PsadtMetadata' }
        @{ Type = 'Squirrel'; Command = 'Get-SquirrelMetadata' }, @{ Type = 'Velopack'; Command = 'Get-VelopackMetadata' }
        @{ Type = 'WixBurn'; Command = 'Get-WixBurnMetadata' }, @{ Type = 'MSP'; Command = 'Get-MspMetadata' }
        @{ Type = 'NSIS'; Command = 'Get-NsisMetadata' }, @{ Type = 'InnoSetup'; Command = 'Get-InnoSetupMetadata' }
    ) {
        Mock -ModuleName InstallerAnalysisCommon -CommandName $Command { 'routed' }
        Get-PackageMetadataFor -Path 'C:\x' -InstallerType $Type | Should -Be 'routed'
        Should -Invoke -ModuleName InstallerAnalysisCommon -CommandName $Command -Times 1 -Exactly
    }
}
