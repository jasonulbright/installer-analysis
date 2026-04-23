#Requires -Modules Pester

<#
.SYNOPSIS
    Pester 5.x tests for InstallerAnalysisCommon module.

.DESCRIPTION
    Tests pure-logic functions: logging, PE architecture, installer type detection,
    silent switch database, template expansion, string analysis, export.
    Does NOT require real installer files or admin elevation.

.EXAMPLE
    Invoke-Pester .\InstallerAnalysisCommon.Tests.ps1
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification='Pester cannot trace BeforeAll -> It scriptblock reads; shared setup variables are consumed in It blocks but PSSA sees them as write-only.')]
param()

BeforeAll {
    Import-Module "$PSScriptRoot\InstallerAnalysisCommon.psd1" -Force -DisableNameChecking
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    # Shared ZIP-builder helper for synthetic package fixtures (Chocolatey, Intunewin,
    # MSIX, PSADT). Creates a new ZIP at $Path with entries from $Entries @{ path = content }.
    # Binary entries can be passed as byte[] values; strings are UTF-8 encoded.
    function script:New-TestZipFile {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][hashtable]$Entries
        )
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
        $archive = [System.IO.Compression.ZipFile]::Open($Path, 'Create')
        try {
            foreach ($entryName in $Entries.Keys) {
                $entry = $archive.CreateEntry($entryName)
                $stream = $entry.Open()
                try {
                    $val = $Entries[$entryName]
                    if ($val -is [byte[]]) {
                        $stream.Write($val, 0, $val.Length)
                    } else {
                        $writer = New-Object System.IO.StreamWriter($stream, [System.Text.UTF8Encoding]::new($false))
                        try { $writer.Write([string]$val) } finally { $writer.Dispose() }
                    }
                } finally {
                    $stream.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    }
}

# ============================================================================
# Write-Log / Initialize-Logging
# ============================================================================

Describe 'Write-Log' {
    It 'writes formatted INFO message to log file' {
        $logFile = Join-Path $TestDrive 'test.log'
        Initialize-Logging -LogPath $logFile
        Write-Log 'Hello' -Quiet
        Get-Content -LiteralPath $logFile -Raw | Should -Match '\[INFO \] Hello'
    }

    It 'tags WARN messages correctly' {
        $logFile = Join-Path $TestDrive 'warn.log'
        Initialize-Logging -LogPath $logFile
        Write-Log 'Warning' -Level WARN -Quiet
        Get-Content -LiteralPath $logFile -Raw | Should -Match '\[WARN \] Warning'
    }

    It 'tags ERROR messages correctly' {
        $logFile = Join-Path $TestDrive 'err.log'
        Initialize-Logging -LogPath $logFile
        Write-Log 'Fail' -Level ERROR -Quiet
        Get-Content -LiteralPath $logFile -Raw | Should -Match '\[ERROR\] Fail'
    }

    It 'accepts empty string' {
        $logFile = Join-Path $TestDrive 'empty.log'
        Initialize-Logging -LogPath $logFile
        { Write-Log '' -Quiet } | Should -Not -Throw
    }
}

Describe 'Initialize-Logging' {
    It 'creates log file with header' {
        $logFile = Join-Path $TestDrive 'init.log'
        Initialize-Logging -LogPath $logFile
        Test-Path -LiteralPath $logFile | Should -BeTrue
        Get-Content -LiteralPath $logFile -Raw | Should -Match '=== Log initialized ==='
    }

    It 'creates parent directories' {
        $logFile = Join-Path $TestDrive 'sub\dir\deep.log'
        Initialize-Logging -LogPath $logFile
        Test-Path -LiteralPath $logFile | Should -BeTrue
    }
}

# ============================================================================
# Get-PeArchitecture
# ============================================================================

Describe 'Get-PeArchitecture' {
    It 'detects x64 from a real EXE' {
        # Use PowerShell's own exe as a known x64 binary
        $psExe = (Get-Process -Id $PID).Path
        $arch = Get-PeArchitecture -Path $psExe
        $arch | Should -BeIn @('x64', 'x86')  # Either is valid depending on PS version
    }

    It 'returns Not a PE for non-PE files' {
        $txtFile = Join-Path $TestDrive 'notpe.txt'
        Set-Content -LiteralPath $txtFile -Value 'hello world'
        $arch = Get-PeArchitecture -Path $txtFile
        $arch | Should -Be 'Not a PE'
    }
}

# ============================================================================
# Get-InstallerType
# ============================================================================

Describe 'Get-InstallerType' {
    It 'detects MSI by extension' {
        $msiFile = Join-Path $TestDrive 'test.msi'
        Set-Content -LiteralPath $msiFile -Value 'fake msi content'
        $type = Get-InstallerType -Path $msiFile
        $type | Should -Be 'MSI'
    }

    It 'returns Unknown for plain text file' {
        $txtFile = Join-Path $TestDrive 'plain.exe'
        Set-Content -LiteralPath $txtFile -Value 'just some text, not an installer'
        Initialize-Logging -LogPath (Join-Path $TestDrive 'type.log')
        $type = Get-InstallerType -Path $txtFile
        $type | Should -Be 'Unknown'
    }

    It 'detects NSIS from NullsoftInst marker' {
        $nsisFile = Join-Path $TestDrive 'nsis.exe'
        $bytes = New-Object byte[] 1024
        # MZ header
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        # Write NullsoftInst marker at offset 100
        $marker = [System.Text.Encoding]::ASCII.GetBytes('NullsoftInst')
        [Array]::Copy($marker, 0, $bytes, 100, $marker.Length)
        [System.IO.File]::WriteAllBytes($nsisFile, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'nsis.log')
        $type = Get-InstallerType -Path $nsisFile
        $type | Should -Be 'NSIS'
    }

    It 'detects Inno Setup from marker string' {
        $innoFile = Join-Path $TestDrive 'inno.exe'
        $bytes = New-Object byte[] 1024
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $marker = [System.Text.Encoding]::ASCII.GetBytes('Inno Setup')
        [Array]::Copy($marker, 0, $bytes, 200, $marker.Length)
        [System.IO.File]::WriteAllBytes($innoFile, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'inno.log')
        $type = Get-InstallerType -Path $innoFile
        $type | Should -Be 'InnoSetup'
    }

    It 'detects WiX Burn from WixBundleManifest marker' {
        $wixFile = Join-Path $TestDrive 'wix.exe'
        $bytes = New-Object byte[] 1024
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $marker = [System.Text.Encoding]::ASCII.GetBytes('WixBundleManifest')
        [Array]::Copy($marker, 0, $bytes, 300, $marker.Length)
        [System.IO.File]::WriteAllBytes($wixFile, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'wix.log')
        $type = Get-InstallerType -Path $wixFile
        $type | Should -Be 'WixBurn'
    }

    It 'detects InstallShield from marker' {
        $isFile = Join-Path $TestDrive 'is.exe'
        $bytes = New-Object byte[] 1024
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $marker = [System.Text.Encoding]::ASCII.GetBytes('InstallShield')
        [Array]::Copy($marker, 0, $bytes, 400, $marker.Length)
        [System.IO.File]::WriteAllBytes($isFile, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'is.log')
        $type = Get-InstallerType -Path $isFile
        $type | Should -Be 'InstallShield'
    }

    It 'detects BitRock from marker' {
        $brFile = Join-Path $TestDrive 'bitrock.exe'
        $bytes = New-Object byte[] 2048
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $marker = [System.Text.Encoding]::ASCII.GetBytes('BitRock')
        [Array]::Copy($marker, 0, $bytes, 900, $marker.Length)
        [System.IO.File]::WriteAllBytes($brFile, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'bitrock.log')
        $type = Get-InstallerType -Path $brFile
        $type | Should -Be 'BitRock'
    }

    It 'detects Inno Setup past the 512KB threshold (up to 4MB scan window)' {
        # Modern Inno Setup installers (GIMP, Audacity, Git, Positron) embed
        # the "Inno Setup" marker between 512KB and 1MB into the file. Verify
        # the scan window catches it by placing the marker at offset ~700KB.
        $innoFile = Join-Path $TestDrive 'inno-large.exe'
        $size = 1MB
        $bytes = New-Object byte[] $size
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $marker = [System.Text.Encoding]::ASCII.GetBytes('Inno Setup')
        [Array]::Copy($marker, 0, $bytes, 700KB, $marker.Length)
        [System.IO.File]::WriteAllBytes($innoFile, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'inno-large.log')
        $type = Get-InstallerType -Path $innoFile
        $type | Should -Be 'InnoSetup'
    }
}

# ============================================================================
# ZIP helpers (Test-IsZipFile / Test-ZipEntryExists / Get-ZipEntryText /
#              Get-ZipRootEntryByPattern)
# ============================================================================

Describe 'Test-IsZipFile' {
    It 'returns true for a real ZIP' {
        $zip = Join-Path $TestDrive 'ok.zip'
        script:New-TestZipFile -Path $zip -Entries @{ 'hello.txt' = 'hi' }
        Test-IsZipFile -Path $zip | Should -BeTrue
    }

    It 'returns false for a plain text file' {
        $txt = Join-Path $TestDrive 'notzip.txt'
        Set-Content -LiteralPath $txt -Value 'just text'
        Test-IsZipFile -Path $txt | Should -BeFalse
    }
}

Describe 'Test-ZipEntryExists' {
    It 'finds an entry by exact name' {
        $zip = Join-Path $TestDrive 'entries.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'root.xml' = '<r/>'
            'nested/child.txt' = 'x'
        }
        Test-ZipEntryExists -Path $zip -EntryName 'root.xml' | Should -BeTrue
        Test-ZipEntryExists -Path $zip -EntryName 'nested/child.txt' | Should -BeTrue
        Test-ZipEntryExists -Path $zip -EntryName 'missing.xml' | Should -BeFalse
    }

    It 'finds an entry by wildcard pattern' {
        $zip = Join-Path $TestDrive 'patterns.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'tools/chocolateyInstall.ps1' = '# install'
            'mypkg.nuspec' = '<package/>'
        }
        Test-ZipEntryExists -Path $zip -Pattern 'chocolatey*.ps1' | Should -BeTrue
        Test-ZipEntryExists -Path $zip -Pattern '*.nuspec' | Should -BeTrue
        Test-ZipEntryExists -Path $zip -Pattern '*.exe' | Should -BeFalse
    }

    It 'returns false for a non-zip file without throwing' {
        $txt = Join-Path $TestDrive 'plain.txt'
        Set-Content -LiteralPath $txt -Value 'content'
        { Test-ZipEntryExists -Path $txt -EntryName 'anything' } | Should -Not -Throw
        Test-ZipEntryExists -Path $txt -EntryName 'anything' | Should -BeFalse
    }
}

Describe 'Get-ZipEntryText' {
    It 'returns the UTF-8 text of a ZIP entry' {
        $zip = Join-Path $TestDrive 'text.zip'
        script:New-TestZipFile -Path $zip -Entries @{ 'hello.txt' = 'Hello, world!' }
        Get-ZipEntryText -Path $zip -EntryName 'hello.txt' | Should -Be 'Hello, world!'
    }

    It 'returns $null for a missing entry' {
        $zip = Join-Path $TestDrive 'empty.zip'
        script:New-TestZipFile -Path $zip -Entries @{ 'real.txt' = 'x' }
        Get-ZipEntryText -Path $zip -EntryName 'missing.txt' | Should -BeNullOrEmpty
    }
}

Describe 'Get-ZipRootEntryByPattern' {
    It 'finds a root-level entry by wildcard' {
        $zip = Join-Path $TestDrive 'root.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'myapp.nuspec' = '<package/>'
            'tools/other.nuspec' = '<package/>'
        }
        Get-ZipRootEntryByPattern -Path $zip -Pattern '*.nuspec' | Should -Be 'myapp.nuspec'
    }

    It 'ignores nested matches' {
        $zip = Join-Path $TestDrive 'nested.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'tools/chocolateyInstall.ps1' = '# install'
        }
        Get-ZipRootEntryByPattern -Path $zip -Pattern '*.ps1' | Should -BeNullOrEmpty
    }
}

# ============================================================================
# Chocolatey / NuGet detection + metadata
# ============================================================================

Describe 'Get-InstallerType detects Chocolatey' {
    It 'returns Chocolatey for a .nupkg with chocolateyInstall.ps1' {
        $nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>myapp</id>
    <version>1.2.3</version>
    <authors>ACME</authors>
    <description>Test package</description>
  </metadata>
</package>
"@
        $pkg = Join-Path $TestDrive 'myapp.1.2.3.nupkg'
        script:New-TestZipFile -Path $pkg -Entries @{
            'myapp.nuspec' = $nuspec
            'tools/chocolateyInstall.ps1' = "# choco install logic`nWrite-Host 'installing'"
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'choco.log')
        Get-InstallerType -Path $pkg | Should -Be 'Chocolatey'
    }

    It 'returns NuGet for a .nupkg without chocolatey*.ps1' {
        $nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>libx</id>
    <version>2.0.0</version>
    <authors>MSFT</authors>
    <description>A library</description>
  </metadata>
</package>
"@
        $pkg = Join-Path $TestDrive 'libx.2.0.0.nupkg'
        script:New-TestZipFile -Path $pkg -Entries @{
            'libx.nuspec' = $nuspec
            'lib/net48/libx.dll' = [byte[]](0x4D, 0x5A, 0x90, 0x00)
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'nuget.log')
        Get-InstallerType -Path $pkg | Should -Be 'NuGet'
    }

    It 'does not misclassify a random .nupkg-named text file' {
        $fake = Join-Path $TestDrive 'fake.nupkg'
        Set-Content -LiteralPath $fake -Value 'not a zip'
        Initialize-Logging -LogPath (Join-Path $TestDrive 'fakenupkg.log')
        Get-InstallerType -Path $fake | Should -Be 'Unknown'
    }
}

Describe 'Get-ChocolateyMetadata' {
    It 'parses nuspec metadata from a Chocolatey package' {
        $nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>sample</id>
    <version>3.4.5</version>
    <title>Sample App</title>
    <authors>ACME Corp</authors>
    <owners>ACME</owners>
    <projectUrl>https://example.com/sample</projectUrl>
    <licenseUrl>https://example.com/license</licenseUrl>
    <description>A sample Chocolatey package for tests.</description>
    <tags>sample testing</tags>
  </metadata>
</package>
"@
        $pkg = Join-Path $TestDrive 'sample.3.4.5.nupkg'
        script:New-TestZipFile -Path $pkg -Entries @{
            'sample.nuspec' = $nuspec
            'tools/chocolateyInstall.ps1' = "# install"
            'tools/chocolateyUninstall.ps1' = "# uninstall"
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'chocometa.log')
        $meta = Get-ChocolateyMetadata -Path $pkg
        $meta | Should -Not -BeNullOrEmpty
        $meta.InstallerType | Should -Be 'Chocolatey'
        $meta.PackageId | Should -Be 'sample'
        $meta.DisplayVersion | Should -Be '3.4.5'
        $meta.DisplayName | Should -Be 'Sample App'
        $meta.Publisher | Should -Be 'ACME Corp'
        $meta.IsChocolatey | Should -BeTrue
        $meta.SilentInstallCommand | Should -Match 'choco install sample'
        $meta.SilentUninstallCommand | Should -Match 'choco uninstall sample'
        $meta.Nuspec['description'] | Should -Match 'sample Chocolatey package'
    }

    It 'classifies a plain NuGet package as NuGet' {
        $nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>plain</id>
    <version>9.9.9</version>
    <authors>Author</authors>
    <description>Plain NuGet.</description>
  </metadata>
</package>
"@
        $pkg = Join-Path $TestDrive 'plain.9.9.9.nupkg'
        script:New-TestZipFile -Path $pkg -Entries @{ 'plain.nuspec' = $nuspec }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'plainnuget.log')
        $meta = Get-ChocolateyMetadata -Path $pkg
        $meta.InstallerType | Should -Be 'NuGet'
        $meta.IsChocolatey | Should -BeFalse
        $meta.SilentInstallCommand | Should -Match 'nuget install plain'
    }

    It 'falls back to id when title is absent' {
        $nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>notitle</id>
    <version>1.0.0</version>
    <authors>x</authors>
    <description>no title here</description>
  </metadata>
</package>
"@
        $pkg = Join-Path $TestDrive 'notitle.1.0.0.nupkg'
        script:New-TestZipFile -Path $pkg -Entries @{
            'notitle.nuspec' = $nuspec
            'tools/chocolateyInstall.ps1' = '# x'
        }
        $meta = Get-ChocolateyMetadata -Path $pkg
        $meta.DisplayName | Should -Be 'notitle'
    }

    It 'returns $null for a non-zip input' {
        $txt = Join-Path $TestDrive 'not.nupkg'
        Set-Content -LiteralPath $txt -Value 'text'
        Get-ChocolateyMetadata -Path $txt | Should -BeNullOrEmpty
    }
}

Describe 'Get-InstallerType detects Intunewin' {
    It 'returns Intunewin for a .intunewin package with Metadata/Detection.xml' {
        $detection = @"
<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="1.8.6">
  <Name>TestApp</Name>
  <UnencryptedContentSize>12345</UnencryptedContentSize>
  <FileName>IntunePackage.intunewin</FileName>
  <SetupFile>setup.exe</SetupFile>
  <EncryptionInfo>
    <EncryptionKey>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</EncryptionKey>
    <MacKey>BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</MacKey>
    <InitializationVector>CCCCCCCCCCCCCCCCCCCCCCCC</InitializationVector>
    <Mac>DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=</Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest>EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=</FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>
"@
        $pkg = Join-Path $TestDrive 'TestApp.intunewin'
        script:New-TestZipFile -Path $pkg -Entries @{
            '[Content_Types].xml' = '<Types/>'
            'IntuneWinPackage/Metadata/Detection.xml' = $detection
            'IntuneWinPackage/Contents/IntunePackage.intunewin' = [byte[]](1, 2, 3, 4)
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'intunewin.log')
        Get-InstallerType -Path $pkg | Should -Be 'Intunewin'
    }

    It 'does not misclassify a .intunewin-named non-zip file' {
        $fake = Join-Path $TestDrive 'fake.intunewin'
        Set-Content -LiteralPath $fake -Value 'text masquerading as intunewin'
        Get-InstallerType -Path $fake | Should -Be 'Unknown'
    }

    It 'does not match a .intunewin-named zip that lacks the Detection.xml path' {
        $miss = Join-Path $TestDrive 'missing-meta.intunewin'
        script:New-TestZipFile -Path $miss -Entries @{ 'hello.txt' = 'hi' }
        Get-InstallerType -Path $miss | Should -Not -Be 'Intunewin'
    }
}

Describe 'Get-IntunewinMetadata' {
    It 'parses EXE-source Detection.xml without MsiInfo' {
        $detection = @"
<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="1.8.6">
  <Name>ExeApp</Name>
  <UnencryptedContentSize>99999</UnencryptedContentSize>
  <FileName>IntunePackage.intunewin</FileName>
  <SetupFile>exeinstaller.exe</SetupFile>
  <EncryptionInfo>
    <EncryptionKey>aaa=</EncryptionKey>
    <MacKey>bbb=</MacKey>
    <InitializationVector>ccc=</InitializationVector>
    <Mac>ddd=</Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest>eee=</FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>
"@
        $pkg = Join-Path $TestDrive 'ExeApp.intunewin'
        script:New-TestZipFile -Path $pkg -Entries @{
            'IntuneWinPackage/Metadata/Detection.xml' = $detection
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'exe.log')
        $meta = Get-IntunewinMetadata -Path $pkg
        $meta | Should -Not -BeNullOrEmpty
        $meta.InstallerType | Should -Be 'Intunewin'
        $meta.ToolVersion | Should -Be '1.8.6'
        $meta.Name | Should -Be 'ExeApp'
        $meta.DisplayName | Should -Be 'ExeApp'
        $meta.SetupFile | Should -Be 'exeinstaller.exe'
        $meta.IsMsiSource | Should -BeFalse
        $meta.MsiInfo | Should -BeNullOrEmpty
        $meta.EncryptionInfo['FileDigestAlgorithm'] | Should -Be 'SHA256'
        $meta.SilentInstallCommand | Should -Match 'ExtractedSetup'
        $meta.SilentUninstallCommand | Should -Match 'Intune portal'
    }

    It 'parses MSI-source Detection.xml with MsiInfo' {
        $detection = @"
<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="1.8.6">
  <Name>MsiApp</Name>
  <UnencryptedContentSize>500000</UnencryptedContentSize>
  <FileName>IntunePackage.intunewin</FileName>
  <SetupFile>installer.msi</SetupFile>
  <EncryptionInfo>
    <EncryptionKey>aaa=</EncryptionKey>
    <MacKey>bbb=</MacKey>
    <InitializationVector>ccc=</InitializationVector>
    <Mac>ddd=</Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest>eee=</FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
  <MsiInfo>
    <MsiProductCode>{11111111-1111-1111-1111-111111111111}</MsiProductCode>
    <MsiProductVersion>4.5.6</MsiProductVersion>
    <MsiUpgradeCode>{22222222-2222-2222-2222-222222222222}</MsiUpgradeCode>
    <MsiExecutionContext>System</MsiExecutionContext>
    <MsiRequiresLogon>false</MsiRequiresLogon>
    <MsiRequiresReboot>false</MsiRequiresReboot>
    <MsiIsMachineInstall>true</MsiIsMachineInstall>
    <MsiIsUserInstall>false</MsiIsUserInstall>
    <MsiPackageCode>{33333333-3333-3333-3333-333333333333}</MsiPackageCode>
    <MsiPublisher>Contoso Inc.</MsiPublisher>
  </MsiInfo>
</ApplicationInfo>
"@
        $pkg = Join-Path $TestDrive 'MsiApp.intunewin'
        script:New-TestZipFile -Path $pkg -Entries @{
            'IntuneWinPackage/Metadata/Detection.xml' = $detection
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'msi.log')
        $meta = Get-IntunewinMetadata -Path $pkg
        $meta.IsMsiSource | Should -BeTrue
        $meta.DisplayVersion | Should -Be '4.5.6'
        $meta.Publisher | Should -Be 'Contoso Inc.'
        $meta.ProductCodeOrEquivalent | Should -Be '{11111111-1111-1111-1111-111111111111}'
        $meta.Architecture | Should -Match 'Per-machine'
        $meta.MsiInfo['MsiUpgradeCode'] | Should -Be '{22222222-2222-2222-2222-222222222222}'
        $meta.SilentUninstallCommand | Should -Match '{11111111-1111-1111-1111-111111111111}'
    }

    It 'returns $null for a non-zip input' {
        $txt = Join-Path $TestDrive 'not.intunewin'
        Set-Content -LiteralPath $txt -Value 'not a zip'
        Get-IntunewinMetadata -Path $txt | Should -BeNullOrEmpty
    }

    It 'returns $null when Detection.xml is missing' {
        $pkg = Join-Path $TestDrive 'no-detection.intunewin'
        script:New-TestZipFile -Path $pkg -Entries @{ 'other.txt' = 'x' }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'no-det.log')
        Get-IntunewinMetadata -Path $pkg | Should -BeNullOrEmpty
    }
}

Describe 'Get-InstallerType detects MSIX / APPX / bundles' {
    It 'returns Msix for a .msix with AppxManifest.xml at root' {
        $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Contoso.SampleApp" Publisher="CN=Contoso" Version="1.2.3.0" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>Contoso Sample</DisplayName>
    <PublisherDisplayName>Contoso, Ltd.</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
  </Properties>
</Package>
"@
        $pkg = Join-Path $TestDrive 'contoso.msix'
        script:New-TestZipFile -Path $pkg -Entries @{
            'AppxManifest.xml' = $manifest
            '[Content_Types].xml' = '<Types/>'
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'msix.log')
        Get-InstallerType -Path $pkg | Should -Be 'Msix'
    }

    It 'returns Msix for a .appx with AppxManifest.xml at root' {
        $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="AppX" Publisher="CN=Pub" Version="0.1.0.0" ProcessorArchitecture="x86"/>
  <Properties>
    <DisplayName>AppX</DisplayName>
    <PublisherDisplayName>Pub</PublisherDisplayName>
  </Properties>
</Package>
"@
        $pkg = Join-Path $TestDrive 'something.appx'
        script:New-TestZipFile -Path $pkg -Entries @{ 'AppxManifest.xml' = $manifest }
        Get-InstallerType -Path $pkg | Should -Be 'Msix'
    }

    It 'returns MsixBundle for a .msixbundle with AppxBundleManifest.xml' {
        $bundleManifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="2.0">
  <Identity Name="Contoso.Bundle" Publisher="CN=Contoso" Version="9.8.7.0"/>
  <Packages>
    <Package Type="application" Version="9.8.7.0" Architecture="x64" FileName="Contoso.x64.msix"/>
    <Package Type="application" Version="9.8.7.0" Architecture="x86" FileName="Contoso.x86.msix"/>
  </Packages>
</Bundle>
"@
        $pkg = Join-Path $TestDrive 'contoso.msixbundle'
        script:New-TestZipFile -Path $pkg -Entries @{
            'AppxMetadata/AppxBundleManifest.xml' = $bundleManifest
        }
        Get-InstallerType -Path $pkg | Should -Be 'MsixBundle'
    }

    It 'does not misclassify a .msix-named non-zip' {
        $fake = Join-Path $TestDrive 'fake.msix'
        Set-Content -LiteralPath $fake -Value 'text masquerading as msix'
        Get-InstallerType -Path $fake | Should -Be 'Unknown'
    }
}

Describe 'Get-MsixManifest' {
    It 'parses a single-package MSIX' {
        $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Contoso.SampleApp" Publisher="CN=Contoso, O=Contoso Ltd., L=Redmond, S=WA, C=US" Version="1.2.3.0" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>Contoso Sample</DisplayName>
    <PublisherDisplayName>Contoso, Ltd.</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
    <Description>A sample app.</Description>
  </Properties>
</Package>
"@
        $pkg = Join-Path $TestDrive 'contoso.msix'
        script:New-TestZipFile -Path $pkg -Entries @{ 'AppxManifest.xml' = $manifest }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'msixmeta.log')
        $meta = Get-MsixManifest -Path $pkg
        $meta | Should -Not -BeNullOrEmpty
        $meta.InstallerType | Should -Be 'Msix'
        $meta.PackageKind | Should -Be 'SinglePackage'
        $meta.DisplayName | Should -Be 'Contoso Sample'
        $meta.DisplayVersion | Should -Be '1.2.3.0'
        $meta.Publisher | Should -Be 'Contoso, Ltd.'
        $meta.Architecture | Should -Be 'x64'
        $meta.Identity['Name'] | Should -Be 'Contoso.SampleApp'
        $meta.Identity['Publisher'] | Should -Match 'CN=Contoso'
        $meta.PropertiesDescription | Should -Be 'A sample app.'
    }

    It 'falls back to Identity.Name when Properties.DisplayName is absent' {
        $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Minimal.App" Publisher="CN=Min" Version="0.1.0.0" ProcessorArchitecture="neutral"/>
  <Properties/>
</Package>
"@
        $pkg = Join-Path $TestDrive 'min.msix'
        script:New-TestZipFile -Path $pkg -Entries @{ 'AppxManifest.xml' = $manifest }
        $meta = Get-MsixManifest -Path $pkg
        $meta.DisplayName | Should -Be 'Minimal.App'
        $meta.Architecture | Should -Be 'neutral'
    }

    It 'parses an MSIX bundle and enumerates inner packages' {
        $bundleManifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="2.0">
  <Identity Name="Contoso.Bundle" Publisher="CN=Contoso" Version="9.8.7.0"/>
  <Packages>
    <Package Type="application" Version="9.8.7.0" Architecture="x64" FileName="Contoso.x64.msix"/>
    <Package Type="application" Version="9.8.7.0" Architecture="x86" FileName="Contoso.x86.msix"/>
    <Package Type="resource" Version="9.8.7.0" ResourceId="en-us" FileName="Contoso.en-us.msix"/>
  </Packages>
</Bundle>
"@
        $pkg = Join-Path $TestDrive 'contoso.msixbundle'
        script:New-TestZipFile -Path $pkg -Entries @{
            'AppxMetadata/AppxBundleManifest.xml' = $bundleManifest
        }
        $meta = Get-MsixManifest -Path $pkg
        $meta.InstallerType | Should -Be 'MsixBundle'
        $meta.PackageKind | Should -Be 'Bundle'
        $meta.DisplayName | Should -Be 'Contoso.Bundle'
        $meta.DisplayVersion | Should -Be '9.8.7.0'
        $meta.BundledPackages.Count | Should -Be 3
        $meta.Architecture | Should -Match 'x64'
        $meta.Architecture | Should -Match 'x86'
        ($meta.BundledPackages | Where-Object Type -EQ 'resource').FileName | Should -Be 'Contoso.en-us.msix'
    }

    It 'returns $null for a non-zip input' {
        $txt = Join-Path $TestDrive 'not.msix'
        Set-Content -LiteralPath $txt -Value 'not a zip'
        Get-MsixManifest -Path $txt | Should -BeNullOrEmpty
    }

    It 'returns $null when neither manifest is present' {
        $pkg = Join-Path $TestDrive 'no-manifest.msix'
        script:New-TestZipFile -Path $pkg -Entries @{ 'other.txt' = 'x' }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'nomani.log')
        Get-MsixManifest -Path $pkg | Should -BeNullOrEmpty
    }
}

Describe 'Get-InstallerType detects PSADT (v3 + v4)' {
    It 'returns PsadtV3 for a ZIP with Deploy-Application.ps1 + AppDeployToolkitMain.ps1' {
        $main = "[Version]`$appDeployMainScriptVersion = [Version]'3.9.2'`r`n[String]`$appDeployMainScriptDate = '02/02/2023'"
        $deploy = "[String]`$appVendor = 'Contoso'`r`n[String]`$appName = 'Sample'`r`n[String]`$appVersion = '1.0.0'`r`n[String]`$appArch = 'x64'"
        $zip = Join-Path $TestDrive 'psadtv3.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'MyApp/Deploy-Application.ps1' = $deploy
            'MyApp/AppDeployToolkit/AppDeployToolkitMain.ps1' = $main
            'MyApp/AppDeployToolkit/AppDeployToolkitConfig.xml' = '<config/>'
            'MyApp/Files/setup.exe' = [byte[]](0x4D, 0x5A, 0x90, 0x00)
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'psv3.log')
        Get-InstallerType -Path $zip | Should -Be 'PsadtV3'
    }

    It 'returns PsadtV4 for a ZIP with PSAppDeployToolkit module + Invoke-AppDeployToolkit.ps1' {
        $psd1 = "@{`r`n    ModuleVersion = '4.0.4'`r`n    RootModule = 'PSAppDeployToolkit.psm1'`r`n}"
        $psm1 = "# PSAppDeployToolkit module"
        $invoke = "`$adtSession = @{`r`n    AppVendor = 'Contoso'`r`n    AppName = 'ModernApp'`r`n    AppVersion = '2.0.0'`r`n    AppArch = 'x64'`r`n}"
        $zip = Join-Path $TestDrive 'psadtv4.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'MyApp/Invoke-AppDeployToolkit.ps1' = $invoke
            'MyApp/PSAppDeployToolkit/PSAppDeployToolkit.psd1' = $psd1
            'MyApp/PSAppDeployToolkit/PSAppDeployToolkit.psm1' = $psm1
            'MyApp/Config/config.psd1' = '@{}'
        }
        Get-InstallerType -Path $zip | Should -Be 'PsadtV4'
    }

    It 'prefers v4 when both sentinels coexist (compat layout)' {
        $psd1 = "@{ ModuleVersion = '4.0.4' }"
        $zip = Join-Path $TestDrive 'psadt-compat.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'MyApp/Deploy-Application.ps1' = "[String]`$appName = 'Legacy'"
            'MyApp/AppDeployToolkit/AppDeployToolkitMain.ps1' = "[Version]`$appDeployMainScriptVersion = [Version]'3.9.0'"
            'MyApp/PSAppDeployToolkit/PSAppDeployToolkit.psd1' = $psd1
            'MyApp/Invoke-AppDeployToolkit.ps1' = '# v4 entry'
        }
        Get-InstallerType -Path $zip | Should -Be 'PsadtV4'
    }

    It 'does not return PSADT for an unrelated ZIP' {
        $zip = Join-Path $TestDrive 'random.zip'
        script:New-TestZipFile -Path $zip -Entries @{ 'hello.txt' = 'hi'; 'script.ps1' = '# not PSADT' }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'randzip.log')
        Get-InstallerType -Path $zip | Should -Be 'Unknown'
    }
}

Describe 'ConvertFrom-PsadtDeployApplication' {
    It 'parses v3 header variables' {
        $script = @"
[CmdletBinding()]
Param ()
[String]`$appVendor = 'Microsoft'
[String]`$appName = 'Office'
[String]`$appVersion = '16.0.1'
[String]`$appArch = 'x64'
[String]`$appLang = 'EN'
[String]`$appRevision = '01'
[String]`$appScriptVersion = '1.2.0'
[String]`$appScriptDate = '04/15/2026'
[String]`$appScriptAuthor = 'ACME'
"@
        $meta = ConvertFrom-PsadtDeployApplication -ScriptText $script
        $meta['AppVendor'] | Should -Be 'Microsoft'
        $meta['AppName'] | Should -Be 'Office'
        $meta['AppVersion'] | Should -Be '16.0.1'
        $meta['AppArch'] | Should -Be 'x64'
        $meta['AppLang'] | Should -Be 'EN'
        $meta['AppRevision'] | Should -Be '01'
        $meta['ScriptVersion'] | Should -Be '1.2.0'
        $meta['ScriptAuthor'] | Should -Be 'ACME'
    }

    It 'parses v4 hashtable-style fields' {
        $script = @"
`$adtSession = @{
    AppVendor = 'Contoso'
    AppName = 'ModernApp'
    AppVersion = '2.5.0'
    AppArch = 'x64'
    AppScriptVersion = '1.0.0'
    AppScriptAuthor = 'Contoso'
}
"@
        $meta = ConvertFrom-PsadtDeployApplication -ScriptText $script
        $meta['AppVendor'] | Should -Be 'Contoso'
        $meta['AppName'] | Should -Be 'ModernApp'
        $meta['AppVersion'] | Should -Be '2.5.0'
        $meta['ScriptVersion'] | Should -Be '1.0.0'
    }

    It 'leaves unknown fields blank without throwing' {
        $meta = ConvertFrom-PsadtDeployApplication -ScriptText '# comment only'
        $meta['AppName'] | Should -Be ''
        $meta['AppVersion'] | Should -Be ''
    }
}

Describe 'Get-PsadtMetadata' {
    It 'extracts toolkit version and app metadata from a v3 zip' {
        $main = @"
# PSAppDeployToolkit engine
[Version]`$appDeployMainScriptVersion = [Version]'3.9.2'
[String]`$appDeployMainScriptDate = '02/02/2023'
"@
        $deploy = @"
[String]`$appVendor = 'Contoso'
[String]`$appName = 'Sample'
[String]`$appVersion = '1.0.0'
[String]`$appArch = 'x64'
"@
        $zip = Join-Path $TestDrive 'psadt-v3-meta.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'app/Deploy-Application.ps1' = $deploy
            'app/AppDeployToolkit/AppDeployToolkitMain.ps1' = $main
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'psmetav3.log')
        $meta = Get-PsadtMetadata -Path $zip
        $meta | Should -Not -BeNullOrEmpty
        $meta.InstallerType | Should -Be 'PsadtV3'
        $meta.ToolkitVariant | Should -Be 'v3'
        $meta.ToolkitVersion | Should -Be '3.9.2'
        $meta.DisplayName | Should -Be 'Contoso Sample'
        $meta.DisplayVersion | Should -Be '1.0.0'
        $meta.Publisher | Should -Be 'Contoso'
        $meta.Architecture | Should -Be 'x64'
        $meta.SilentInstallCommand | Should -Match 'Deploy-Application.exe'
    }

    It 'extracts toolkit version from a v4 zip module manifest' {
        $psd1 = @"
@{
    ModuleVersion = '4.0.4'
    RootModule = 'PSAppDeployToolkit.psm1'
}
"@
        $invoke = @"
`$adtSession = @{
    AppVendor = 'Globex'
    AppName = 'Flux'
    AppVersion = '3.0.0'
    AppArch = 'ARM64'
}
"@
        $zip = Join-Path $TestDrive 'psadt-v4-meta.zip'
        script:New-TestZipFile -Path $zip -Entries @{
            'app/Invoke-AppDeployToolkit.ps1' = $invoke
            'app/PSAppDeployToolkit/PSAppDeployToolkit.psd1' = $psd1
            'app/PSAppDeployToolkit/PSAppDeployToolkit.psm1' = '# module body'
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'psmetav4.log')
        $meta = Get-PsadtMetadata -Path $zip
        $meta.InstallerType | Should -Be 'PsadtV4'
        $meta.ToolkitVariant | Should -Be 'v4'
        $meta.ToolkitVersion | Should -Be '4.0.4'
        $meta.DisplayName | Should -Be 'Globex Flux'
        $meta.DisplayVersion | Should -Be '3.0.0'
        $meta.Architecture | Should -Be 'ARM64'
        $meta.SilentInstallCommand | Should -Match 'Invoke-AppDeployToolkit.exe'
    }

    It 'returns $null for a non-PSADT zip' {
        $zip = Join-Path $TestDrive 'random2.zip'
        script:New-TestZipFile -Path $zip -Entries @{ 'plain.txt' = 'x' }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'psnon.log')
        Get-PsadtMetadata -Path $zip | Should -BeNullOrEmpty
    }
}

Describe 'Get-InstallerType detects Squirrel' {
    It 'returns Squirrel when two or more lifecycle markers are present' {
        $file = Join-Path $TestDrive 'ElectronSetup.exe'
        $bytes = New-Object byte[] 4096
        $bytes[0] = 0x4D; $bytes[1] = 0x5A    # MZ header so Get-PeArchitecture is happy
        # Inject two Squirrel markers starting at offset 256
        $marker1 = [System.Text.Encoding]::ASCII.GetBytes('squirrel-install')
        $marker2 = [System.Text.Encoding]::ASCII.GetBytes('SquirrelTemp')
        [Array]::Copy($marker1, 0, $bytes, 256, $marker1.Length)
        [Array]::Copy($marker2, 0, $bytes, 400, $marker2.Length)
        [System.IO.File]::WriteAllBytes($file, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'squirrel.log')
        Get-InstallerType -Path $file | Should -Be 'Squirrel'
    }

    It 'returns Squirrel for one lifecycle marker + Update.exe' {
        $file = Join-Path $TestDrive 'SqSingle.exe'
        $bytes = New-Object byte[] 4096
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $marker = [System.Text.Encoding]::ASCII.GetBytes('squirrel-uninstall')
        $updateExe = [System.Text.Encoding]::ASCII.GetBytes('Update.exe')
        [Array]::Copy($marker, 0, $bytes, 256, $marker.Length)
        [Array]::Copy($updateExe, 0, $bytes, 500, $updateExe.Length)
        [System.IO.File]::WriteAllBytes($file, $bytes)
        Get-InstallerType -Path $file | Should -Be 'Squirrel'
    }

    It 'does not return Squirrel on just Update.exe (too weak alone)' {
        $file = Join-Path $TestDrive 'UpdateOnly.exe'
        $bytes = New-Object byte[] 4096
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $updateExe = [System.Text.Encoding]::ASCII.GetBytes('Update.exe string only')
        [Array]::Copy($updateExe, 0, $bytes, 400, $updateExe.Length)
        [System.IO.File]::WriteAllBytes($file, $bytes)
        Get-InstallerType -Path $file | Should -Not -Be 'Squirrel'
    }

    It 'takes precedence over NSIS when both marker families coexist' {
        $file = Join-Path $TestDrive 'SquirrelOverNsis.exe'
        $bytes = New-Object byte[] 4096
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        # Both NSIS AND Squirrel markers -- Squirrel wins by order
        $nsis = [System.Text.Encoding]::ASCII.GetBytes('NullsoftInst')
        $s1 = [System.Text.Encoding]::ASCII.GetBytes('squirrel-install')
        $s2 = [System.Text.Encoding]::ASCII.GetBytes('squirrel-updated')
        [Array]::Copy($nsis, 0, $bytes, 200, $nsis.Length)
        [Array]::Copy($s1,   0, $bytes, 400, $s1.Length)
        [Array]::Copy($s2,   0, $bytes, 600, $s2.Length)
        [System.IO.File]::WriteAllBytes($file, $bytes)
        Get-InstallerType -Path $file | Should -Be 'Squirrel'
    }

    It 'does not falsely flag a plain NSIS binary as Squirrel' {
        $file = Join-Path $TestDrive 'PlainNSIS.exe'
        $bytes = New-Object byte[] 4096
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $nsis = [System.Text.Encoding]::ASCII.GetBytes('NullsoftInst')
        [Array]::Copy($nsis, 0, $bytes, 200, $nsis.Length)
        [System.IO.File]::WriteAllBytes($file, $bytes)
        Get-InstallerType -Path $file | Should -Be 'NSIS'
    }
}

Describe 'Get-SquirrelMetadata' {
    It 'extracts AppName and Version from embedded full.nupkg reference' {
        $file = Join-Path $TestDrive 'ElectronApp.exe'
        $bytes = New-Object byte[] 8192
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $payload = [System.Text.Encoding]::ASCII.GetBytes(
            'padding_squirrel-install_pad_SquirrelTemp_pad_MyElectronApp-2.5.1-full.nupkg_pad_Update.exe_end'
        )
        [Array]::Copy($payload, 0, $bytes, 256, $payload.Length)
        [System.IO.File]::WriteAllBytes($file, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'sqmeta.log')
        $meta = Get-SquirrelMetadata -Path $file
        $meta | Should -Not -BeNullOrEmpty
        $meta.InstallerType | Should -Be 'Squirrel'
        $meta.DisplayName | Should -Be 'MyElectronApp'
        $meta.DisplayVersion | Should -Be '2.5.1'
        $meta.MarkersFound.Count | Should -BeGreaterOrEqual 2
        $meta.NupkgReferences.Count | Should -Be 1
        $meta.NupkgReferences[0].Kind | Should -Be 'full'
        $meta.Confidence | Should -Be 'High'
        $meta.SilentInstallCommand | Should -Match '--silent'
    }

    It 'prefers full over delta when both appear' {
        $file = Join-Path $TestDrive 'FullAndDelta.exe'
        $bytes = New-Object byte[] 8192
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $payload = [System.Text.Encoding]::ASCII.GetBytes(
            'squirrel-install squirrel-updated MyApp-1.0.0-delta.nupkg MyApp-1.0.0-full.nupkg'
        )
        [Array]::Copy($payload, 0, $bytes, 256, $payload.Length)
        [System.IO.File]::WriteAllBytes($file, $bytes)
        $meta = Get-SquirrelMetadata -Path $file
        $preferredRef = $meta.NupkgReferences | Where-Object Kind -EQ 'full' | Select-Object -First 1
        $preferredRef | Should -Not -BeNullOrEmpty
        $meta.DisplayVersion | Should -Be '1.0.0'
    }

    It 'returns $null when no Squirrel markers exist' {
        $file = Join-Path $TestDrive 'NotSquirrel.exe'
        $bytes = New-Object byte[] 4096
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        [System.IO.File]::WriteAllBytes($file, $bytes)
        Initialize-Logging -LogPath (Join-Path $TestDrive 'notsq.log')
        Get-SquirrelMetadata -Path $file | Should -BeNullOrEmpty
    }

    It 'still extracts markers when no nupkg reference is present (lower confidence)' {
        $file = Join-Path $TestDrive 'MarkersOnly.exe'
        $bytes = New-Object byte[] 4096
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        $payload = [System.Text.Encoding]::ASCII.GetBytes('squirrel-install squirrel-updated Update.exe')
        [Array]::Copy($payload, 0, $bytes, 256, $payload.Length)
        [System.IO.File]::WriteAllBytes($file, $bytes)
        $meta = Get-SquirrelMetadata -Path $file
        $meta.InstallerType | Should -Be 'Squirrel'
        $meta.NupkgReferences.Count | Should -Be 0
        $meta.DisplayName | Should -Be 'MarkersOnly'
        $meta.DisplayVersion | Should -Be ''
    }
}

Describe 'Get-DeploymentFields with PackageMetadata' {
    It 'prefers PackageMetadata over MSI and FileVersionInfo' {
        $fi = [PSCustomObject]@{
            FileName = 'x.nupkg'; ProductName = 'File PN'; ProductVersion = '0.0.1'
            FileVersion = '0.0.1.0'; FileDescription = 'desc'; CompanyName = 'File Co'
        }
        $msi = @{ ProductName = 'MSI PN'; ProductVersion = '0.0.2'; Manufacturer = 'MSI Co' }
        $pkg = [PSCustomObject]@{
            DisplayName = 'Package PN'
            DisplayVersion = '5.0.0'
            Publisher = 'Package Co'
            SilentUninstallCommand = 'choco uninstall sample -y'
        }
        $result = Get-DeploymentFields -FileInfo $fi -MsiProperties $msi -PackageMetadata $pkg
        $result.DisplayName | Should -Be 'Package PN'
        $result.DisplayVersion | Should -Be '5.0.0'
        $result.Vendor | Should -Be 'Package Co'
        $result.SilentUninstallString | Should -Be 'choco uninstall sample -y'
    }
}

# ============================================================================
# Get-DeploymentFields
# ============================================================================

Describe 'Get-DeploymentFields' {
    BeforeAll {
        $baseFileInfo = [PSCustomObject]@{
            FileName = 'setup.exe'; ProductName = 'FileInfo App'; ProductVersion = '1.0.0'
            FileVersion = '1.0.0.0'; FileDescription = 'Setup Application'; CompanyName = 'FileInfo Corp'
        }
        $baseSwitches = [PSCustomObject]@{ Install = '"setup.exe" /S'; Uninstall = '"uninstall.exe" /S'; Notes = 'test' }
    }

    It 'prefers MSI properties over FileVersionInfo' {
        $msiProps = @{ ProductName = 'MSI App'; ProductVersion = '2.0.0'; Manufacturer = 'MSI Vendor' }
        $result = Get-DeploymentFields -FileInfo $baseFileInfo -MsiProperties $msiProps -Switches $baseSwitches
        $result.DisplayName | Should -Be 'MSI App'
        $result.DisplayVersion | Should -Be '2.0.0'
        $result.Vendor | Should -Be 'MSI Vendor'
    }

    It 'falls back to FileVersionInfo when no MSI properties' {
        $result = Get-DeploymentFields -FileInfo $baseFileInfo -Switches $baseSwitches
        $result.DisplayName | Should -Be 'FileInfo App'
        $result.DisplayVersion | Should -Be '1.0.0'
        $result.Vendor | Should -Be 'FileInfo Corp'
    }

    It 'returns SilentUninstallString from switches' {
        $result = Get-DeploymentFields -FileInfo $baseFileInfo -Switches $baseSwitches
        $result.SilentUninstallString | Should -Be '"uninstall.exe" /S'
    }

    It 'falls back to FileDescription when ProductName is empty' {
        $sparseInfo = [PSCustomObject]@{
            FileName = 'setup.exe'; ProductName = ''; ProductVersion = ''
            FileVersion = '3.0'; FileDescription = 'Fallback Desc'; CompanyName = ''
        }
        $result = Get-DeploymentFields -FileInfo $sparseInfo -Switches $baseSwitches
        $result.DisplayName | Should -Be 'Fallback Desc'
        $result.DisplayVersion | Should -Be '3.0'
    }

    It 'returns empty strings when no data available' {
        $emptyInfo = [PSCustomObject]@{
            FileName = 'x.exe'; ProductName = ''; ProductVersion = ''
            FileVersion = ''; FileDescription = ''; CompanyName = ''
        }
        $result = Get-DeploymentFields -FileInfo $emptyInfo
        $result.DisplayName | Should -Be ''
        $result.DisplayVersion | Should -Be ''
        $result.Vendor | Should -Be ''
        $result.SilentUninstallString | Should -Be ''
    }
}

# ============================================================================
# Get-SilentSwitchDatabase / Get-SilentSwitches
# ============================================================================

Describe 'Get-SilentSwitchDatabase' {
    It 'returns a hashtable with all known installer types' {
        $db = Get-SilentSwitchDatabase
        $db | Should -BeOfType [hashtable]
        $db.Keys | Should -Contain 'MSI'
        $db.Keys | Should -Contain 'NSIS'
        $db.Keys | Should -Contain 'InnoSetup'
        $db.Keys | Should -Contain 'InstallShield'
        $db.Keys | Should -Contain 'WixBurn'
        $db.Keys | Should -Contain 'Unknown'
    }

    It 'each entry has Install, Uninstall, and Notes' {
        $db = Get-SilentSwitchDatabase
        foreach ($key in $db.Keys) {
            $db[$key].Install | Should -Not -BeNullOrEmpty
            $db[$key].Uninstall | Should -Not -BeNullOrEmpty
            $db[$key].Notes | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Get-SilentSwitches' {
    It 'substitutes filename for MSI type' {
        $result = Get-SilentSwitches -InstallerType 'MSI' -FilePath 'C:\temp\app.msi' -MsiProperties @{ ProductCode = '{12345}' }
        $result.Install | Should -Match 'app\.msi'
        $result.Uninstall | Should -Match '\{12345\}'
    }

    It 'returns /S for NSIS' {
        $result = Get-SilentSwitches -InstallerType 'NSIS' -FilePath 'C:\temp\setup.exe'
        $result.Install | Should -Match '/S'
    }

    It 'returns /VERYSILENT for InnoSetup' {
        $result = Get-SilentSwitches -InstallerType 'InnoSetup' -FilePath 'C:\temp\setup.exe'
        $result.Install | Should -Match '/VERYSILENT'
    }

    It 'handles Unknown type gracefully' {
        $result = Get-SilentSwitches -InstallerType 'Unknown' -FilePath 'C:\temp\mystery.exe'
        $result | Should -Not -BeNullOrEmpty
        $result.InstallerType | Should -Be 'Unknown'
    }
}

# ============================================================================
# Get-InstallerFileInfo
# ============================================================================

Describe 'Get-InstallerFileInfo' {
    It 'returns file metadata for a real file' {
        $psExe = (Get-Process -Id $PID).Path
        Initialize-Logging -LogPath (Join-Path $TestDrive 'fi.log')
        $info = Get-InstallerFileInfo -Path $psExe
        $info.FileName | Should -Not -BeNullOrEmpty
        $info.FileSize | Should -BeGreaterThan 0
        $info.SHA256 | Should -Not -BeNullOrEmpty
        $info.Architecture | Should -Not -BeNullOrEmpty
    }
}

# ============================================================================
# Find-7ZipPath
# ============================================================================

Describe 'Find-7ZipPath' {
    It 'returns a path if 7-Zip is installed' {
        $path = Find-7ZipPath
        # May or may not be installed, but should not throw
        if ($path) { Test-Path -LiteralPath $path | Should -BeTrue }
    }

    It 'uses preferred path when provided' {
        $fakePath = Join-Path $TestDrive '7z.exe'
        Set-Content -LiteralPath $fakePath -Value 'fake'
        $result = Find-7ZipPath -PreferredPath $fakePath
        $result | Should -Be $fakePath
    }
}

# ============================================================================
# Get-BinaryStrings / Get-InterestingStrings
# ============================================================================

Describe 'Get-BinaryStrings' {
    It 'extracts printable strings from binary data' {
        $testFile = Join-Path $TestDrive 'strings.bin'
        $content = "AAAA`0`0`0`0LongEnoughString`0`0ShortAB`0`0AnotherLongString123`0`0"
        [System.IO.File]::WriteAllBytes($testFile, [System.Text.Encoding]::ASCII.GetBytes($content))
        $strings = Get-BinaryStrings -Path $testFile -MinLength 8
        $strings | Should -Contain 'LongEnoughString'
        $strings | Should -Contain 'AnotherLongString123'
        $strings | Should -Not -Contain 'ShortAB'
    }
}

Describe 'Get-InterestingStrings' {
    It 'categorizes strings correctly' {
        $testFile = Join-Path $TestDrive 'interesting.bin'
        $content = "PADDING_PAD_NullsoftInst_padding_https://example.com/download_pad_HKLM\SOFTWARE\Test\Key_pad_{12345678-1234-1234-1234-123456789012}_pad_1.2.3.4_endpad"
        [System.IO.File]::WriteAllBytes($testFile, [System.Text.Encoding]::ASCII.GetBytes($content))
        Initialize-Logging -LogPath (Join-Path $TestDrive 'str.log')
        $result = Get-InterestingStrings -Path $testFile
        $result | Should -BeOfType [hashtable]
        $result.InstallerMarkers.Count | Should -BeGreaterOrEqual 1
        $result.URLs.Count | Should -BeGreaterOrEqual 1
        $result.GUIDs.Count | Should -BeGreaterOrEqual 1
    }
}

# ============================================================================
# Export
# ============================================================================

Describe 'Export-AnalysisReport' {
    It 'writes CSV' {
        $dt = New-Object System.Data.DataTable
        [void]$dt.Columns.Add("Property", [string]); [void]$dt.Columns.Add("Value", [string])
        [void]$dt.Rows.Add("Name", "test.exe"); [void]$dt.Rows.Add("Type", "NSIS")
        $csvPath = Join-Path $TestDrive 'report.csv'
        Initialize-Logging -LogPath (Join-Path $TestDrive 'csv.log')
        Export-AnalysisReport -DataTable $dt -OutputPath $csvPath
        Test-Path -LiteralPath $csvPath | Should -BeTrue
        $rows = Import-Csv -LiteralPath $csvPath
        $rows.Count | Should -Be 2
    }
}

Describe 'Export-AnalysisHtml' {
    It 'writes HTML' {
        $dt = New-Object System.Data.DataTable
        [void]$dt.Columns.Add("Property", [string]); [void]$dt.Columns.Add("Value", [string])
        [void]$dt.Rows.Add("Name", "test.msi")
        $htmlPath = Join-Path $TestDrive 'report.html'
        Initialize-Logging -LogPath (Join-Path $TestDrive 'html.log')
        Export-AnalysisHtml -DataTable $dt -OutputPath $htmlPath -ReportTitle 'Test'
        Test-Path -LiteralPath $htmlPath | Should -BeTrue
        Get-Content -LiteralPath $htmlPath -Raw | Should -Match 'test\.msi'
    }
}

Describe 'New-AnalysisSummaryText' {
    It 'returns formatted summary' {
        $fileInfo = [PSCustomObject]@{
            FileName = 'setup.exe'; FileSizeFormatted = '10.5 MB'; SHA256 = 'abc123'
            FileVersion = '1.0.0'; ProductVersion = '1.0.0'; ProductName = 'My App'
            CompanyName = 'ACME'; Architecture = 'x64'
            SignatureStatus = 'Valid'; SignerSubject = 'CN=ACME Inc'
        }
        $switches = [PSCustomObject]@{ Install = '"setup.exe" /S'; Uninstall = '"uninstall.exe" /S'; Notes = '/S is case sensitive' }
        $summary = New-AnalysisSummaryText -FileInfo $fileInfo -InstallerType 'NSIS' -Switches $switches
        $summary | Should -Match 'setup\.exe'
        $summary | Should -Match 'NSIS'
        $summary | Should -Match '/S'
    }

    It 'includes MSI properties when provided' {
        $fileInfo = [PSCustomObject]@{
            FileName = 'app.msi'; FileSizeFormatted = '5 MB'; SHA256 = 'def456'
            FileVersion = '2.0'; ProductVersion = '2.0'; ProductName = 'App'
            CompanyName = 'Vendor'; Architecture = 'x64'
            SignatureStatus = 'Valid'; SignerSubject = ''
        }
        $switches = [PSCustomObject]@{ Install = 'msiexec /i'; Uninstall = 'msiexec /x'; Notes = '' }
        $msiProps = @{ ProductCode = '{GUID}'; UpgradeCode = '{UGUID}'; ProductVersion = '2.0.0'; Manufacturer = 'Vendor' }
        $summary = New-AnalysisSummaryText -FileInfo $fileInfo -InstallerType 'MSI' -Switches $switches -MsiProperties $msiProps
        $summary | Should -Match '\{GUID\}'
        $summary | Should -Match '\{UGUID\}'
    }

    It 'renders MSIX bundled-package list when PackageMetadata is a bundle' {
        $fi = [PSCustomObject]@{ FileName = 'x.msixbundle'; FileSizeFormatted = '20 MB'; SHA256='h'; Architecture='x64'; SignatureStatus='Unknown' }
        $sw = [PSCustomObject]@{ Install='Add-AppxPackage'; Uninstall='Remove-AppxPackage'; Notes='' }
        $pkg = [PSCustomObject]@{
            InstallerType = 'MsixBundle'
            Identity      = [ordered]@{ Name='Contoso.Bundle'; Publisher='CN=Contoso'; Version='9.8.7.0' }
            BundledPackages = @(
                [pscustomobject]@{ Type='application'; Version='9.8.7.0'; Architecture='x64';  ResourceId=''; FileName='Contoso.x64.msix' },
                [pscustomobject]@{ Type='application'; Version='9.8.7.0'; Architecture='x86';  ResourceId=''; FileName='Contoso.x86.msix' },
                [pscustomobject]@{ Type='resource';    Version='9.8.7.0'; Architecture='';     ResourceId='en-us'; FileName='Contoso.en-us.msix' }
            )
        }
        $summary = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'MsixBundle' -Switches $sw -PackageMetadata $pkg
        $summary | Should -Match 'Bundled Packages: 3'
        $summary | Should -Match 'Contoso\.x64\.msix'
        $summary | Should -Match 'Contoso\.x86\.msix'
        $summary | Should -Match 'Contoso\.en-us\.msix'
        $summary | Should -Match 'Identity:'
        $summary | Should -Match 'Contoso\.Bundle'
    }

    It 'renders all 9 PSADT AppMetadata fields for PsadtV4' {
        $fi = [PSCustomObject]@{ FileName = 'psadt.zip'; FileSizeFormatted = '8 MB'; SHA256='h'; Architecture='x64'; SignatureStatus='Unknown' }
        $sw = [PSCustomObject]@{ Install='Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode Silent'; Uninstall='Invoke-AppDeployToolkit.exe -DeploymentType Uninstall -DeployMode Silent'; Notes='' }
        $am = [ordered]@{
            AppVendor     = 'Contoso'
            AppName       = 'ModernApp'
            AppVersion    = '2.0.0'
            AppArch       = 'x64'
            AppLang       = 'EN'
            AppRevision   = '01'
            ScriptVersion = '1.0.0'
            ScriptDate    = '2026-04-22'
            ScriptAuthor  = 'Jason Ulbright'
        }
        $pkg = [PSCustomObject]@{
            InstallerType  = 'PsadtV4'
            ToolkitVariant = 'v4'
            ToolkitVersion = '4.2.0'
            AppMetadata    = $am
        }
        $summary = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'PsadtV4' -Switches $sw -PackageMetadata $pkg
        foreach ($field in 'AppVendor','AppName','AppVersion','AppArch','AppLang','AppRevision','ScriptVersion','ScriptDate','ScriptAuthor') {
            $summary | Should -Match $field
        }
        $summary | Should -Match '4\.2\.0'
        $summary | Should -Match 'ModernApp'
    }

    It 'renders nuspec Package Metadata for Chocolatey' {
        $fi = [PSCustomObject]@{ FileName = 'pkg.nupkg'; FileSizeFormatted = '1 MB'; SHA256='h'; Architecture='x64'; SignatureStatus='Unknown' }
        $sw = [PSCustomObject]@{ Install='choco install pkg -y'; Uninstall='choco uninstall pkg -y'; Notes='' }
        $pkg = [PSCustomObject]@{
            InstallerType  = 'Chocolatey'
            PackageId      = 'sample-app'
            DisplayVersion = '3.1.4'
            Publisher      = 'Contoso Authors'
            ProjectUrl     = 'https://example.com/sample-app'
            Tags           = 'admin tool'
            Description    = 'A short description of sample-app.'
        }
        $summary = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'Chocolatey' -Switches $sw -PackageMetadata $pkg
        $summary | Should -Match 'Id:\s+sample-app'
        $summary | Should -Match 'Project URL:\s+https://example\.com/sample-app'
    }

    It 'renders Intunewin Detection.xml metadata including MsiInfo' {
        $fi = [PSCustomObject]@{ FileName = 'app.intunewin'; FileSizeFormatted = '30 MB'; SHA256='h'; Architecture='x64'; SignatureStatus='Unknown' }
        $sw = [PSCustomObject]@{ Install='IME decrypts'; Uninstall=''; Notes='' }
        $pkg = [PSCustomObject]@{
            InstallerType   = 'Intunewin'
            DisplayName     = 'Sample'
            SetupFile       = 'setup.msi'
            ToolVersion     = '1.8.5'
            EncryptionInfo  = 'present'
            MsiInfo         = [pscustomobject]@{
                MsiProductCode       = '{11111111-1111-1111-1111-111111111111}'
                MsiProductVersion    = '1.2.3'
                MsiUpgradeCode       = '{22222222-2222-2222-2222-222222222222}'
                MsiExecutionContext  = 'System'
                MsiRequiresReboot    = 'false'
            }
        }
        $summary = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'Intunewin' -Switches $sw -PackageMetadata $pkg
        $summary | Should -Match 'Tool Version:\s+1\.8\.5'
        $summary | Should -Match 'MsiProductCode:'
        $summary | Should -Match '\{11111111-1111-1111-1111-111111111111\}'
    }

    It 'returns BitRock silent switches with mode unattended' {
        $sw = Get-SilentSwitches -InstallerType 'BitRock' -FilePath 'C:\tmp\postgresql-17.exe'
        $sw.Install   | Should -Match '--mode\s+unattended'
        $sw.Install   | Should -Match 'unattendedmodeui'
        $sw.Uninstall | Should -Match '--mode\s+unattended'
    }

    It 'renders Squirrel markers + embedded nupkg reference' {
        $fi = [PSCustomObject]@{ FileName = 'Setup.exe'; FileSizeFormatted = '60 MB'; SHA256='h'; Architecture='x86'; SignatureStatus='Valid' }
        $sw = [PSCustomObject]@{ Install='Setup.exe --silent'; Uninstall='Update.exe --uninstall'; Notes='' }
        $pkg = [PSCustomObject]@{
            InstallerType   = 'Squirrel'
            DisplayName     = 'Smoke'
            DisplayVersion  = '1.0.0'
            MarkersFound    = @('SquirrelTemp','squirrel-install','squirrel-updated','Update.exe')
            EmbeddedNupkg   = 'Smoke-1.0.0-full.nupkg'
            Confidence      = 'High'
        }
        $summary = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'Squirrel' -Switches $sw -PackageMetadata $pkg
        $summary | Should -Match 'Markers:\s+4 found'
        $summary | Should -Match 'Smoke-1\.0\.0-full\.nupkg'
        $summary | Should -Match 'Confidence:\s+High'
    }
}

# ============================================================================
# ConvertTo-DeploymentJson
# ============================================================================

Describe 'ConvertTo-DeploymentJson' {
    BeforeAll {
        $jsonFileInfo = [PSCustomObject]@{
            FileName = 'setup.exe'; FileSize = 12345; SHA256 = 'ABC123'
            FileVersion = '1.0.0.0'; ProductVersion = '1.0.0'; ProductName = 'JSON App'
            CompanyName = 'JSON Vendor'; FileDescription = 'Setup'; Architecture = 'x64'
            SignatureStatus = 'Valid'; SignerSubject = 'CN=JSON'
        }
        $jsonSwitches = [PSCustomObject]@{
            Install = '"setup.exe" /S'; Uninstall = '"uninstall.exe" /S'; Notes = '/S is case sensitive'
        }
    }

    It 'returns a JSON string parseable by ConvertFrom-Json' {
        $json = ConvertTo-DeploymentJson -FileInfo $jsonFileInfo -InstallerType 'NSIS' -Switches $jsonSwitches
        $json | Should -BeOfType [string]
        $parsed = $json | ConvertFrom-Json
        $parsed | Should -Not -BeNullOrEmpty
    }

    It 'carries a SchemaVersion for downstream contract guarantees' {
        $json = ConvertTo-DeploymentJson -FileInfo $jsonFileInfo -InstallerType 'NSIS' -Switches $jsonSwitches
        $parsed = $json | ConvertFrom-Json
        $parsed.SchemaVersion | Should -Be '1.0'
    }

    It 'groups fields under Source / Application / Deployment / Detection / Raw' {
        $json = ConvertTo-DeploymentJson -FileInfo $jsonFileInfo -InstallerType 'NSIS' -Switches $jsonSwitches
        $parsed = $json | ConvertFrom-Json
        $parsed.Source.FileName         | Should -Be 'setup.exe'
        $parsed.Source.FileSize         | Should -Be 12345
        $parsed.Source.SHA256           | Should -Be 'ABC123'
        $parsed.Application.DisplayName | Should -Be 'JSON App'
        $parsed.Application.InstallerType | Should -Be 'NSIS'
        $parsed.Deployment.InstallCommand | Should -Match '/S'
        $parsed.Detection.Hint | Should -Not -BeNullOrEmpty
    }

    It 'prefers DeploymentFields for DisplayName / DisplayVersion / Publisher' {
        $df = [PSCustomObject]@{
            DisplayName = 'Deploy Name'; DisplayVersion = '9.9.9'
            SilentUninstallString = '"uninstall.exe" /S'; Vendor = 'Deploy Vendor'
        }
        $json = ConvertTo-DeploymentJson -FileInfo $jsonFileInfo -InstallerType 'NSIS' -Switches $jsonSwitches -DeploymentFields $df
        $parsed = $json | ConvertFrom-Json
        $parsed.Application.DisplayName    | Should -Be 'Deploy Name'
        $parsed.Application.DisplayVersion | Should -Be '9.9.9'
        $parsed.Application.Publisher      | Should -Be 'Deploy Vendor'
    }

    It 'surfaces MSI ProductCode + UpgradeCode in Application and keeps full properties under Raw' {
        $msiProps = @{ ProductCode = '{11111111-1111-1111-1111-111111111111}'; UpgradeCode = '{22222222-2222-2222-2222-222222222222}'; Manufacturer = 'MSI Vendor' }
        $json = ConvertTo-DeploymentJson -FileInfo $jsonFileInfo -InstallerType 'MSI' -Switches $jsonSwitches -MsiProperties $msiProps
        $parsed = $json | ConvertFrom-Json
        $parsed.Application.ProductCode | Should -Be '{11111111-1111-1111-1111-111111111111}'
        $parsed.Application.UpgradeCode | Should -Be '{22222222-2222-2222-2222-222222222222}'
        $parsed.Raw.MsiProperties.Manufacturer | Should -Be 'MSI Vendor'
        $parsed.Detection.Hint | Should -Match 'ProductCode'
    }

    It 'nests PackageMetadata under Raw and prefers its silent commands over Switches' {
        $pkg = [PSCustomObject]@{
            InstallerType = 'Msix'; DisplayName = 'Pkg App'; DisplayVersion = '2.0.0'
            Publisher = 'Pkg Publisher'; Architecture = 'x64'
            ProductCodeOrEquivalent = 'Pkg.App'
            SilentInstallCommand = 'Add-AppxPackage -Path "pkg.msix"'
            SilentUninstallCommand = 'Remove-AppxPackage'
            Identity = [ordered]@{ Name = 'Pkg.App'; Publisher = 'CN=Pkg'; Version = '2.0.0.0'; ProcessorArchitecture = 'x64' }
        }
        $json = ConvertTo-DeploymentJson -FileInfo $jsonFileInfo -InstallerType 'Msix' -Switches $jsonSwitches -PackageMetadata $pkg
        $parsed = $json | ConvertFrom-Json
        $parsed.Application.ProductCode | Should -Be 'Pkg.App'
        $parsed.Deployment.InstallCommand | Should -Match 'Add-AppxPackage'
        $parsed.Deployment.UninstallCommand | Should -Match 'Remove-AppxPackage'
        $parsed.Raw.PackageMetadata.Identity.Name | Should -Be 'Pkg.App'
        $parsed.Detection.Hint | Should -Match 'family-name'
    }

    It 'varies DetectionHint by InstallerType' {
        $types = @('MSI','NSIS','Chocolatey','Msix','PsadtV4','Squirrel')
        $hints = foreach ($t in $types) {
            ((ConvertTo-DeploymentJson -FileInfo $jsonFileInfo -InstallerType $t -Switches $jsonSwitches) | ConvertFrom-Json).Detection.Hint
        }
        # Every hint string should be unique across these 6 types
        ($hints | Sort-Object -Unique).Count | Should -Be 6
    }

    It 'defaults missing fields to empty strings (never null in the schema)' {
        $minimalFileInfo = [PSCustomObject]@{ FileName = 'x.exe'; FileSize = 0; SHA256 = '' }
        $json = ConvertTo-DeploymentJson -FileInfo $minimalFileInfo -InstallerType 'Unknown'
        $parsed = $json | ConvertFrom-Json
        $parsed.Application.DisplayName    | Should -Be ''
        $parsed.Application.DisplayVersion | Should -Be ''
        $parsed.Application.Publisher      | Should -Be ''
        $parsed.Application.ProductCode    | Should -Be ''
        $parsed.Application.UpgradeCode    | Should -Be ''
        $parsed.Deployment.InstallCommand  | Should -Be ''
    }
}

# ============================================================================
# Test-MsiModuleAvailable
# ============================================================================

Describe 'Test-MsiModuleAvailable' {
    It 'returns a boolean' {
        $result = Test-MsiModuleAvailable
        $result | Should -BeOfType [bool]
    }
}
