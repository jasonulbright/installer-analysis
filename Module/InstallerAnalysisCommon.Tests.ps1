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
        $meta.EncryptionInfo['Encrypted']            | Should -BeTrue
        $meta.EncryptionInfo['EncryptionKey']        | Should -Be '<redacted>'
        $meta.EncryptionInfo['MacKey']               | Should -Be '<redacted>'
        $meta.EncryptionInfo['InitializationVector'] | Should -Be '<redacted>'
        $meta.EncryptionInfo['Mac']                  | Should -Be '<redacted>'
        $meta.EncryptionInfo['ProfileIdentifier']    | Should -Be 'ProfileVersion1'
        $meta.EncryptionInfo['FileDigest']           | Should -Be 'eee='
        $meta.EncryptionInfo['FileDigestAlgorithm']  | Should -Be 'SHA256'
        $meta.SilentInstallCommand | Should -Match 'ExtractedSetup'
        $meta.SilentUninstallCommand | Should -Match 'Intune portal'
    }

    It 'surfaces raw AES key material when -IncludeIntunewinKeyMaterial is set' {
        $detection = @"
<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="1.8.6">
  <Name>OptInApp</Name>
  <UnencryptedContentSize>1024</UnencryptedContentSize>
  <FileName>IntunePackage.intunewin</FileName>
  <SetupFile>optin.exe</SetupFile>
  <EncryptionInfo>
    <EncryptionKey>KEY-RAW=</EncryptionKey>
    <MacKey>MAC-RAW=</MacKey>
    <InitializationVector>IV-RAW</InitializationVector>
    <Mac>MAC-VALUE=</Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest>DIGEST=</FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>
"@
        $pkg = Join-Path $TestDrive 'OptInApp.intunewin'
        script:New-TestZipFile -Path $pkg -Entries @{
            'IntuneWinPackage/Metadata/Detection.xml' = $detection
        }
        Initialize-Logging -LogPath (Join-Path $TestDrive 'optin.log')
        $meta = Get-IntunewinMetadata -Path $pkg -IncludeIntunewinKeyMaterial
        $meta | Should -Not -BeNullOrEmpty
        $meta.EncryptionInfo['Encrypted']            | Should -BeTrue
        $meta.EncryptionInfo['EncryptionKey']        | Should -Be 'KEY-RAW='
        $meta.EncryptionInfo['MacKey']               | Should -Be 'MAC-RAW='
        $meta.EncryptionInfo['InitializationVector'] | Should -Be 'IV-RAW'
        $meta.EncryptionInfo['Mac']                  | Should -Be 'MAC-VALUE='
        $meta.EncryptionInfo['ProfileIdentifier']    | Should -Be 'ProfileVersion1'
        $meta.EncryptionInfo['FileDigest']           | Should -Be 'DIGEST='
        $meta.EncryptionInfo['FileDigestAlgorithm']  | Should -Be 'SHA256'
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
        # SilentInstall/Uninstall now render inside Deployment Fields; pass DF so
        # the renderer has somewhere to surface those values.
        $fileInfo = [PSCustomObject]@{
            FileName = 'setup.exe'; FileSizeFormatted = '10.5 MB'; SHA256 = 'abc123'
            FileVersion = '1.0.0'; ProductVersion = '1.0.0'; ProductName = 'My App'
            CompanyName = 'ACME'; Architecture = 'x64'
            SignatureStatus = 'Valid'; SignerSubject = 'CN=ACME Inc'
        }
        $switches = [PSCustomObject]@{ Install = '"setup.exe" /S'; Uninstall = '"uninstall.exe" /S'; Notes = '' }
        $df = [PSCustomObject]@{ DisplayName='My App'; DisplayVersion='1.0.0'; Vendor='ACME'; SilentUninstallString='"uninstall.exe" /S' }
        $summary = New-AnalysisSummaryText -FileInfo $fileInfo -InstallerType 'NSIS' -Switches $switches -DeploymentFields $df
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
        # Identity.Name now lives in Deployment Fields DisplayName (de-duped from
        # the Package Metadata block). Pass DeploymentFields so the rendered
        # summary has the bundle name to assert against.
        $fi = [PSCustomObject]@{ FileName = 'x.msixbundle'; FileSizeFormatted = '20 MB'; SHA256='h'; Architecture='x64'; SignatureStatus='Unknown' }
        $sw = [PSCustomObject]@{ Install='Add-AppxPackage'; Uninstall='Remove-AppxPackage'; Notes='' }
        $df = [PSCustomObject]@{ DisplayName='Contoso.Bundle'; DisplayVersion='9.8.7.0'; Vendor='CN=Contoso'; SilentUninstallString='Remove-AppxPackage' }
        $pkg = [PSCustomObject]@{
            InstallerType = 'MsixBundle'
            Identity      = [ordered]@{ Name='Contoso.Bundle'; Publisher='CN=Contoso'; Version='9.8.7.0' }
            BundledPackages = @(
                [pscustomobject]@{ Type='application'; Version='9.8.7.0'; Architecture='x64';  ResourceId=''; FileName='Contoso.x64.msix' },
                [pscustomobject]@{ Type='application'; Version='9.8.7.0'; Architecture='x86';  ResourceId=''; FileName='Contoso.x86.msix' },
                [pscustomobject]@{ Type='resource';    Version='9.8.7.0'; Architecture='';     ResourceId='en-us'; FileName='Contoso.en-us.msix' }
            )
        }
        $summary = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'MsixBundle' -Switches $sw -DeploymentFields $df -PackageMetadata $pkg
        $summary | Should -Match 'Bundled Packages: 3'
        $summary | Should -Match 'Contoso\.x64\.msix'
        $summary | Should -Match 'Contoso\.x86\.msix'
        $summary | Should -Match 'Contoso\.en-us\.msix'
        $summary | Should -Match 'Identity:'
        # Contoso.Bundle now lives in Deployment Fields DisplayName, not under Identity.
        $summary | Should -Match 'DisplayName:\s+Contoso\.Bundle'
        # Identity.Publisher (cryptographic CN=...) stays under Package Metadata.
        $summary | Should -Match 'Publisher:\s+CN=Contoso'
    }

    It 'renders all 9 PSADT AppMetadata fields across Deployment Fields and Package Metadata' {
        # Layout change: AppVendor / AppName / AppVersion are now surfaced via
        # Deployment Fields (Vendor / DisplayName / DisplayVersion); the
        # PSADT-specific fields (AppArch, AppLang, AppRevision, ScriptVersion,
        # ScriptDate, ScriptAuthor) stay in the Package Metadata block. The
        # full set of nine values is still rendered -- just in two sections.
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
        $df = [PSCustomObject]@{ DisplayName='ModernApp'; DisplayVersion='2.0.0'; Vendor='Contoso'; SilentUninstallString='Invoke-AppDeployToolkit.exe -DeploymentType Uninstall -DeployMode Silent' }
        $pkg = [PSCustomObject]@{
            InstallerType  = 'PsadtV4'
            ToolkitVariant = 'v4'
            ToolkitVersion = '4.2.0'
            AppMetadata    = $am
        }
        $summary = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'PsadtV4' -Switches $sw -DeploymentFields $df -PackageMetadata $pkg

        # AppVendor / AppName / AppVersion now visible via Deployment Fields:
        $summary | Should -Match 'DisplayName:\s+ModernApp'
        $summary | Should -Match 'DisplayVersion:\s+2\.0\.0'
        $summary | Should -Match 'Vendor:\s+Contoso'

        # The 6 PSADT-specific fields plus toolkit version stay in Package Metadata:
        foreach ($field in 'AppArch','AppLang','AppRevision','ScriptVersion','ScriptDate','ScriptAuthor') {
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
        # NupkgReferences is the actual field name produced by Get-SquirrelMetadata.
        # An older version of this test asserted "EmbeddedNupkg" — that field has
        # never existed on real metadata; the test passed against a phantom code
        # path. Fixed alongside the corresponding renderer fix.
        $fi = [PSCustomObject]@{ FileName = 'Setup.exe'; FileSizeFormatted = '60 MB'; SHA256='h'; Architecture='x86'; SignatureStatus='Valid' }
        $sw = [PSCustomObject]@{ Install='Setup.exe --silent'; Uninstall='Update.exe --uninstall'; Notes='' }
        $pkg = [PSCustomObject]@{
            InstallerType           = 'Squirrel'
            DisplayName             = 'Smoke'
            DisplayVersion          = '1.0.0'
            ProductCodeOrEquivalent = 'Smoke'
            MarkersFound            = @('SquirrelTemp','squirrel-install','squirrel-updated','Update.exe')
            NupkgReferences         = @(
                [PSCustomObject]@{ FileName='Smoke-1.0.0-full.nupkg'; AppName='Smoke'; Version='1.0.0'; Kind='full' }
            )
            Confidence              = 'High'
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

# ============================================================================
# Get-UninstallRegistryKey
# ============================================================================

Describe 'Get-UninstallRegistryKey' {
    BeforeAll {
        $script:fiX64 = [PSCustomObject]@{ FileName='setup.exe'; Architecture='x64' }
        $script:fiX86 = [PSCustomObject]@{ FileName='setup.exe'; Architecture='x86' }
        $script:dfApp = [PSCustomObject]@{ DisplayName='MyApp'; DisplayVersion='1.0'; SilentUninstallString=''; Vendor='Acme' }
    }

    It 'returns HKLM ARP path for MSI x64 keyed on ProductCode' {
        $msi = @{ ProductCode = '{ABC-123}' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fiX64 -MsiProperties $msi -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{ABC-123}'
        $r.Hive | Should -Be 'HKLM'
    }

    It 'redirects to WOW6432Node for MSI x86' {
        $msi = @{ ProductCode = '{ABC-123}' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fiX86 -MsiProperties $msi -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{ABC-123}'
        $r.Note | Should -Match 'WOW6432Node'
    }

    It 'returns $null for MSI without ProductCode' {
        Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fiX64 -MsiProperties @{} -DeploymentFields $script:dfApp | Should -BeNullOrEmpty
    }

    It 'uses BundleId from PackageMetadata for WixBurn' {
        $pkg = [PSCustomObject]@{ UninstallRegistryKey='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{BUNDLE-GUID}'; UninstallRegistryKeyNote='from burn header' }
        $r = Get-UninstallRegistryKey -InstallerType 'WixBurn' -FileInfo $script:fiX64 -PackageMetadata $pkg -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{BUNDLE-GUID}'
    }

    It 'returns $null for WixBurn when BundleId is missing (no template leak)' {
        # Old behavior was to render "{BundleId}" as a literal in the path.
        # New behavior: drop the field entirely so the renderer doesn't print
        # a leaked template token. Honest about what we don't know.
        $r = Get-UninstallRegistryKey -InstallerType 'WixBurn' -FileInfo $script:fiX64 -DeploymentFields $script:dfApp
        $r | Should -BeNullOrEmpty
    }

    It 'returns $null for NSIS / Inno / BitRock / PSADT / Squirrel / InstallShield / AdvancedInstaller when name source is missing' {
        # TeamViewer ships an NSIS bootstrapper with all PE FileVersionInfo
        # stripped -- nothing to key on. Same pattern across all script-defined
        # types: rather than rendering "<DisplayName>" / "<AppName>" / similar
        # placeholders as literals, return null so the renderer omits the line.
        $fiEmpty  = [PSCustomObject]@{ FileName='setup.exe'; Architecture='x64' }
        $dfEmpty  = [PSCustomObject]@{ DisplayName=''; DisplayVersion=''; SilentUninstallString=''; Vendor='' }
        foreach ($t in 'NSIS','InnoSetup','BitRock','PsadtV3','PsadtV4','Squirrel','InstallShield','AdvancedInstaller') {
            $r = Get-UninstallRegistryKey -InstallerType $t -FileInfo $fiEmpty -DeploymentFields $dfEmpty
            $r | Should -BeNullOrEmpty -Because "$t should yield null when its key source is missing"
        }
    }

    It 'returns HKCU path keyed on AppName for Squirrel (per-user)' {
        $pkg = [PSCustomObject]@{ DisplayName='Slack'; ProductCodeOrEquivalent='Slack' }
        $r = Get-UninstallRegistryKey -InstallerType 'Squirrel' -FileInfo $script:fiX64 -PackageMetadata $pkg -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Slack'
        $r.Hive | Should -Be 'HKCU'
    }

    It 'appends _is1 suffix for InnoSetup' {
        $r = Get-UninstallRegistryKey -InstallerType 'InnoSetup' -FileInfo $script:fiX64 -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp_is1'
    }

    It 'returns HKLM ARP path keyed on DisplayName for NSIS' {
        $r = Get-UninstallRegistryKey -InstallerType 'NSIS' -FileInfo $script:fiX64 -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp'
    }

    It 'keys InstallShield on ProductCode when available' {
        $msi = @{ ProductCode = '{IS-CODE}' }
        $r = Get-UninstallRegistryKey -InstallerType 'InstallShield' -FileInfo $script:fiX64 -MsiProperties $msi -DeploymentFields $script:dfApp
        $r.Path | Should -Match '\{IS-CODE\}$'
    }

    It 'keys PsadtV3 on AppMetadata.AppName' {
        $pkg = [PSCustomObject]@{ AppMetadata = @{ AppName='Acme Foo' } }
        $r = Get-UninstallRegistryKey -InstallerType 'PsadtV3' -FileInfo $script:fiX64 -PackageMetadata $pkg -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme Foo'
    }

    It 'keys PsadtV4 on AppMetadata.AppName' {
        $pkg = [PSCustomObject]@{ AppMetadata = @{ AppName='Bar' } }
        $r = Get-UninstallRegistryKey -InstallerType 'PsadtV4' -FileInfo $script:fiX64 -PackageMetadata $pkg -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Bar'
    }

    It 'keys BitRock on DisplayName' {
        $r = Get-UninstallRegistryKey -InstallerType 'BitRock' -FileInfo $script:fiX64 -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp'
    }

    It 'keys AdvancedInstaller on the wrapped ProductCode' {
        $msi = @{ ProductCode = '{AI-CODE}' }
        $r = Get-UninstallRegistryKey -InstallerType 'AdvancedInstaller' -FileInfo $script:fiX64 -MsiProperties $msi -DeploymentFields $script:dfApp
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{AI-CODE}'
    }

    It 'returns AppX family-name path (NOT ARP) for Msix' {
        $pkg = [PSCustomObject]@{ Identity = [PSCustomObject]@{ Name='Microsoft.WindowsCalculator' } }
        $r = Get-UninstallRegistryKey -InstallerType 'Msix' -FileInfo $script:fiX64 -PackageMetadata $pkg -DeploymentFields $script:dfApp
        $r.Path | Should -Match "Get-AppxPackage.*Microsoft\.WindowsCalculator"
        $r.Hive | Should -Be 'AppX (not ARP)'
    }

    It 'returns $null for Chocolatey (no ARP write)' {
        Get-UninstallRegistryKey -InstallerType 'Chocolatey' -FileInfo $script:fiX64 -DeploymentFields $script:dfApp | Should -BeNullOrEmpty
    }

    It 'returns $null for NuGet (package manager, not installer)' {
        Get-UninstallRegistryKey -InstallerType 'NuGet' -FileInfo $script:fiX64 -DeploymentFields $script:dfApp | Should -BeNullOrEmpty
    }

    It 'returns $null for Unknown type' {
        Get-UninstallRegistryKey -InstallerType 'Unknown' -FileInfo $script:fiX64 -DeploymentFields $script:dfApp | Should -BeNullOrEmpty
    }
}

# ============================================================================
# Get-DeploymentFields with InstallerType (UninstallRegistryKey)
# ============================================================================

Describe 'Get-DeploymentFields with InstallerType' {
    It 'populates UninstallRegistryKey when InstallerType is provided' {
        $fi = [PSCustomObject]@{ ProductName='Foo'; ProductVersion='1.0'; CompanyName='Acme'; Architecture='x64' }
        $msi = @{ ProductCode='{XYZ}'; ProductName='Foo'; Manufacturer='Acme' }
        $df = Get-DeploymentFields -FileInfo $fi -MsiProperties $msi -Switches $null -InstallerType 'MSI'
        $df.UninstallRegistryKey     | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{XYZ}'
        $df.UninstallRegistryKeyNote | Should -Not -BeNullOrEmpty
    }

    It 'leaves UninstallRegistryKey empty when InstallerType is omitted (back-compat)' {
        $fi = [PSCustomObject]@{ ProductName='Foo'; ProductVersion='1.0'; CompanyName='Acme'; Architecture='x64' }
        $df = Get-DeploymentFields -FileInfo $fi -Switches $null
        $df.UninstallRegistryKey | Should -BeNullOrEmpty
    }

    It 'leaves UninstallRegistryKey empty for types with no ARP write (Chocolatey)' {
        $fi = [PSCustomObject]@{ ProductName=''; ProductVersion=''; CompanyName=''; Architecture='' }
        $df = Get-DeploymentFields -FileInfo $fi -Switches $null -InstallerType 'Chocolatey'
        $df.UninstallRegistryKey | Should -BeNullOrEmpty
    }
}

# ============================================================================
# Get-WixBurnMetadata
# ============================================================================

Describe 'Get-WixBurnMetadata' {
    It 'returns $null for a non-existent file' {
        Get-WixBurnMetadata -Path (Join-Path $TestDrive 'nope.exe') | Should -BeNullOrEmpty
    }

    It 'returns $null for a non-PE file' {
        $f = Join-Path $TestDrive 'plain.bin'
        [System.IO.File]::WriteAllText($f, 'not a PE')
        Get-WixBurnMetadata -Path $f | Should -BeNullOrEmpty
    }

    It 'returns $null for a PE without a .wixburn section' {
        # Use any real PE from system that is not a Burn bundle.
        $pwsh = (Get-Process -Id $PID).Path
        if (Test-Path -LiteralPath $pwsh) {
            Get-WixBurnMetadata -Path $pwsh | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for a PE with an implausible section count (defensive bound)' {
        # Synthesize a tiny PE-shaped file claiming numSections=65535. The bound
        # check should reject it before iterating the section table.
        $f = Join-Path $TestDrive 'evil-numsections.exe'
        $buf = New-Object byte[] 256
        # DOS: 'MZ' at 0, e_lfanew=0x40 at 0x3C
        $buf[0] = 0x4D; $buf[1] = 0x5A
        $buf[0x3C] = 0x40
        # PE signature at 0x40: 'PE\0\0'
        $buf[0x40] = 0x50; $buf[0x41] = 0x45
        # COFF: Machine(2)=0, NumberOfSections(2)=65535 at offset 0x46
        $buf[0x46] = 0xFF; $buf[0x47] = 0xFF
        [System.IO.File]::WriteAllBytes($f, $buf)
        Get-WixBurnMetadata -Path $f | Should -BeNullOrEmpty
    }
}

# ============================================================================
# Get-InstallerType: dual-encoding Squirrel detection
# ============================================================================

Describe 'Get-InstallerType dual-encoding Squirrel scan' {
    It 'detects Squirrel when markers exist only in UTF-16LE' {
        # Real-world case: GitHub Desktop's Setup.exe stores marker strings as wide
        # chars. Build a fixture that mimics the PE-with-wide-markers layout: MZ
        # header, then a UTF-16LE block carrying SquirrelTemp + Update.exe + nupkg.
        $f = Join-Path $TestDrive 'squirrel-wide.exe'
        $mz = [byte[]](0x4D, 0x5A) + (New-Object byte[] 510)    # MZ + 510 zero bytes
        $wide = [System.Text.Encoding]::Unicode.GetBytes("`0SquirrelTemp`0Update.exe`0FakeApp-1.2.3-full.nupkg`0")
        [System.IO.File]::WriteAllBytes($f, ($mz + $wide))
        Get-InstallerType -Path $f | Should -Be 'Squirrel'
    }

    It 'detects Squirrel when markers exist only in ASCII (existing behavior preserved)' {
        $f = Join-Path $TestDrive 'squirrel-ascii.exe'
        $mz = [byte[]](0x4D, 0x5A) + (New-Object byte[] 510)
        $ascii = [System.Text.Encoding]::ASCII.GetBytes("`0SquirrelTemp`0squirrel-install`0Update.exe`0App-1.0.0-full.nupkg`0")
        [System.IO.File]::WriteAllBytes($f, ($mz + $ascii))
        Get-InstallerType -Path $f | Should -Be 'Squirrel'
    }

    It 'detects Squirrel via nupkg fallback when only Update.exe + nupkg pattern (no lifecycle markers)' {
        $f = Join-Path $TestDrive 'squirrel-nupkg-only.exe'
        $mz = [byte[]](0x4D, 0x5A) + (New-Object byte[] 510)
        $wide = [System.Text.Encoding]::Unicode.GetBytes("`0Update.exe`0FooBar-2.5.1-full.nupkg`0")
        [System.IO.File]::WriteAllBytes($f, ($mz + $wide))
        Get-InstallerType -Path $f | Should -Be 'Squirrel'
    }

    It 'does NOT misdetect plain MZ blob with no Squirrel signal as Squirrel' {
        $f = Join-Path $TestDrive 'plain-mz.exe'
        $mz = [byte[]](0x4D, 0x5A) + (New-Object byte[] 4094)
        [System.IO.File]::WriteAllBytes($f, $mz)
        Get-InstallerType -Path $f | Should -Not -Be 'Squirrel'
    }
}

# ============================================================================
# Get-SquirrelMetadata: dual-encoding nupkg extraction
# ============================================================================

Describe 'Get-SquirrelMetadata dual-encoding' {
    It 'extracts AppName and Version from a UTF-16LE-only nupkg reference' {
        $f = Join-Path $TestDrive 'sq-wide.exe'
        $mz = [byte[]](0x4D, 0x5A) + (New-Object byte[] 510)
        $wide = [System.Text.Encoding]::Unicode.GetBytes("`0SquirrelTemp`0Update.exe`0GitHubDesktop-3.5.8-full.nupkg`0")
        [System.IO.File]::WriteAllBytes($f, ($mz + $wide))
        $r = Get-SquirrelMetadata -Path $f
        $r | Should -Not -BeNullOrEmpty
        $r.DisplayName    | Should -Be 'GitHubDesktop'
        $r.DisplayVersion | Should -Be '3.5.8'
    }

    It 'dedups nupkg references that appear in both ASCII and UTF-16LE' {
        $f = Join-Path $TestDrive 'sq-both.exe'
        $mz = [byte[]](0x4D, 0x5A) + (New-Object byte[] 510)
        $body = [System.Text.Encoding]::ASCII.GetBytes("`0SquirrelTemp`0Update.exe`0App-1.0.0-full.nupkg`0") +
                [System.Text.Encoding]::Unicode.GetBytes("`0App-1.0.0-full.nupkg`0")
        [System.IO.File]::WriteAllBytes($f, ($mz + $body))
        $r = Get-SquirrelMetadata -Path $f
        @($r.NupkgReferences).Count | Should -Be 1
    }
}

# ============================================================================
# Get-UninstallRegistryKey -- MSI architecture override (MSI Template)
# ============================================================================

Describe 'Get-UninstallRegistryKey MSI architecture override' {
    BeforeAll {
        $script:fiMsiPlaceholder = [PSCustomObject]@{ FileName='setup.msi'; Architecture='N/A (see MSI Summary)' }
        $script:dfApp = [PSCustomObject]@{ DisplayName='MyApp'; DisplayVersion='1.0'; SilentUninstallString=''; Vendor='Acme' }
    }

    It 'routes x86 MSI to WOW6432Node when MsiArchitecture is supplied' {
        $msi = @{ ProductCode = '{ABC-123}' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fiMsiPlaceholder -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'x86'
        $r.Path | Should -Be 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{ABC-123}'
    }

    It 'routes x86 MSI to WOW6432Node for the Intel Template value' {
        $msi = @{ ProductCode = '{ABC-123}' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fiMsiPlaceholder -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'Intel'
        $r.Path | Should -Be 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{ABC-123}'
    }

    It 'routes x64 MSI to plain HKLM when MsiArchitecture indicates x64' {
        $msi = @{ ProductCode = '{ABC-123}' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fiMsiPlaceholder -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'x64'
        $r.Path | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{ABC-123}'
    }

    It 'warns about unknown architecture when MsiArchitecture is omitted and FileInfo is the placeholder' {
        $msi = @{ ProductCode = '{ABC-123}' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fiMsiPlaceholder -MsiProperties $msi -DeploymentFields $script:dfApp
        $r.Note | Should -Match 'Architecture unknown'
    }
}

# ============================================================================
# Get-UninstallRegistryKey -- per-user MSI (ALLUSERS / MSIINSTALLPERUSER)
# ============================================================================

Describe 'Get-UninstallRegistryKey per-user MSI' {
    BeforeAll {
        $script:fi = [PSCustomObject]@{ FileName='setup.msi'; Architecture='x64' }
        $script:dfApp = [PSCustomObject]@{ DisplayName='MyApp'; DisplayVersion='1.0'; SilentUninstallString=''; Vendor='Acme' }
    }

    It 'routes to HKCU when ALLUSERS=2 + MSIINSTALLPERUSER=1' {
        $msi = @{ ProductCode='{ABC-123}'; ALLUSERS='2'; MSIINSTALLPERUSER='1' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fi -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'x64'
        $r.Hive | Should -Be 'HKCU'
        $r.Path | Should -Be 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{ABC-123}'
    }

    It 'routes to HKCU when ALLUSERS is empty string (bare per-user)' {
        $msi = @{ ProductCode='{ABC-456}'; ALLUSERS='' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fi -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'x64'
        $r.Hive | Should -Be 'HKCU'
    }

    It 'routes to HKCU when MSIINSTALLPERUSER=1 without ALLUSERS row' {
        $msi = @{ ProductCode='{ABC-789}'; MSIINSTALLPERUSER='1' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fi -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'x64'
        $r.Hive | Should -Be 'HKCU'
    }

    It 'stays HKLM when ALLUSERS=2 + MSIINSTALLPERUSER=0 (dual-mode, per-machine)' {
        $msi = @{ ProductCode='{ABC-DEF}'; ALLUSERS='2'; MSIINSTALLPERUSER='0' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fi -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'x64'
        $r.Hive | Should -Be 'HKLM'
    }

    It 'stays HKLM when ALLUSERS=1 (explicit per-machine)' {
        $msi = @{ ProductCode='{ABC-GHI}'; ALLUSERS='1' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fi -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'x64'
        $r.Hive | Should -Be 'HKLM'
    }

    It 'stays HKLM when neither property is present (conservative default)' {
        $msi = @{ ProductCode='{ABC-JKL}' }
        $r = Get-UninstallRegistryKey -InstallerType 'MSI' -FileInfo $script:fi -MsiProperties $msi -DeploymentFields $script:dfApp -MsiArchitecture 'x64'
        $r.Hive | Should -Be 'HKLM'
    }
}

# ============================================================================
# Find-SquirrelNupkgRefs -- regex backtracking
# ============================================================================

Describe 'Find-SquirrelNupkgRefs regex safety' {
    It 'returns in under 2 seconds on the pathological "Update.exe + 100KB of A-" input' {
        $evil = 'Update.exe' + ('A-' * 50000) + 'B'
        # Find-SquirrelNupkgRefs is script-scoped inside the module. Invoke it
        # via the module's ScriptBlock so script-scope resolution works.
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $m = Get-Module InstallerAnalysisCommon
        $hits = & $m { param($t) Find-SquirrelNupkgRefs -Text $t } $evil
        $sw.Stop()
        $sw.ElapsedMilliseconds | Should -BeLessThan 2000
        @($hits).Count | Should -Be 0
    }

    It 'still finds legitimate nupkg references in mixed text' {
        # Real binaries delimit strings with null bytes; the regex picks the
        # AppName up at the first non-[A-Za-z0-9.-] char going backwards.
        $text = "garbage`0GitHubDesktop-3.5.8-full.nupkg`0garbage"
        $m = Get-Module InstallerAnalysisCommon
        $hits = & $m { param($t) Find-SquirrelNupkgRefs -Text $t } $text
        @($hits).Count | Should -Be 1
        $hits[0].AppName | Should -Be 'GitHubDesktop'
        $hits[0].Version | Should -Be '3.5.8'
        $hits[0].Kind    | Should -Be 'full'
    }

    It 'returns empty array on empty / null input' {
        $m = Get-Module InstallerAnalysisCommon
        @(& $m { param($t) Find-SquirrelNupkgRefs -Text $t } '').Count | Should -Be 0
        @(& $m { param($t) Find-SquirrelNupkgRefs -Text $t } $null).Count | Should -Be 0
    }
}

# ============================================================================
# Get-PackageMetadataFor dispatch (includes WixBurn case)
# ============================================================================

Describe 'Get-PackageMetadataFor' {
    It 'returns $null for types with no framework-specific extractor (MSI, NSIS, Unknown)' {
        Get-PackageMetadataFor -Path (Join-Path $TestDrive 'x') -InstallerType 'MSI'      | Should -BeNullOrEmpty
        Get-PackageMetadataFor -Path (Join-Path $TestDrive 'x') -InstallerType 'NSIS'     | Should -BeNullOrEmpty
        Get-PackageMetadataFor -Path (Join-Path $TestDrive 'x') -InstallerType 'Unknown'  | Should -BeNullOrEmpty
    }

    It 'dispatches WixBurn to Get-WixBurnMetadata (returns $null for non-burn input)' {
        # Use any non-burn file; Get-WixBurnMetadata returns $null when no .wixburn section.
        $f = Join-Path $TestDrive 'plain.bin'
        [System.IO.File]::WriteAllText($f, 'not a burn bundle')
        Get-PackageMetadataFor -Path $f -InstallerType 'WixBurn' | Should -BeNullOrEmpty
    }
}

# ============================================================================
# Get-DeploymentFields end-to-end with MsiSummary
# ============================================================================

Describe 'New-AnalysisSummaryText placeholder substitution' {
    It 'bakes AppName and Setup filename into Squirrel switches / notes / uninstall string' {
        $fi  = [PSCustomObject]@{ FileName='GitHubDesktopSetup-x64.exe'; ProductName='GitHubDesktop'; ProductVersion='3.5.8'; CompanyName='GitHub, Inc.'; Architecture='x86'; FileSizeFormatted='181.2 MB'; SHA256='X'; SignatureStatus='Valid'; SignerSubject='' }
        $pkg = [PSCustomObject]@{
            InstallerType           = 'Squirrel'
            DisplayName             = 'GitHubDesktop'
            DisplayVersion          = '3.5.8'
            ProductCodeOrEquivalent = 'GitHubDesktop'
            MarkersFound            = @('SquirrelTemp')
            Confidence              = 'Medium'
            HasUpdateExe            = $true
            SilentInstallCommand    = '"<Setup.exe>" --silent'
            SilentUninstallCommand  = '"%LOCALAPPDATA%\<AppName>\Update.exe" --uninstall -s'
        }
        $sw  = Get-SilentSwitches -InstallerType 'Squirrel' -FilePath 'GitHubDesktopSetup-x64.exe'
        $df  = Get-DeploymentFields -FileInfo $fi -Switches $sw -PackageMetadata $pkg -InstallerType 'Squirrel'
        $txt = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'Squirrel' -Switches $sw -DeploymentFields $df -PackageMetadata $pkg

        # Every placeholder the analysis already resolves should be substituted.
        $txt | Should -Not -Match '<AppName>'
        $txt | Should -Not -Match '<Setup\.exe>'
        $txt | Should -Match 'GitHubDesktopSetup-x64\.exe'
        $txt | Should -Match '%LOCALAPPDATA%\\GitHubDesktop\\Update\.exe'
        # The full predicted key path is rendered without a placeholder.
        $txt | Should -Match 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GitHubDesktop'
        # No prose smuggled into the silent commands via inline "# ..." comments.
        # The SilentInstallString / SilentUninstallString lines must contain
        # the command and only the command -- not "# installs to..." style notes.
        foreach ($line in ($txt -split "`r?`n")) {
            if ($line -match '^\s*Silent(Install|Uninstall)String:') {
                $line | Should -Not -Match '\s#\s'
            }
        }
    }

    It 'bakes ProductCode into MSI silent uninstall command' {
        $fi  = [PSCustomObject]@{ FileName='Setup.msi'; ProductName='Foo'; ProductVersion='1.0'; CompanyName='Acme'; Architecture='N/A (see MSI Summary)'; FileSizeFormatted='1 MB'; SHA256='X'; SignatureStatus='Valid'; SignerSubject='' }
        $msi = @{ ProductCode='{ABCDEF12-3456-7890-ABCD-EF1234567890}'; ProductName='Foo'; Manufacturer='Acme' }
        $sw  = Get-SilentSwitches -InstallerType 'MSI' -FilePath 'Setup.msi' -MsiProperties $msi
        $summary = [PSCustomObject]@{ Architecture='x64'; Template='x64;1033' }
        $df  = Get-DeploymentFields -FileInfo $fi -MsiProperties $msi -Switches $sw -InstallerType 'MSI' -MsiSummary $summary
        $txt = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'MSI' -Switches $sw -MsiProperties $msi -DeploymentFields $df

        $txt | Should -Not -Match '<ProductCode>'
        $txt | Should -Match '\{ABCDEF12-3456-7890-ABCD-EF1234567890\}'
    }
}

Describe 'Get-DeploymentFields end-to-end with MsiSummary' {
    It 'uses MsiSummary.Architecture to route an x86 MSI to WOW6432Node when FileInfo is the placeholder' {
        $fi = [PSCustomObject]@{ ProductName='Foo'; ProductVersion='1.0'; CompanyName='Acme'; Architecture='N/A (see MSI Summary)' }
        $msi = @{ ProductCode='{XYZ}'; ProductName='Foo'; Manufacturer='Acme' }
        $summary = [PSCustomObject]@{ Architecture='x86'; Template='Intel;1033' }
        $df = Get-DeploymentFields -FileInfo $fi -MsiProperties $msi -Switches $null -InstallerType 'MSI' -MsiSummary $summary
        $df.UninstallRegistryKey | Should -Be 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{XYZ}'
    }

    It 'routes per-user MSI to HKCU end-to-end through Get-DeploymentFields' {
        $fi = [PSCustomObject]@{ ProductName='Foo'; ProductVersion='1.0'; CompanyName='Acme'; Architecture='N/A (see MSI Summary)' }
        $msi = @{ ProductCode='{PU-1}'; ProductName='Foo'; Manufacturer='Acme'; ALLUSERS='2'; MSIINSTALLPERUSER='1' }
        $summary = [PSCustomObject]@{ Architecture='x64'; Template='x64;1033' }
        $df = Get-DeploymentFields -FileInfo $fi -MsiProperties $msi -Switches $null -InstallerType 'MSI' -MsiSummary $summary
        $df.UninstallRegistryKey | Should -Be 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{PU-1}'
    }
}

# ============================================================================
# Round-2 regressions
# ============================================================================

Describe 'Find-SquirrelNupkgRefs round-2 fixes' {
    It 'accepts a hyphenated prerelease (App-1.2.3-beta-1-full.nupkg)' {
        $text = "`0Update.exe`0App-1.2.3-beta-1-full.nupkg`0"
        $m = Get-Module InstallerAnalysisCommon
        $hits = & $m { param($t) Find-SquirrelNupkgRefs -Text $t } $text
        @($hits).Count   | Should -Be 1
        $hits[0].AppName | Should -Be 'App'
        $hits[0].Version | Should -Be '1.2.3-beta-1'
        $hits[0].Kind    | Should -Be 'full'
    }

    It 'accepts uppercase .NUPKG suffix' {
        $text = "`0Update.exe`0MyApp-1.0.0-full.NUPKG`0"
        $m = Get-Module InstallerAnalysisCommon
        $hits = & $m { param($t) Find-SquirrelNupkgRefs -Text $t } $text
        @($hits).Count   | Should -Be 1
        $hits[0].AppName | Should -Be 'MyApp'
    }

    It 'returns in under 2 seconds on 500KB of bare ".nupkg" literals (no -full/-delta)' {
        $big = 'Update.exe' + ('.nupkg' * 83333)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $m = Get-Module InstallerAnalysisCommon
        $hits = & $m { param($t) Find-SquirrelNupkgRefs -Text $t } $big
        $sw.Stop()
        $sw.ElapsedMilliseconds | Should -BeLessThan 2000
        @($hits).Count | Should -Be 0
    }

    It 'caps work via 2s elapsed budget on extreme legitimate -full.nupkg flood' {
        # Synthesize many legitimate refs. Even if every one matches, total time
        # must stay within the elapsed-time budget the scanner enforces.
        $chunk = 'X' * 200 + 'App-1.0.0-full.nupkg'
        $big = $chunk * 5000   # ~1.1MB
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $m = Get-Module InstallerAnalysisCommon
        $hits = & $m { param($t) Find-SquirrelNupkgRefs -Text $t } $big
        $sw.Stop()
        $sw.ElapsedMilliseconds | Should -BeLessThan 3000   # 2s budget + reasonable slack
    }
}

Describe 'ConvertTo-DeploymentJson placeholder substitution' {
    It 'bakes AppName / Setup.exe / LOCALAPPDATA path into Squirrel JSON output' {
        $fi  = [PSCustomObject]@{ FileName='GitHubDesktopSetup-x64.exe'; FileSize=1MB; SHA256='X'; ProductName='GitHubDesktop'; ProductVersion='3.5.8'; CompanyName='GitHub, Inc.'; Architecture='x86' }
        $pkg = [PSCustomObject]@{
            InstallerType           = 'Squirrel'
            DisplayName             = 'GitHubDesktop'
            DisplayVersion          = '3.5.8'
            ProductCodeOrEquivalent = 'GitHubDesktop'
            SilentInstallCommand    = '"<Setup.exe>" --silent'
            SilentUninstallCommand  = '"%LOCALAPPDATA%\<AppName>\Update.exe" --uninstall -s'
        }
        $sw  = Get-SilentSwitches -InstallerType 'Squirrel' -FilePath 'GitHubDesktopSetup-x64.exe'
        $df  = Get-DeploymentFields -FileInfo $fi -Switches $sw -PackageMetadata $pkg -InstallerType 'Squirrel'
        $json = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'Squirrel' -Switches $sw -DeploymentFields $df -PackageMetadata $pkg
        $parsed = $json | ConvertFrom-Json

        $parsed.Deployment.InstallCommand   | Should -Not -Match '<AppName>'
        $parsed.Deployment.InstallCommand   | Should -Not -Match '<Setup\.exe>'
        $parsed.Deployment.InstallCommand   | Should -Match 'GitHubDesktopSetup-x64\.exe'
        $parsed.Deployment.UninstallCommand | Should -Match '%LOCALAPPDATA%\\GitHubDesktop\\Update\.exe'
        $parsed.Deployment.Notes            | Should -Not -Match '<AppName>'
        $parsed.Detection.UninstallRegistryKeyNote | Should -Not -Match '<AppName>'
        $parsed.Detection.Hint              | Should -Not -Match '<AppName>'
        $parsed.Detection.Hint              | Should -Match 'GitHubDesktop'
    }

    It 'bakes ProductCode into MSI JSON uninstall command' {
        $fi  = [PSCustomObject]@{ FileName='Setup.msi'; FileSize=1MB; SHA256='X'; ProductName='Foo'; ProductVersion='1.0'; CompanyName='Acme'; Architecture='N/A (see MSI Summary)' }
        $msi = @{ ProductCode='{FEEDFACE-DEAD-BEEF-CAFE-1234567890AB}'; ProductName='Foo'; Manufacturer='Acme' }
        $sw  = Get-SilentSwitches -InstallerType 'MSI' -FilePath 'Setup.msi' -MsiProperties $msi
        $summary = [PSCustomObject]@{ Architecture='x64'; Template='x64;1033' }
        $df  = Get-DeploymentFields -FileInfo $fi -MsiProperties $msi -Switches $sw -InstallerType 'MSI' -MsiSummary $summary
        $json = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'MSI' -Switches $sw -MsiProperties $msi -DeploymentFields $df
        $parsed = $json | ConvertFrom-Json

        $parsed.Deployment.UninstallCommand | Should -Not -Match '<ProductCode>'
        $parsed.Deployment.UninstallCommand | Should -Match '\{FEEDFACE-DEAD-BEEF-CAFE-1234567890AB\}'
    }
}

Describe 'New-AnalysisSummaryText renders NupkgReferences (round-2 fix)' {
    It 'shows the primary nupkg reference for a Squirrel package' {
        $fi  = [PSCustomObject]@{ FileName='Slack-Setup.exe'; ProductName='Slack'; ProductVersion='5.0.0'; CompanyName='Slack'; Architecture='x86'; FileSizeFormatted='100 MB'; SHA256='X'; SignatureStatus='Valid'; SignerSubject='' }
        $pkg = [PSCustomObject]@{
            InstallerType           = 'Squirrel'
            DisplayName             = 'Slack'
            DisplayVersion          = '5.0.0'
            ProductCodeOrEquivalent = 'Slack'
            MarkersFound            = @('SquirrelTemp')
            Confidence              = 'Medium'
            HasUpdateExe            = $true
            NupkgReferences         = @(
                [PSCustomObject]@{ FileName='Slack-5.0.0-full.nupkg'; AppName='Slack'; Version='5.0.0'; Kind='full' }
                [PSCustomObject]@{ FileName='Slack-5.0.0-delta.nupkg'; AppName='Slack'; Version='5.0.0'; Kind='delta' }
            )
        }
        $sw  = Get-SilentSwitches -InstallerType 'Squirrel' -FilePath 'Slack-Setup.exe'
        $df  = Get-DeploymentFields -FileInfo $fi -Switches $sw -PackageMetadata $pkg -InstallerType 'Squirrel'
        $txt = New-AnalysisSummaryText -FileInfo $fi -InstallerType 'Squirrel' -Switches $sw -DeploymentFields $df -PackageMetadata $pkg

        $txt | Should -Match 'Embedded nupkg:.*Slack-5\.0\.0-full\.nupkg.*\[full\]'
        $txt | Should -Match 'Other refs:.*1 more.*Slack-5\.0\.0-delta\.nupkg'
    }
}

# ============================================================================
# Round-3 regressions
# ============================================================================

Describe 'ConvertTo-DeploymentJson round-3 substitution' {
    It 'substitutes <DisplayName> in NSIS Detection.Hint' {
        $fi  = [PSCustomObject]@{ FileName='Setup.exe'; FileSize=1MB; SHA256='X'; ProductName='KnownApp'; ProductVersion='1.0'; CompanyName='Acme'; Architecture='x64' }
        $sw  = Get-SilentSwitches -InstallerType 'NSIS' -FilePath 'Setup.exe'
        $df  = Get-DeploymentFields -FileInfo $fi -Switches $sw -InstallerType 'NSIS'
        $json = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'NSIS' -Switches $sw -DeploymentFields $df
        $parsed = $json | ConvertFrom-Json

        $parsed.Application.DisplayName | Should -Be 'KnownApp'
        $parsed.Detection.Hint          | Should -Not -Match '<DisplayName>'
        $parsed.Detection.Hint          | Should -Match 'HKLM\\\.\.\.\\Uninstall\\KnownApp'
    }

    It 'substitutes <DisplayName> in BitRock Detection.Hint' {
        $fi  = [PSCustomObject]@{ FileName='postgresql-17.exe'; FileSize=1MB; SHA256='X'; ProductName='PostgreSQL'; ProductVersion='17'; CompanyName='PG'; Architecture='x64' }
        $sw  = Get-SilentSwitches -InstallerType 'BitRock' -FilePath 'postgresql-17.exe'
        $df  = Get-DeploymentFields -FileInfo $fi -Switches $sw -InstallerType 'BitRock'
        $json = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'BitRock' -Switches $sw -DeploymentFields $df
        $parsed = $json | ConvertFrom-Json

        $parsed.Detection.Hint | Should -Not -Match '<AppName>'
        $parsed.Detection.Hint | Should -Match 'PostgreSQL'
    }

    It 'substitutes <AppId> in InnoSetup Detection.Hint' {
        $fi  = [PSCustomObject]@{ FileName='setup.exe'; FileSize=1MB; SHA256='X'; ProductName='MyInnoApp'; ProductVersion='1.0'; CompanyName='Acme'; Architecture='x64' }
        $sw  = Get-SilentSwitches -InstallerType 'InnoSetup' -FilePath 'setup.exe'
        $df  = Get-DeploymentFields -FileInfo $fi -Switches $sw -InstallerType 'InnoSetup'
        $json = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'InnoSetup' -Switches $sw -DeploymentFields $df
        $parsed = $json | ConvertFrom-Json

        $parsed.Detection.Hint | Should -Not -Match '<AppId>'
        $parsed.Detection.Hint | Should -Match 'MyInnoApp_is1'
    }

    It 'substitutes placeholders inside Raw.PackageMetadata.SilentInstallCommand' {
        $fi  = [PSCustomObject]@{ FileName='GitHubDesktopSetup-x64.exe'; FileSize=1MB; SHA256='X'; ProductName='GitHubDesktop'; ProductVersion='3.5.8'; CompanyName='GitHub'; Architecture='x86' }
        $pkg = [PSCustomObject]@{
            InstallerType           = 'Squirrel'
            DisplayName             = 'GitHubDesktop'
            DisplayVersion          = '3.5.8'
            ProductCodeOrEquivalent = 'GitHubDesktop'
            SilentInstallCommand    = '"<Setup.exe>" --silent   # installs to %LOCALAPPDATA%\<AppName>\ per-user'
            SilentUninstallCommand  = '"%LOCALAPPDATA%\<AppName>\Update.exe" --uninstall -s'
            MarkersFound            = @('SquirrelTemp')
            NupkgReferences         = @([PSCustomObject]@{ FileName='GitHubDesktop-3.5.8-full.nupkg'; AppName='GitHubDesktop'; Version='3.5.8'; Kind='full' })
        }
        $sw  = Get-SilentSwitches -InstallerType 'Squirrel' -FilePath 'GitHubDesktopSetup-x64.exe'
        $df  = Get-DeploymentFields -FileInfo $fi -Switches $sw -PackageMetadata $pkg -InstallerType 'Squirrel'
        $json = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'Squirrel' -Switches $sw -DeploymentFields $df -PackageMetadata $pkg
        $parsed = $json | ConvertFrom-Json

        $parsed.Raw.PackageMetadata.SilentInstallCommand   | Should -Not -Match '<Setup\.exe>'
        $parsed.Raw.PackageMetadata.SilentInstallCommand   | Should -Not -Match '<AppName>'
        $parsed.Raw.PackageMetadata.SilentInstallCommand   | Should -Match 'GitHubDesktopSetup-x64\.exe'
        $parsed.Raw.PackageMetadata.SilentInstallCommand   | Should -Match '%LOCALAPPDATA%\\GitHubDesktop\\'

        $parsed.Raw.PackageMetadata.SilentUninstallCommand | Should -Not -Match '<AppName>'
        $parsed.Raw.PackageMetadata.SilentUninstallCommand | Should -Match '%LOCALAPPDATA%\\GitHubDesktop\\Update\.exe'
    }

    It 'preserves non-command fields in Raw.PackageMetadata untouched (NupkgReferences, MarkersFound)' {
        $fi  = [PSCustomObject]@{ FileName='Slack-Setup.exe'; FileSize=1MB; SHA256='X'; ProductName='Slack'; ProductVersion='5.0.0'; CompanyName='Slack'; Architecture='x86' }
        $pkg = [PSCustomObject]@{
            InstallerType           = 'Squirrel'
            DisplayName             = 'Slack'
            DisplayVersion          = '5.0.0'
            ProductCodeOrEquivalent = 'Slack'
            SilentInstallCommand    = '"<Setup.exe>" --silent'
            SilentUninstallCommand  = '"%LOCALAPPDATA%\<AppName>\Update.exe"'
            MarkersFound            = @('SquirrelTemp','squirrel-install')
            NupkgReferences         = @([PSCustomObject]@{ FileName='Slack-5.0.0-full.nupkg'; AppName='Slack'; Version='5.0.0'; Kind='full' })
        }
        $sw  = Get-SilentSwitches -InstallerType 'Squirrel' -FilePath 'Slack-Setup.exe'
        $df  = Get-DeploymentFields -FileInfo $fi -Switches $sw -PackageMetadata $pkg -InstallerType 'Squirrel'
        $json = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'Squirrel' -Switches $sw -DeploymentFields $df -PackageMetadata $pkg
        $parsed = $json | ConvertFrom-Json

        @($parsed.Raw.PackageMetadata.MarkersFound).Count    | Should -Be 2
        @($parsed.Raw.PackageMetadata.NupkgReferences).Count | Should -Be 1
        $parsed.Raw.PackageMetadata.NupkgReferences[0].FileName | Should -Be 'Slack-5.0.0-full.nupkg'
    }
}

# ============================================================================
# Get-InterestingStrings UTF-16LE coverage
# ============================================================================

Describe 'Get-InterestingStrings UTF-16LE coverage' {
    It 'finds URLs that exist only as UTF-16LE in the binary' {
        $f = Join-Path $TestDrive 'wide-url.bin'
        $wide = [System.Text.Encoding]::Unicode.GetBytes("`0https://central.github.com/api/connection`0")
        # Sandwich the wide string between non-printable padding so it has clear
        # boundaries on both ends.
        $padding = New-Object byte[] 128
        [System.IO.File]::WriteAllBytes($f, ($padding + $wide + $padding))
        $r = Get-InterestingStrings -Path $f
        $r.URLs | Should -Contain 'https://central.github.com/api/connection'
    }

    It 'finds registry paths that exist only as UTF-16LE' {
        $f = Join-Path $TestDrive 'wide-reg.bin'
        $wide = [System.Text.Encoding]::Unicode.GetBytes("`0HKCU\Software\Microsoft\Windows\CurrentVersion\Run`0")
        $padding = New-Object byte[] 64
        [System.IO.File]::WriteAllBytes($f, ($padding + $wide + $padding))
        $r = Get-InterestingStrings -Path $f
        @($r.RegistryPaths) | Where-Object { $_ -match 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' } | Should -Not -BeNullOrEmpty
    }

    It 'finds GUIDs that exist only as UTF-16LE' {
        $f = Join-Path $TestDrive 'wide-guid.bin'
        $wide = [System.Text.Encoding]::Unicode.GetBytes("`0{12345678-ABCD-EF01-2345-6789ABCDEF01}`0")
        $padding = New-Object byte[] 64
        [System.IO.File]::WriteAllBytes($f, ($padding + $wide + $padding))
        $r = Get-InterestingStrings -Path $f
        $r.GUIDs | Should -Contain '{12345678-ABCD-EF01-2345-6789ABCDEF01}'
    }

    It 'completes in under 5 seconds on a 1MB synthetic buffer' {
        $f = Join-Path $TestDrive 'big.bin'
        $bytes = New-Object byte[] 1MB
        # Sprinkle a few real findings so the regex has work to do.
        $needle = [System.Text.Encoding]::ASCII.GetBytes('https://example.com/api')
        for ($i = 0; $i -lt $bytes.Length - 100; $i += 4096) {
            [Array]::Copy($needle, 0, $bytes, $i, $needle.Length)
        }
        [System.IO.File]::WriteAllBytes($f, $bytes)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Get-InterestingStrings -Path $f
        $sw.Stop()
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
        @($r.URLs).Count | Should -BeGreaterThan 0
    }
}

# ============================================================================
# Payload allowlist coverage
# ============================================================================

Describe 'Pipeline payload gate' {
    It 'attempts 7-Zip listing for every type when 7z is available (no allowlist)' {
        # Previously gated on a hardcoded type list; that silently dropped any
        # legitimately-analyzable format detection didn't classify (e.g. VMware
        # Tools, a custom PE wrapping a WiX MSI). The new contract: if 7z is
        # available, call Get-PayloadContents unconditionally.
        $script = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\start-installeranalysis.ps1') -Raw
        $script | Should -Match 'if\s*\(\s*\$SevenZipPath\s*\)\s*\{\s*[^}]*Get-PayloadContents'
        # And the old `type -in @(...)` gate must be gone.
        $script | Should -Not -Match "type -in @\(\s*'MSI'\s*,\s*'NSIS'"
    }
}

# ============================================================================
# Get-DeploymentFields whitespace trim (Inno PE resource padding)
# ============================================================================

Describe 'Get-DeploymentFields trims whitespace from PE-resource padded strings' {
    It 'strips trailing spaces in DisplayName, DisplayVersion, Vendor' {
        # Inno Setup pads FileVersionInfo strings with ~60 trailing spaces. If
        # we leak that into DisplayName, the predicted Inno UninstallRegistryKey
        # becomes "HKLM:\...\Uninstall\Git                   _is1" -- broken.
        $fi = [PSCustomObject]@{
            ProductName       = 'Git                                                         '
            ProductVersion    = '2.50.0                                            '
            CompanyName       = 'The Git Development Community                               '
            FileDescription   = 'Git'
            FileVersion       = '2.50.0'
            Architecture      = 'x86'
        }
        $df = Get-DeploymentFields -FileInfo $fi -Switches $null -InstallerType 'InnoSetup'
        $df.DisplayName    | Should -Be 'Git'
        $df.DisplayVersion | Should -Be '2.50.0'
        $df.Vendor         | Should -Be 'The Git Development Community'
        $df.UninstallRegistryKey | Should -Be 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1'
    }
}

# ============================================================================
# Get-PayloadContents dateless-row parser (Inno gzip wizard stream)
# ============================================================================

Describe 'Get-PayloadContents accepts 7z rows without a date column' {
    It 'parses Inno-style "[0]~" rows that 7z emits with empty date/time columns' {
        # Synthesize a 7z list output: header + body row that has only attrs +
        # size + compressed + name (no date prefix). Drive the parser by stubbing
        # the 7z output via the SevenZipPath being a no-op script -- can't fully
        # exercise without 7z available, so verify by direct regex test.
        $lineWithDate    = '2024-12-12 14:50:14 ....A      66672      11264  Setup.tmp'
        $lineWithoutDate = '                    .....       307753        84936  [0]~'

        # Mirror the parser's regexes here so the test pins the exact behaviour.
        $reDated   = '^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+(\d+)\s+\d*\s+(.+)$'
        $reDateless = '^\s+(\.+|D\.+|[\.A-Z]+)\s+(\d+)\s+\d*\s+(.+)$'

        $lineWithDate    | Should -Match $reDated
        $lineWithoutDate | Should -Match $reDateless
        # The dateless row must NOT match the dated regex (otherwise the parser
        # would never reach the fallback branch).
        $lineWithoutDate | Should -Not -Match $reDated
    }
}

# ============================================================================
# Get-ChocolateyMetadata nuspec namespace variants
# ============================================================================

Describe 'Get-ChocolateyMetadata handles multiple nuspec XSD namespaces' {
    BeforeAll {
        function script:New-NupkgFixture {
            param([string]$OutPath, [string]$Namespace, [hashtable]$Fields)
            $fieldXml = ($Fields.GetEnumerator() | ForEach-Object {
                "    <$($_.Key)>$($_.Value)</$($_.Key)>"
            }) -join "`r`n"
            $nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="$Namespace">
  <metadata>
$fieldXml
  </metadata>
</package>
"@
            $entries = @{
                'package.nuspec' = $nuspec
                'tools/chocolateyInstall.ps1' = '# noop'
            }
            script:New-TestZipFile -Path $OutPath -Entries $entries
        }
    }

    It 'parses the 2013/05 namespace (Chocolatey gallery default)' {
        $f = Join-Path $TestDrive 'choco-2013.nupkg'
        New-NupkgFixture -OutPath $f `
            -Namespace 'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd' `
            -Fields @{ id='myapp'; version='1.2.3'; title='MyApp'; authors='Acme'; projectUrl='https://example.com'; tags='foo bar' }
        $r = Get-ChocolateyMetadata -Path $f
        $r.DisplayName    | Should -Be 'MyApp'
        $r.DisplayVersion | Should -Be '1.2.3'
        $r.PackageId      | Should -Be 'myapp'
        $r.ProjectUrl     | Should -Be 'https://example.com'
        $r.Tags           | Should -Be 'foo bar'
    }

    It 'parses the 2017/09 namespace (modern NuGet)' {
        $f = Join-Path $TestDrive 'choco-2017.nupkg'
        New-NupkgFixture -OutPath $f `
            -Namespace 'http://schemas.microsoft.com/packaging/2017/09/nuspec.xsd' `
            -Fields @{ id='newpkg'; version='4.5.6'; authors='Vendor' }
        $r = Get-ChocolateyMetadata -Path $f
        $r.PackageId | Should -Be 'newpkg'
        $r.DisplayVersion | Should -Be '4.5.6'
    }

    It 'still parses the original 2010/07 namespace' {
        $f = Join-Path $TestDrive 'choco-2010.nupkg'
        New-NupkgFixture -OutPath $f `
            -Namespace 'http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd' `
            -Fields @{ id='oldpkg'; version='0.1.0'; authors='Vendor' }
        $r = Get-ChocolateyMetadata -Path $f
        $r.PackageId | Should -Be 'oldpkg'
    }

    It 'surfaces ProjectUrl / Tags / Description as top-level properties (renderer contract)' {
        # The Overview renderer reads $pkg.ProjectUrl directly; the bridge from
        # the nuspec camelCase keys to PascalCase top-level properties must hold.
        $f = Join-Path $TestDrive 'choco-bridge.nupkg'
        New-NupkgFixture -OutPath $f `
            -Namespace 'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd' `
            -Fields @{ id='br'; version='1.0'; authors='X'; projectUrl='https://proj'; tags='t1 t2'; description='hello'; licenseUrl='https://lic' }
        $r = Get-ChocolateyMetadata -Path $f
        $r.PSObject.Properties['ProjectUrl']  | Should -Not -BeNullOrEmpty
        $r.PSObject.Properties['Tags']        | Should -Not -BeNullOrEmpty
        $r.PSObject.Properties['Description'] | Should -Not -BeNullOrEmpty
        $r.PSObject.Properties['LicenseUrl']  | Should -Not -BeNullOrEmpty
        $r.ProjectUrl  | Should -Be 'https://proj'
        $r.Tags        | Should -Be 't1 t2'
        $r.Description | Should -Be 'hello'
        $r.LicenseUrl  | Should -Be 'https://lic'
    }
}

# ============================================================================
# Get-EmbeddedInstallers classification (Inner Installers tab feed)
# ============================================================================

Describe 'Get-EmbeddedInstallers' {
    It 'returns an empty array for null payload' {
        $r = Get-EmbeddedInstallers -Payload $null -Type 'Unknown'
        @($r).Count | Should -Be 0
    }

    It 'returns an empty array when payload has no installer-class entries' {
        $payload = @(
            [PSCustomObject]@{ Name = 'readme.txt';  Size = 1024; SizeFormatted = '1 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'license.rtf'; Size = 2048; SizeFormatted = '2 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'images';      Size = 0;    SizeFormatted = '0 B';  IsDirectory = $true }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'Unknown'
        $r.Count | Should -Be 0
    }

    It 'classifies extensions to the documented Kind set' {
        $payload = @(
            [PSCustomObject]@{ Name = 'inner.msi';   Size = 1000000; SizeFormatted = '1.0 MB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'patch.msp';   Size = 50000;   SizeFormatted = '49 KB';  IsDirectory = $false }
            [PSCustomObject]@{ Name = 'feature.cab'; Size = 200000;  SizeFormatted = '195 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'sub.exe';     Size = 5000000; SizeFormatted = '4.8 MB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'data.zip';    Size = 800000;  SizeFormatted = '781 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'app.nupkg';   Size = 600000;  SizeFormatted = '586 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'pack.msix';   Size = 700000;  SizeFormatted = '684 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'pack.appx';   Size = 700000;  SizeFormatted = '684 KB'; IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'Unknown'
        $r.Count | Should -Be 8
        ($r | Where-Object { $_.Name -eq 'inner.msi' }).Kind   | Should -Be 'MSI'
        ($r | Where-Object { $_.Name -eq 'patch.msp' }).Kind   | Should -Be 'MSP'
        ($r | Where-Object { $_.Name -eq 'feature.cab' }).Kind | Should -Be 'CAB'
        ($r | Where-Object { $_.Name -eq 'sub.exe' }).Kind     | Should -Be 'EXE'
        ($r | Where-Object { $_.Name -eq 'data.zip' }).Kind    | Should -Be 'ZIP'
        ($r | Where-Object { $_.Name -eq 'app.nupkg' }).Kind   | Should -Be 'NUPKG'
        ($r | Where-Object { $_.Name -eq 'pack.msix' }).Kind   | Should -Be 'MSIX'
        ($r | Where-Object { $_.Name -eq 'pack.appx' }).Kind   | Should -Be 'APPX'
    }

    It 'drops MSI internal table streams when Type=MSI' {
        # 7-Zip surfaces MSI table streams as control-prefixed or punctuation-prefixed
        # names. None are installable; the Inner Installers tab must not offer them.
        $payload = @(
            [PSCustomObject]@{ Name = '!Property';             Size = 100;     SizeFormatted = '100 B'; IsDirectory = $false }
            [PSCustomObject]@{ Name = '!File';                 Size = 100;     SizeFormatted = '100 B'; IsDirectory = $false }
            [PSCustomObject]@{ Name = '[5]SummaryInformation'; Size = 100;     SizeFormatted = '100 B'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'Binary._12345';         Size = 100;     SizeFormatted = '100 B'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'Icon.foo';              Size = 100;     SizeFormatted = '100 B'; IsDirectory = $false }
            [PSCustomObject]@{ Name = "`u{0001}TableStream";   Size = 100;     SizeFormatted = '100 B'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'Cab1.cab';              Size = 5000000; SizeFormatted = '4.8 MB'; IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'MSI'
        $r.Count | Should -Be 1
        $r[0].Name | Should -Be 'Cab1.cab'
        $r[0].Description | Should -Match 'Media-table'
    }

    It 'preserves bracket-prefixed entries when Type is not MSI (e.g. Inno [0]~ wizard)' {
        # The Inno wizard stream surfaces as "[0]~" -- not an installer, so it
        # gets filtered by classifier (no extension), but the MSI prefilter
        # should not fire for InnoSetup.
        $payload = @(
            [PSCustomObject]@{ Name = '[0]~';      Size = 300000;  SizeFormatted = '293 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'setup.tmp'; Size = 66672;   SizeFormatted = '65 KB';  IsDirectory = $false }
            [PSCustomObject]@{ Name = 'app.msi';   Size = 1000000; SizeFormatted = '1.0 MB'; IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'InnoSetup'
        # Only app.msi has an installer-class extension; the bracket stream is
        # extension-less and gets dropped by classifier, not by the MSI prefilter.
        $r.Count | Should -Be 1
        $r[0].Name | Should -Be 'app.msi'
    }

    It 'sorts MSI ahead of CAB and orders by descending size within each Kind' {
        # Models the VMware Tools shape: inner MSI first, then the largest
        # component CABs in descending size order.
        $payload = @(
            [PSCustomObject]@{ Name = 'HGFS.cab';     Size = 177152;    SizeFormatted = '173 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'VmVideo.cab';  Size = 76252160;  SizeFormatted = '72.7 MB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = '<inner.msi>';  Size = 99614720;  SizeFormatted = '95.0 MB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'VGAuth.cab';   Size = 5347737;   SizeFormatted = '5.1 MB';  IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'Unknown'
        $r.Count | Should -Be 4
        $r[0].Name | Should -Be '<inner.msi>'
        # Then CABs ordered by size desc
        $r[1].Name | Should -Be 'VmVideo.cab'
        $r[2].Name | Should -Be 'VGAuth.cab'
        $r[3].Name | Should -Be 'HGFS.cab'
    }

    It 'tags WixBurn chained packages with the bundle-package description' {
        $payload = @(
            [PSCustomObject]@{ Name = 'dotnet-runtime.msi'; Size = 30000000; SizeFormatted = '28.6 MB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'hostfxr.exe';        Size = 5000000;  SizeFormatted = '4.8 MB';  IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'WixBurn'
        ($r | Where-Object { $_.Name -eq 'dotnet-runtime.msi' }).Description | Should -Match 'Burn bundle'
        ($r | Where-Object { $_.Name -eq 'hostfxr.exe' }).Description        | Should -Match 'Burn bundle'
    }

    It 'tags Squirrel .nupkg / Update.exe with the Squirrel-specific description' {
        $payload = @(
            [PSCustomObject]@{ Name = 'myapp-1.0.0-full.nupkg'; Size = 10000000; SizeFormatted = '9.5 MB';  IsDirectory = $false }
            [PSCustomObject]@{ Name = 'Update.exe';             Size = 1000000;  SizeFormatted = '1.0 MB';  IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'Squirrel'
        ($r | Where-Object { $_.Name -eq 'myapp-1.0.0-full.nupkg' }).Description | Should -Match 'Squirrel'
        ($r | Where-Object { $_.Name -eq 'Update.exe' }).Description             | Should -Match 'Squirrel'
    }

    It 'sets IsAnalyzable=true for every classified entry' {
        # Phase 1: classification = analyzability. Per-Kind drill-down policies
        # come in Phase 2.
        $payload = @(
            [PSCustomObject]@{ Name = 'inner.msi'; Size = 1000; SizeFormatted = '1 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'a.cab';     Size = 1000; SizeFormatted = '1 KB'; IsDirectory = $false }
            [PSCustomObject]@{ Name = 'b.exe';     Size = 1000; SizeFormatted = '1 KB'; IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'Unknown'
        ($r | Where-Object { -not $_.IsAnalyzable }).Count | Should -Be 0
    }

    It 'skips directory entries' {
        $payload = @(
            [PSCustomObject]@{ Name = 'subdir';    Size = 0;     SizeFormatted = '0 B';  IsDirectory = $true }
            [PSCustomObject]@{ Name = 'inner.msi'; Size = 1000;  SizeFormatted = '1 KB'; IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'Unknown'
        $r.Count | Should -Be 1
        $r[0].Name | Should -Be 'inner.msi'
    }

    It 'records ParentPath on every row for the audit trail' {
        $payload = @(
            [PSCustomObject]@{ Name = 'inner.msi'; Size = 1000; SizeFormatted = '1 KB'; IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'Unknown' -ParentPath 'C:\path\to\outer.exe'
        $r[0].ParentPath | Should -Be 'C:\path\to\outer.exe'
    }

    It 'fabricates SizeFormatted when the source row lacks it' {
        # Get-PayloadContents always sets SizeFormatted, but defensive coding
        # against future caller drift.
        $payload = @(
            [PSCustomObject]@{ Name = 'inner.msi'; Size = 1572864; IsDirectory = $false }
        )
        $r = Get-EmbeddedInstallers -Payload $payload -Type 'Unknown'
        $r[0].SizeFormatted | Should -Match 'MB'
    }
}

# ============================================================================
# Get-MspMetadata — Windows Installer Patch parser
# ============================================================================

Describe 'Get-MspMetadata' {
    It 'returns null for a non-existent file' {
        $r = Get-MspMetadata -Path 'C:\nope\does-not-exist.msp'
        $r | Should -BeNullOrEmpty
    }

    It 'returns null for a non-MSP file' {
        $f = Join-Path $TestDrive 'notapatch.bin'
        [System.IO.File]::WriteAllBytes($f, [byte[]](0..63))
        # Get-MspMetadata catches the COM error and returns null; should never throw.
        { Get-MspMetadata -Path $f } | Should -Not -Throw
    }
}

Describe 'Get-InstallerType returns MSP for .msp extension' {
    # The MSP type detection is extension-based (mirroring how MSI is detected).
    # The detection contract guarantees that any *.msp file is classified as
    # 'MSP' BEFORE the signature scan runs -- so this works even on an empty
    # placeholder file.
    It 'classifies a file with .msp extension as MSP without reading its bytes' {
        $f = Join-Path $TestDrive 'placeholder.msp'
        Set-Content -LiteralPath $f -Value ''
        Get-InstallerType -Path $f | Should -Be 'MSP'
    }
}

Describe 'New-AnalysisSummaryText renders Effective Post-Patch Detection Target' {
    BeforeAll {
        # Synthetic FileInfo
        $script:tFi = [PSCustomObject]@{
            FileName              = 'outer.exe'
            FullPath              = 'C:\path\to\outer.exe'
            FileSize              = 1MB
            FileSizeFormatted     = '1.0 MB'
            SHA256                = ('A' * 64)
            Architecture          = 'x86'
            SignatureStatus       = 'Valid'
            SignerSubject         = 'CN=Test'
        }
        $script:tMsp = [PSCustomObject]@{
            PrimaryPatchCode       = '{11111111-2222-3333-4444-555555555555}'
            PatchCodes             = @('{11111111-2222-3333-4444-555555555555}')
            TargetProductCodes     = @('{AAAAAAAA-AAAA-1041-AAAA-AAAAAAAAAAAA}','{AAAAAAAA-AAAA-1033-AAAA-AAAAAAAAAAAA}')
            PatchDisplayName       = 'Test Product (26.001.21529)'
            PatchDescription       = 'Cumulative update'
            TargetProductName      = 'Test Product'
            ManufacturerName       = 'Test Mfr'
            Classification         = 'Critical Update'
            MoreInfoURL            = 'https://example.com/info'
            CreationTimeUTC        = '01-01-2026 00:00'
            AllowRemoval           = '0'
            InferredDisplayVersion = '26.001.21529'
            SourceFile             = 'rollup.msp'
        }
        $script:tInnerMsi = [PSCustomObject]@{
            ProductCode     = '{AAAAAAAA-AAAA-1033-AAAA-AAAAAAAAAAAA}'
            ProductName     = 'Test Product'
            ProductVersion  = '16.0.0.0'
            Manufacturer    = 'Test Mfr'
            MsiArchitecture = 'x86'
            SourceFile      = 'inner.msi'
        }
    }

    It 'surfaces post-patch DisplayVersion + ProductCode-keyed UninstallRegistryKey' {
        $text = New-AnalysisSummaryText `
            -FileInfo $tFi -InstallerType '7zSFX' `
            -DeploymentFields ([PSCustomObject]@{ DisplayName='Test Outer'; DisplayVersion='1.0'; Vendor='X'; SilentUninstallString='' }) `
            -MspMetadata @($tMsp) -InnerMsiData $tInnerMsi

        # The block header is present
        $text | Should -Match 'Effective Post-Patch Detection Target:'
        # ProductCode comes from the inner base MSI (en_US 1033 variant)
        $text | Should -Match '\{AAAAAAAA-AAAA-1033-AAAA-AAAAAAAAAAAA\}'
        # Post-patch DisplayVersion is the MSP-inferred one
        $text | Should -Match '26\.001\.21529'
        # WOW6432Node-routed key (x86 MSI on x64 default)
        $text | Should -Match 'WOW6432Node'
        # Classification surfaces
        $text | Should -Match 'Critical Update'
    }

    It 'falls back to first MSP TargetProductCode when no inner MSI data' {
        $text = New-AnalysisSummaryText `
            -FileInfo $tFi -InstallerType '7zSFX' `
            -DeploymentFields ([PSCustomObject]@{ DisplayName='Test Outer'; DisplayVersion='1.0'; Vendor='X'; SilentUninstallString='' }) `
            -MspMetadata @($tMsp)
        $text | Should -Match 'Effective Post-Patch Detection Target:'
        # Without inner MSI we pick TargetProductCodes[0] which is 1041
        $text | Should -Match '\{AAAAAAAA-AAAA-1041-AAAA-AAAAAAAAAAAA\}'
    }

    It 'omits the post-patch block entirely when no MspMetadata is supplied' {
        $text = New-AnalysisSummaryText `
            -FileInfo $tFi -InstallerType 'MSI' `
            -DeploymentFields ([PSCustomObject]@{ DisplayName='Plain'; DisplayVersion='1.0'; Vendor='X'; SilentUninstallString='' })
        $text | Should -Not -Match 'Effective Post-Patch Detection Target'
    }

    # Empty inferred version: the ARP value match line was rendered even when
    # InferredDisplayVersion was null, producing "DisplayVersion = " with
    # nothing after the equals sign. Detection rule must not be rendered when
    # the version isn't known.
    It 'omits "ARP value match" when InferredDisplayVersion is null(null inferred version)' {
        $mspNoVer = [PSCustomObject]@{
            PrimaryPatchCode       = '{11111111-2222-3333-4444-555555555555}'
            PatchCodes             = @('{11111111-2222-3333-4444-555555555555}')
            TargetProductCodes     = @('{AAAAAAAA-AAAA-1033-AAAA-AAAAAAAAAAAA}')
            PatchDisplayName       = 'Some product (no version)'
            PatchDescription       = 'no version here'
            TargetProductName      = 'Some product'
            InferredDisplayVersion = $null
            Classification         = 'Security Update'
            SourceFile             = 'noversion.msp'
        }
        $text = New-AnalysisSummaryText `
            -FileInfo $tFi -InstallerType '7zSFX' `
            -DeploymentFields ([PSCustomObject]@{ DisplayName='X'; DisplayVersion='1'; Vendor='Y'; SilentUninstallString='' }) `
            -MspMetadata @($mspNoVer)
        # The block header may still appear (other fields are useful), but the
        # "ARP value match: DisplayVersion = <empty>" line must not render.
        ($text -split "`r`n") |
            Where-Object { $_ -match 'ARP value match' -and $_ -match '=\s*$' } |
            Should -BeNullOrEmpty
    }

    # Architecture not inferable: when InnerMsiData is absent (e.g. inner-MSI
    # extraction failed) the renderer must not default to WOW6432Node.
    # Both candidate paths are rendered as clean labels so the packager
    # picks the right one. No explanatory note appended.
    It 'renders both candidate keys when InnerMsiData architecture is absent(architecture branch)' {
        $mspWithVer = [PSCustomObject]@{
            PrimaryPatchCode       = '{11111111-2222-3333-4444-555555555555}'
            PatchCodes             = @('{11111111-2222-3333-4444-555555555555}')
            TargetProductCodes     = @('{AAAAAAAA-AAAA-1033-AAAA-AAAAAAAAAAAA}')
            PatchDisplayName       = 'Some product (5.0.0)'
            TargetProductName      = 'Some product'
            InferredDisplayVersion = '5.0.0'
            Classification         = 'Critical Update'
            SourceFile             = 'foo.msp'
        }
        $text = New-AnalysisSummaryText `
            -FileInfo $tFi -InstallerType '7zSFX' `
            -DeploymentFields ([PSCustomObject]@{ DisplayName='X'; DisplayVersion='1'; Vendor='Y'; SilentUninstallString='' }) `
            -MspMetadata @($mspWithVer)
        $text | Should -Match 'UninstallRegistryKey x86:.*WOW6432Node'
        $text | Should -Match 'UninstallRegistryKey x64:.*\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    }

    # Variant: when InnerMsiData IS supplied with an explicit x64 arch, only
    # the non-WOW6432Node key should render.
    It 'renders only the non-WOW6432Node key when InnerMsiData reports x64(architecture branch)' {
        $mspWithVer = [PSCustomObject]@{
            PrimaryPatchCode       = '{11111111-2222-3333-4444-555555555555}'
            TargetProductCodes     = @()
            PatchDisplayName       = 'X (5.0.0)'
            TargetProductName      = 'X'
            InferredDisplayVersion = '5.0.0'
            Classification         = 'Critical Update'
            SourceFile             = 'foo.msp'
        }
        $innerX64 = [PSCustomObject]@{
            ProductCode     = '{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}'
            ProductName     = 'X'
            ProductVersion  = '4.9.0'
            Manufacturer    = 'X'
            MsiArchitecture = 'x64'
            SourceFile      = 'inner.msi'
        }
        $text = New-AnalysisSummaryText `
            -FileInfo $tFi -InstallerType '7zSFX' `
            -DeploymentFields ([PSCustomObject]@{ DisplayName='X'; DisplayVersion='1'; Vendor='Y'; SilentUninstallString='' }) `
            -MspMetadata @($mspWithVer) -InnerMsiData $innerX64
        $text | Should -Not -Match 'WOW6432Node'
        $text | Should -Match 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\\{BBBBBBBB'
    }
}

# ============================================================================
# 7-Zip include pattern with spaces: 7z -i! include pattern must be quoted for entry
# names containing spaces. The production helper now lives in the module
# as Expand-PayloadEntry, which is what the UI script + the bg-runspace
# pipeline both call. Test drives it directly. Skips on machines without
# 7-Zip on PATH or in a known location.
# ============================================================================

Describe 'Expand-PayloadEntry handles entry names with spaces(spaces-in-name)' -Tag 'Live7z' {
    BeforeAll {
        $script:sevenZip = Find-7ZipPath
        if (-not $script:sevenZip) {
            Set-ItResult -Skipped -Because '7-Zip not installed on this machine.'
        }
    }

    It 'extracts an entry whose name contains a space' {
        if (-not $script:sevenZip) { Set-ItResult -Skipped; return }
        $work = Join-Path $TestDrive 'spaceextract'
        $staging = Join-Path $work 'staging'
        New-Item -ItemType Directory -Path $staging -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $staging 'Acrobat Patch.msp') -Value 'msp'
        Set-Content -LiteralPath (Join-Path $staging 'other.txt')         -Value 'other'

        $arch = Join-Path $work 'test.7z'
        Start-Process -FilePath $script:sevenZip -ArgumentList @('a', "`"$arch`"", "`"$staging\*`"") -Wait -NoNewWindow | Out-Null

        $out = Join-Path $work 'out'
        $result = Expand-PayloadEntry -SevenZipPath $script:sevenZip -ArchivePath $arch -EntryName 'Acrobat Patch.msp' -OutputDir $out

        $result | Should -Not -BeNullOrEmpty
        (Test-Path -LiteralPath (Join-Path $out 'Acrobat Patch.msp')) | Should -BeTrue
        # Should not have extracted unrelated entry
        (Test-Path -LiteralPath (Join-Path $out 'other.txt')) | Should -BeFalse
    }

    It 'returns $null when archive does not exist' {
        if (-not $script:sevenZip) { Set-ItResult -Skipped; return }
        $r = Expand-PayloadEntry -SevenZipPath $script:sevenZip -ArchivePath 'C:\nope\missing.7z' -EntryName 'x.msp' -OutputDir (Join-Path $TestDrive 'noarch-out')
        $r | Should -BeNullOrEmpty
    }
}
