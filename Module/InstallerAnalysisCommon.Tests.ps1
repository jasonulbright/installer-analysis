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

BeforeAll {
    Import-Module "$PSScriptRoot\InstallerAnalysisCommon.psd1" -Force -DisableNameChecking
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
