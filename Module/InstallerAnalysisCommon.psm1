<#
.SYNOPSIS
    Core module for Installer Analysis Tool.

.DESCRIPTION
    Provides functions for analyzing installer files (EXE, MSI):
      - Structured logging
      - File identification (version info, PE architecture, digital signature)
      - Installer type detection (MSI, NSIS, Inno Setup, InstallShield, WiX Burn, etc.)
      - MSI property extraction (via PSGallery MSI module or COM fallback)
      - Silent install switch lookup
      - Payload extraction via 7-Zip
      - Binary string analysis
      - Export to CSV, HTML, clipboard

.EXAMPLE
    Import-Module "$PSScriptRoot\Module\InstallerAnalysisCommon.psd1" -Force
    $info = Get-InstallerFileInfo -Path "C:\temp\setup.exe"
    $type = Get-InstallerType -Path "C:\temp\setup.exe"
#>

# ---------------------------------------------------------------------------
# Module-scoped state
# ---------------------------------------------------------------------------

$script:__IATLogPath       = $null
$script:MsiModuleAvailable = $null

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Initialize-Logging {
    param([string]$LogPath)
    $script:__IATLogPath = $LogPath
    if ($LogPath) {
        $parentDir = Split-Path -Path $LogPath -Parent
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
        $header = "[{0}] [INFO ] === Log initialized ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Set-Content -LiteralPath $LogPath -Value $header -Encoding UTF8
    }
}

function Write-Log {
    param(
        [AllowEmptyString()][Parameter(Mandatory, Position = 0)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [switch]$Quiet
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $formatted = "[{0}] [{1,-5}] {2}" -f $timestamp, $Level, $Message
    if (-not $Quiet) {
        Write-Host $formatted
        if ($Level -eq 'ERROR') { $host.UI.WriteErrorLine($formatted) }
    }
    if ($script:__IATLogPath) {
        Add-Content -LiteralPath $script:__IATLogPath -Value $formatted -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# File Identification
# ---------------------------------------------------------------------------

function Get-PeArchitecture {
    <#
    .SYNOPSIS
        Reads PE header to determine architecture (x86/x64/ARM64).
    #>
    param([Parameter(Mandatory)][string]$Path)

    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $reader = New-Object System.IO.BinaryReader($stream)

        # MZ header check
        $mz = $reader.ReadUInt16()
        if ($mz -ne 0x5A4D) { $reader.Close(); $stream.Close(); return 'Not a PE' }

        # PE header offset at 0x3C
        $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $reader.ReadInt32()

        # PE signature
        $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peSignature = $reader.ReadUInt32()
        if ($peSignature -ne 0x00004550) { $reader.Close(); $stream.Close(); return 'Invalid PE' }

        # Machine type at PE+4
        $machineType = $reader.ReadUInt16()
        $reader.Close(); $stream.Close()

        switch ($machineType) {
            0x014C { return 'x86' }
            0x8664 { return 'x64' }
            0xAA64 { return 'ARM64' }
            0x01C0 { return 'ARM' }
            default { return "Unknown (0x$($machineType.ToString('X4')))" }
        }
    }
    catch {
        if ($reader) { try { $reader.Close() } catch {} }
        if ($stream) { try { $stream.Close() } catch {} }
        return 'Error'
    }
}

function Get-InstallerFileInfo {
    <#
    .SYNOPSIS
        Extracts file metadata: version info, PE architecture, digital signature, size, hash.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Write-Log "Analyzing file: $Path"

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $arch = if ($item.Extension -eq '.msi') { 'N/A (see MSI Summary)' } else { Get-PeArchitecture -Path $Path }
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash

    return [PSCustomObject]@{
        FileName         = $item.Name
        FullPath         = $item.FullName
        Extension        = $item.Extension
        FileSize         = $item.Length
        FileSizeFormatted = if ($item.Length -ge 1MB) { "{0:N1} MB" -f ($item.Length / 1MB) } else { "{0:N0} KB" -f ($item.Length / 1KB) }
        SHA256           = $hash
        FileVersion      = $versionInfo.FileVersion
        ProductVersion   = $versionInfo.ProductVersion
        ProductName      = $versionInfo.ProductName
        CompanyName      = $versionInfo.CompanyName
        FileDescription  = $versionInfo.FileDescription
        OriginalFilename = $versionInfo.OriginalFilename
        LegalCopyright   = $versionInfo.LegalCopyright
        Architecture     = $arch
        SignatureStatus  = if ($sig) { [string]$sig.Status } else { 'Unknown' }
        SignerSubject    = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
        SignerIssuer     = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { '' }
        SignerThumbprint = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { '' }
    }
}

function Get-InstallerType {
    <#
    .SYNOPSIS
        Detects installer framework by scanning binary signatures.
    .DESCRIPTION
        Returns one of: MSI, NSIS, InnoSetup, InstallShield, WixBurn, 7zSFX, WinRarSFX, AdvancedInstaller, Unknown
    #>
    param([Parameter(Mandatory)][string]$Path)

    # MSI by extension
    if ($Path -match '\.msi$') { return 'MSI' }

    Write-Log "Scanning binary signatures..."

    # Read first 512KB for signature scanning (or full file if smaller)
    $maxRead = 512KB
    $fileSize = (Get-Item -LiteralPath $Path).Length
    $readSize = [Math]::Min($maxRead, $fileSize)

    $stream = [System.IO.File]::OpenRead($Path)
    $bytes = New-Object byte[] $readSize
    $stream.Read($bytes, 0, $readSize) | Out-Null
    $stream.Close()

    $asciiText = [System.Text.Encoding]::ASCII.GetString($bytes)

    # OLE Compound Document (MSI in disguise, e.g., .exe wrapping MSI)
    if ($bytes.Length -ge 8 -and $bytes[0] -eq 0xD0 -and $bytes[1] -eq 0xCF -and $bytes[2] -eq 0x11 -and $bytes[3] -eq 0xE0) {
        return 'MSI'
    }

    # WiX Burn -- check first (specific marker, avoids false positives)
    if ($asciiText -match 'WixBundleManifest|\.wixburn') {
        return 'WixBurn'
    }

    # NSIS -- DEADBEEF marker (little-endian) + NullsoftInst
    if ($asciiText -match 'NullsoftInst|Nullsoft\.NSIS') {
        return 'NSIS'
    }
    # Also check for DEADBEEF magic in raw bytes
    for ($i = 0; $i -lt [Math]::Min($bytes.Length - 4, 64KB); $i++) {
        if ($bytes[$i] -eq 0xEF -and $bytes[$i+1] -eq 0xBE -and $bytes[$i+2] -eq 0xAD -and $bytes[$i+3] -eq 0xDE) {
            return 'NSIS'
        }
    }

    # Inno Setup
    if ($asciiText -match 'Inno Setup') {
        return 'InnoSetup'
    }

    # InstallShield
    if ($asciiText -match 'InstallShield') {
        return 'InstallShield'
    }

    # Advanced Installer
    if ($asciiText -match 'Advanced Installer') {
        return 'AdvancedInstaller'
    }

    # 7-Zip SFX -- look for 7z magic bytes anywhere in the file
    for ($i = 0; $i -lt [Math]::Min($bytes.Length - 6, $readSize); $i++) {
        if ($bytes[$i] -eq 0x37 -and $bytes[$i+1] -eq 0x7A -and $bytes[$i+2] -eq 0xBC -and
            $bytes[$i+3] -eq 0xAF -and $bytes[$i+4] -eq 0x27 -and $bytes[$i+5] -eq 0x1C) {
            return '7zSFX'
        }
    }
    if ($asciiText -match '!@InstallEnd@!') {
        return '7zSFX'
    }

    # WinRAR SFX -- RAR magic: 52 61 72 21 1A 07
    for ($i = 0; $i -lt [Math]::Min($bytes.Length - 7, $readSize); $i++) {
        if ($bytes[$i] -eq 0x52 -and $bytes[$i+1] -eq 0x61 -and $bytes[$i+2] -eq 0x72 -and
            $bytes[$i+3] -eq 0x21 -and $bytes[$i+4] -eq 0x1A -and $bytes[$i+5] -eq 0x07) {
            return 'WinRarSFX'
        }
    }

    return 'Unknown'
}

# ---------------------------------------------------------------------------
# MSI Analysis
# ---------------------------------------------------------------------------

function Test-MsiModuleAvailable {
    <#
    .SYNOPSIS
        Checks if the PSGallery MSI module is installed.
    #>
    if ($null -eq $script:MsiModuleAvailable) {
        $script:MsiModuleAvailable = $null -ne (Get-Module -ListAvailable -Name MSI -ErrorAction SilentlyContinue)
    }
    return $script:MsiModuleAvailable
}

function Get-MsiProperties {
    <#
    .SYNOPSIS
        Reads all properties from an MSI Property table.
    .DESCRIPTION
        Uses PSGallery MSI module if available, otherwise falls back to COM interop.
    #>
    param([Parameter(Mandatory)][string]$MsiPath)

    Write-Log "Reading MSI properties: $MsiPath"

    # Try PSGallery MSI module first
    if (Test-MsiModuleAvailable) {
        try {
            Write-Log "Using MSI module for property extraction"
            Import-Module MSI -ErrorAction Stop
            $props = Get-MSIProperty -Path $MsiPath -ErrorAction Stop
            $result = [ordered]@{}
            foreach ($p in $props) {
                $result[$p.Property] = $p.Value
            }
            Write-Log "Read $($result.Count) MSI properties via MSI module"
            return $result
        }
        catch {
            Write-Log "MSI module failed, falling back to COM: $_" -Level WARN
        }
    }

    # COM interop fallback
    Write-Log "Using COM interop for MSI property extraction"
    $installer = $null; $db = $null; $view = $null; $record = $null

    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db = $installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installer, @($MsiPath, 0))

        $sql = 'SELECT Property, Value FROM Property'
        $view = $db.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $db, @($sql))
        $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null

        $result = [ordered]@{}
        do {
            $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
            if ($null -ne $record) {
                $propName = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
                $propValue = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 2)
                $result[$propName] = $propValue
                [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) | Out-Null
                $record = $null
            }
        } while ($null -ne $record)

        Write-Log "Read $($result.Count) MSI properties via COM"
        return $result
    }
    catch {
        Write-Log "Failed to read MSI properties: $_" -Level ERROR
        return [ordered]@{}
    }
    finally {
        foreach ($o in @($record, $view, $db, $installer)) {
            if ($null -ne $o -and [System.Runtime.InteropServices.Marshal]::IsComObject($o)) {
                [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($o) | Out-Null
            }
        }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

function Get-MsiSummaryInfo {
    <#
    .SYNOPSIS
        Reads MSI summary information stream (architecture, package code, etc.).
    #>
    param([Parameter(Mandatory)][string]$MsiPath)

    Write-Log "Reading MSI summary info: $MsiPath"

    # Try PSGallery MSI module first
    if (Test-MsiModuleAvailable) {
        try {
            Import-Module MSI -ErrorAction Stop
            $summary = Get-MSISummaryInfo -Path $MsiPath -ErrorAction Stop
            return [PSCustomObject]@{
                Template     = $summary.Template
                RevisionNumber = $summary.RevisionNumber
                Subject      = $summary.Subject
                Author       = $summary.Author
                Keywords     = $summary.Keywords
                Comments     = $summary.Comments
                Architecture = if ($summary.Template -match 'x64|Intel64|64') { 'x64' } elseif ($summary.Template -match 'Intel|x86') { 'x86' } else { $summary.Template }
            }
        }
        catch {
            Write-Log "MSI module summary failed, falling back to COM: $_" -Level WARN
        }
    }

    # COM fallback
    $installer = $null; $db = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db = $installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installer, @($MsiPath, 0))
        $summaryInfo = $db.GetType().InvokeMember("SummaryInformation", "GetProperty", $null, $db, 0)

        $template = $summaryInfo.GetType().InvokeMember("Property", "InvokeMethod", $null, $summaryInfo, 7)
        $revision = $summaryInfo.GetType().InvokeMember("Property", "InvokeMethod", $null, $summaryInfo, 9)
        $subject  = $summaryInfo.GetType().InvokeMember("Property", "InvokeMethod", $null, $summaryInfo, 3)
        $author   = $summaryInfo.GetType().InvokeMember("Property", "InvokeMethod", $null, $summaryInfo, 4)

        return [PSCustomObject]@{
            Template       = [string]$template
            RevisionNumber = [string]$revision
            Subject        = [string]$subject
            Author         = [string]$author
            Keywords       = ''
            Comments       = ''
            Architecture   = if ([string]$template -match 'x64|Intel64|64') { 'x64' } elseif ([string]$template -match 'Intel|x86') { 'x86' } else { [string]$template }
        }
    }
    catch {
        Write-Log "Failed to read MSI summary: $_" -Level ERROR
        return $null
    }
    finally {
        foreach ($o in @($summaryInfo, $db, $installer)) {
            if ($null -ne $o -and [System.Runtime.InteropServices.Marshal]::IsComObject($o)) {
                [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($o) | Out-Null
            }
        }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

# ---------------------------------------------------------------------------
# Silent Switch Analysis
# ---------------------------------------------------------------------------

function Get-SilentSwitchDatabase {
    <#
    .SYNOPSIS
        Returns the static lookup table of known silent install switches per installer type.
    #>
    return @{
        'MSI' = @{
            Install   = 'msiexec.exe /i "<MSI>" /qn /norestart'
            Uninstall = 'msiexec.exe /x "<ProductCode>" /qn /norestart'
            Notes     = 'ProductCode required for uninstall. Add /L*v "<log>" for verbose logging.'
        }
        'NSIS' = @{
            Install   = '"<EXE>" /S'
            Uninstall = '"<UninstallEXE>" /S'
            Notes     = '/S is CASE SENSITIVE (uppercase S). Some NSIS installers also support /D=<path> for install directory.'
        }
        'InnoSetup' = @{
            Install   = '"<EXE>" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
            Uninstall = '"<UninstallEXE>" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
            Notes     = '/SP- suppresses the initial "This will install..." prompt. /DIR="<path>" for custom directory.'
        }
        'InstallShield' = @{
            Install   = '"<EXE>" /s /v"/qn"'
            Uninstall = '"<EXE>" /s /v"/qn" /x'
            Notes     = 'Some InstallShield installers require a response file: -s -f1"setup.iss"'
        }
        'WixBurn' = @{
            Install   = '"<EXE>" /quiet /norestart'
            Uninstall = '"<EXE>" /uninstall /quiet /norestart'
            Notes     = '/log "<path>" for logging. Burn bundles contain embedded MSI/EXE payloads.'
        }
        'AdvancedInstaller' = @{
            Install   = '"<EXE>" /i /qn'
            Uninstall = '"<EXE>" /x /qn'
            Notes     = 'Based on MSI technology. May also support msiexec.exe switches on the embedded MSI.'
        }
        '7zSFX' = @{
            Install   = 'Self-extracting archive. Extract with 7z.exe, then run the embedded installer.'
            Uninstall = 'Depends on the extracted payload.'
            Notes     = 'Not a true installer. Extract contents to identify the actual installer inside.'
        }
        'WinRarSFX' = @{
            Install   = 'Self-extracting archive. Extract with 7z.exe or WinRAR, then run the embedded installer.'
            Uninstall = 'Depends on the extracted payload.'
            Notes     = 'Not a true installer. Extract contents to identify the actual installer inside.'
        }
        'Unknown' = @{
            Install   = 'Unable to determine. Try: "<EXE>" /? or "<EXE>" --help for usage.'
            Uninstall = 'Check Add/Remove Programs for uninstall string.'
            Notes     = 'Installer framework not recognized. Common switches to try: /S, /silent, /quiet, /q, /VERYSILENT'
        }
    }
}

function Get-SilentSwitches {
    <#
    .SYNOPSIS
        Returns install/uninstall switches for the detected installer type.
    .DESCRIPTION
        Substitutes actual filename and ProductCode (if MSI) into the template strings.
    #>
    param(
        [Parameter(Mandatory)][string]$InstallerType,
        [Parameter(Mandatory)][string]$FilePath,
        [hashtable]$MsiProperties
    )

    $db = Get-SilentSwitchDatabase
    $fileName = Split-Path -Leaf $FilePath

    if (-not $db.ContainsKey($InstallerType)) { $InstallerType = 'Unknown' }
    $entry = $db[$InstallerType]

    $install   = $entry.Install -replace '<EXE>', $fileName -replace '<MSI>', $fileName
    $uninstall = $entry.Uninstall -replace '<EXE>', $fileName -replace '<UninstallEXE>', 'uninstall.exe'

    if ($MsiProperties -and $MsiProperties.ContainsKey('ProductCode')) {
        $install   = $install -replace '<ProductCode>', $MsiProperties['ProductCode']
        $uninstall = $uninstall -replace '<ProductCode>', $MsiProperties['ProductCode']
    }

    return [PSCustomObject]@{
        InstallerType = $InstallerType
        Install       = $install
        Uninstall     = $uninstall
        Notes         = $entry.Notes
    }
}

# ---------------------------------------------------------------------------
# Payload Extraction
# ---------------------------------------------------------------------------

function Find-7ZipPath {
    <#
    .SYNOPSIS
        Locates 7z.exe on the system.
    #>
    param([string]$PreferredPath)

    if ($PreferredPath -and (Test-Path -LiteralPath $PreferredPath)) { return $PreferredPath }

    $candidates = @(
        'C:\Program Files\7-Zip\7z.exe'
        'C:\Program Files (x86)\7-Zip\7z.exe'
    )

    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }

    $inPath = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    return $null
}

function Get-PayloadContents {
    <#
    .SYNOPSIS
        Lists contents of an installer using 7z.exe without extracting.
    .DESCRIPTION
        Returns array of PSCustomObjects with Name, Size, DateTime properties.
        Returns $null if 7z.exe is not found.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$SevenZipPath
    )

    if (-not $SevenZipPath) { $SevenZipPath = Find-7ZipPath }
    if (-not $SevenZipPath) {
        Write-Log "7-Zip not found. Cannot list payload contents." -Level WARN
        return $null
    }

    Write-Log "Listing payload contents with 7z..."

    $tempOut = [System.IO.Path]::GetTempFileName()
    $tempErr = [System.IO.Path]::GetTempFileName()

    try {
        Start-Process -FilePath $SevenZipPath -ArgumentList @('l', "`"$Path`"") `
            -Wait -NoNewWindow `
            -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr

        $output = Get-Content -LiteralPath $tempOut -ErrorAction SilentlyContinue

        # Parse 7z list output -- look for the file table between dashed lines
        $results = @()
        $inTable = $false
        $dashCount = 0

        foreach ($line in $output) {
            if ($line -match '^-{10,}') {
                $dashCount++
                if ($dashCount -eq 1) { $inTable = $true; continue }
                if ($dashCount -eq 2) { break }
            }
            if ($inTable -and $line.Trim()) {
                # Format: Date Time Attr Size Compressed Name
                if ($line -match '^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+(\d+)\s+\d*\s+(.+)$') {
                    $attr = $Matches[1]
                    $size = [long]$Matches[2]
                    $name = $Matches[3].Trim()
                    $results += [PSCustomObject]@{
                        Name = $name
                        Size = $size
                        SizeFormatted = if ($size -ge 1MB) { "{0:N1} MB" -f ($size / 1MB) } elseif ($size -ge 1KB) { "{0:N0} KB" -f ($size / 1KB) } else { "$size B" }
                        IsDirectory = ($attr -match 'D')
                    }
                }
            }
        }

        Write-Log "Found $($results.Count) items in payload"
        return $results
    }
    catch {
        Write-Log "Failed to list payload: $_" -Level ERROR
        return @()
    }
    finally {
        Remove-Item -LiteralPath $tempOut, $tempErr -ErrorAction SilentlyContinue
    }
}

function Expand-InstallerPayload {
    <#
    .SYNOPSIS
        Extracts installer contents to a directory using 7z.exe.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutputPath,
        [string]$SevenZipPath
    )

    if (-not $SevenZipPath) { $SevenZipPath = Find-7ZipPath }
    if (-not $SevenZipPath) {
        Write-Log "7-Zip not found. Cannot extract payload." -Level ERROR
        return $null
    }

    if (-not $OutputPath) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $OutputPath = Join-Path $env:TEMP "InstallerAnalysis\$baseName`_$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    Write-Log "Extracting to: $OutputPath"

    $proc = Start-Process -FilePath $SevenZipPath -ArgumentList @('x', "`"$Path`"", "-o`"$OutputPath`"", '-y') `
        -Wait -NoNewWindow -PassThru

    if ($proc.ExitCode -eq 0) {
        Write-Log "Extraction complete"
    } else {
        Write-Log "7z.exe exited with code $($proc.ExitCode)" -Level WARN
    }

    return $OutputPath
}

# ---------------------------------------------------------------------------
# String Analysis
# ---------------------------------------------------------------------------

function Get-BinaryStrings {
    <#
    .SYNOPSIS
        Extracts printable ASCII strings (>= 8 chars) from a binary file.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MinLength = 8,
        [int]$MaxBytes = 2MB
    )

    $fileSize = (Get-Item -LiteralPath $Path).Length
    $readSize = [Math]::Min($MaxBytes, $fileSize)

    $stream = [System.IO.File]::OpenRead($Path)
    $bytes = New-Object byte[] $readSize
    $stream.Read($bytes, 0, $readSize) | Out-Null
    $stream.Close()

    $strings = @()
    $current = New-Object System.Text.StringBuilder

    foreach ($b in $bytes) {
        if ($b -ge 0x20 -and $b -le 0x7E) {
            $current.Append([char]$b) | Out-Null
        } else {
            if ($current.Length -ge $MinLength) {
                $strings += $current.ToString()
            }
            $current.Clear() | Out-Null
        }
    }
    if ($current.Length -ge $MinLength) { $strings += $current.ToString() }

    return $strings
}

function Get-InterestingStrings {
    <#
    .SYNOPSIS
        Filters binary strings into categorized interesting findings.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Write-Log "Scanning for interesting strings..."

    $rawStrings = Get-BinaryStrings -Path $Path
    if (-not $rawStrings) { return @{ InstallerMarkers = @(); URLs = @(); RegistryPaths = @(); FilePaths = @(); GUIDs = @(); VersionStrings = @() } }

    $all = $rawStrings -join "`n"

    $markers = @($rawStrings | Where-Object { $_ -match 'NullsoftInst|Inno Setup|InstallShield|WixBurn|Advanced Installer|WixBundleManifest|Microsoft Visual C\+\+|\.NET Framework|NSIS' } | Sort-Object -Unique)
    $urls = @([regex]::Matches($all, 'https?://[^\s"''<>]+') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    $regPaths = @([regex]::Matches($all, '(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s"'']+') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    $filePaths = @([regex]::Matches($all, '[A-Za-z]:\\[^\s"''*?<>|]+\.(exe|msi|dll|sys|cab)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    $guids = @([regex]::Matches($all, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    $versions = @([regex]::Matches($all, '\b\d+\.\d+\.\d+(\.\d+)?\b') | ForEach-Object { $_.Value } | Sort-Object -Unique | Select-Object -First 50)

    Write-Log "Found: $($markers.Count) markers, $($urls.Count) URLs, $($regPaths.Count) registry paths, $($guids.Count) GUIDs"

    return @{
        InstallerMarkers = $markers
        URLs             = $urls
        RegistryPaths    = $regPaths
        FilePaths        = $filePaths
        GUIDs            = $guids
        VersionStrings   = $versions
    }
}

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

function Export-AnalysisReport {
    <#
    .SYNOPSIS
        Exports analysis results as CSV (property/value pairs).
    #>
    param(
        [Parameter(Mandatory)][System.Data.DataTable]$DataTable,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $parentDir = Split-Path -Path $OutputPath -Parent
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    $rows = @()
    foreach ($row in $DataTable.Rows) {
        $obj = [ordered]@{}
        foreach ($col in $DataTable.Columns) { $obj[$col.ColumnName] = $row[$col.ColumnName] }
        $rows += [PSCustomObject]$obj
    }
    $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Log "Exported CSV to $OutputPath"
}

function Export-AnalysisHtml {
    <#
    .SYNOPSIS
        Exports analysis results as a styled HTML report.
    #>
    param(
        [Parameter(Mandatory)][System.Data.DataTable]$DataTable,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$ReportTitle = 'Installer Analysis Report'
    )

    $parentDir = Split-Path -Path $OutputPath -Parent
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    $css = @(
        '<style>',
        'body { font-family: "Segoe UI", Arial, sans-serif; margin: 20px; background: #fafafa; }',
        'h1 { color: #0078D4; margin-bottom: 4px; }',
        '.summary { color: #666; margin-bottom: 12px; font-size: 0.9em; }',
        'table { border-collapse: collapse; width: 100%; margin-top: 12px; }',
        'th { background: #0078D4; color: #fff; padding: 8px 12px; text-align: left; }',
        'td { padding: 6px 12px; border-bottom: 1px solid #e0e0e0; }',
        'tr:nth-child(even) { background: #f5f5f5; }',
        '.prop { font-weight: bold; width: 200px; }',
        '</style>'
    ) -join "`r`n"

    $headerRow = ($DataTable.Columns | ForEach-Object { "<th>$($_.ColumnName)</th>" }) -join ''
    $bodyRows = foreach ($row in $DataTable.Rows) {
        $cells = foreach ($col in $DataTable.Columns) {
            $val = [string]$row[$col.ColumnName]
            $cls = if ($col.Ordinal -eq 0) { ' class="prop"' } else { '' }
            "<td$cls>$val</td>"
        }
        "<tr>$($cells -join '')</tr>"
    }

    $html = @(
        '<!DOCTYPE html>', '<html><head><meta charset="utf-8"><title>' + $ReportTitle + '</title>',
        $css, '</head><body>', "<h1>$ReportTitle</h1>",
        "<div class='summary'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Rows: $($DataTable.Rows.Count)</div>",
        "<table><thead><tr>$headerRow</tr></thead>",
        "<tbody>$($bodyRows -join "`r`n")</tbody></table>",
        '</body></html>'
    ) -join "`r`n"

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    Write-Log "Exported HTML to $OutputPath"
}

function New-AnalysisSummaryText {
    <#
    .SYNOPSIS
        Returns a clipboard-ready text summary of the analysis.
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$FileInfo,
        [Parameter(Mandatory)][string]$InstallerType,
        [PSCustomObject]$Switches,
        [hashtable]$MsiProperties
    )

    $lines = @(
        "Installer Analysis: $($FileInfo.FileName)",
        ("-" * 50),
        "Type:         $InstallerType",
        "Architecture: $($FileInfo.Architecture)",
        "Version:      $(if ($FileInfo.ProductVersion) { $FileInfo.ProductVersion } else { $FileInfo.FileVersion })",
        "Company:      $($FileInfo.CompanyName)",
        "Size:         $($FileInfo.FileSizeFormatted)",
        "SHA-256:      $($FileInfo.SHA256)",
        "Signed:       $($FileInfo.SignatureStatus)$(if ($FileInfo.SignerSubject) { " ($($FileInfo.SignerSubject))" })",
        "",
        "Silent Install:    $($Switches.Install)",
        "Silent Uninstall:  $($Switches.Uninstall)",
        "Notes:             $($Switches.Notes)"
    )

    if ($MsiProperties -and $MsiProperties.Count -gt 0) {
        $lines += ""
        $lines += "MSI Properties:"
        if ($MsiProperties.ContainsKey('ProductCode'))  { $lines += "  Product Code:  $($MsiProperties['ProductCode'])" }
        if ($MsiProperties.ContainsKey('UpgradeCode'))  { $lines += "  Upgrade Code:  $($MsiProperties['UpgradeCode'])" }
        if ($MsiProperties.ContainsKey('ProductVersion')) { $lines += "  Version:       $($MsiProperties['ProductVersion'])" }
        if ($MsiProperties.ContainsKey('Manufacturer'))  { $lines += "  Manufacturer:  $($MsiProperties['Manufacturer'])" }
    }

    return ($lines -join "`r`n")
}
