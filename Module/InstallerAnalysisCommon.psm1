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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Log is the single console-surfacing path; Write-Host is the deliberate contract so INFO/WARN/ERROR reach both the host and the file log. Suppressing PSSA noise; error-level lines use WriteErrorLine.')]
    param(
        [AllowEmptyString()][Parameter(Mandatory, Position = 0)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [switch]$Quiet
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $formatted = "[{0}] [{1,-5}] {2}" -f $timestamp, $Level, $Message
    if (-not $Quiet) {
        if ($Level -eq 'ERROR') { $host.UI.WriteErrorLine($formatted) }
        else { Write-Host $formatted }
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

    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $reader = New-Object System.IO.BinaryReader($stream)

        $mz = $reader.ReadUInt16()
        if ($mz -ne 0x5A4D) { return 'Not a PE' }

        $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $reader.ReadInt32()

        $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peSignature = $reader.ReadUInt32()
        if ($peSignature -ne 0x00004550) { return 'Invalid PE' }

        $machineType = $reader.ReadUInt16()
        switch ($machineType) {
            0x014C  { 'x86' }
            0x8664  { 'x64' }
            0xAA64  { 'ARM64' }
            0x01C0  { 'ARM' }
            default { "Unknown (0x$($machineType.ToString('X4')))" }
        }
    }
    catch {
        return 'Error'
    }
    finally {
        if ($reader) { try { $reader.Close() } catch { $null = $_ } }
        if ($stream) { try { $stream.Close() } catch { $null = $_ } }
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

function Test-ZipEntryExists {
    <#
    .SYNOPSIS
        Returns $true if the archive at $Path contains an entry matching $EntryName (exact) or $Pattern (wildcard).
    .DESCRIPTION
        Opens the ZIP read-only and checks its entries. Returns $false if the file is not a valid ZIP
        or does not contain the target. Safe to call on any file path.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Predicate against multiple zip entries; plural reads correctly.')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$EntryName,
        [string]$Pattern,
        [switch]$RootOnly
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        foreach ($entry in $archive.Entries) {
            $full = $entry.FullName
            if ($RootOnly -and ($full -match '/' -or $full -match '\\')) { continue }
            if ($EntryName -and $full -eq $EntryName) { return $true }
            if ($Pattern -and ($entry.Name -like $Pattern)) { return $true }
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        if ($archive) { $archive.Dispose() }
    }
}

function Get-ZipEntryText {
    <#
    .SYNOPSIS
        Reads a text entry out of a ZIP archive and returns its contents as a string.
    .DESCRIPTION
        Returns $null if the archive cannot be opened or the entry does not exist.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$EntryName
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $archive = $null; $stream = $null; $reader = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        $entry = $archive.GetEntry($EntryName)
        if ($null -eq $entry) { return $null }
        $stream = $entry.Open()
        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadToEnd()
    }
    catch {
        return $null
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($archive) { $archive.Dispose() }
    }
}

function Get-ZipRootEntryByPattern {
    <#
    .SYNOPSIS
        Returns the full path of the first ZIP entry at root matching a wildcard pattern, or $null.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -match '/' -or $entry.FullName -match '\\') { continue }
            if ($entry.Name -like $Pattern) { return $entry.FullName }
        }
        return $null
    }
    catch {
        return $null
    }
    finally {
        if ($archive) { $archive.Dispose() }
    }
}

function Test-IsZipFile {
    <#
    .SYNOPSIS
        Returns $true if the first 4 bytes of the file are the ZIP local-file-header magic (PK\x03\x04).
    #>
    param([Parameter(Mandatory)][string]$Path)

    $stream = $null
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $bytes = New-Object byte[] 4
        $read = $stream.Read($bytes, 0, 4)
        if ($read -lt 4) { return $false }
        return ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and $bytes[2] -eq 0x03 -and $bytes[3] -eq 0x04)
    }
    catch {
        return $false
    }
    finally {
        if ($stream) { try { $stream.Close() } catch { $null = $_ } }
    }
}

function Get-InstallerType {
    <#
    .SYNOPSIS
        Detects installer framework by scanning binary signatures and ZIP layout.
    .DESCRIPTION
        Returns one of:
          MSI, NSIS, InnoSetup, InstallShield, WixBurn, AdvancedInstaller,
          BitRock, 7zSFX, WinRarSFX,
          Chocolatey, NuGet, Intunewin, Msix, MsixBundle, PsadtV3, PsadtV4,
          Squirrel,
          Unknown.
    #>
    param([Parameter(Mandatory)][string]$Path)

    # MSI by extension
    if ($Path -match '\.msi$') { return 'MSI' }

    # NuGet / Chocolatey packages: .nupkg = ZIP + root *.nuspec
    if ($Path -match '\.nupkg$') {
        if (Test-IsZipFile -Path $Path) {
            $nuspec = Get-ZipRootEntryByPattern -Path $Path -Pattern '*.nuspec'
            if ($nuspec) {
                # Chocolatey if it carries a chocolatey*.ps1 under tools/
                if (Test-ZipEntryExists -Path $Path -Pattern 'chocolatey*.ps1') { return 'Chocolatey' }
                return 'NuGet'
            }
        }
    }

    # Intune Win32 Content Prep Tool output: .intunewin = OPC/ZIP with Metadata/Detection.xml
    if ($Path -match '\.intunewin$') {
        if ((Test-IsZipFile -Path $Path) -and (Test-ZipEntryExists -Path $Path -EntryName 'IntuneWinPackage/Metadata/Detection.xml')) {
            return 'Intunewin'
        }
    }

    # MSIX / APPX bundles (check before single packages -- bundle extensions are distinct)
    if ($Path -match '\.(msixbundle|appxbundle)$') {
        if ((Test-IsZipFile -Path $Path) -and (Test-ZipEntryExists -Path $Path -EntryName 'AppxMetadata/AppxBundleManifest.xml')) {
            return 'MsixBundle'
        }
    }

    # MSIX / APPX single packages
    if ($Path -match '\.(msix|appx)$') {
        if ((Test-IsZipFile -Path $Path) -and (Test-ZipEntryExists -Path $Path -EntryName 'AppxManifest.xml')) {
            return 'Msix'
        }
    }

    # PSADT (PSAppDeployToolkit) wrapped as ZIP. v4 tested before v3 because the v4
    # module folder can coexist with a legacy Deploy-Application.ps1 in compatibility
    # layouts; we want to classify those as v4.
    if ($Path -match '\.zip$') {
        if (Test-IsZipFile -Path $Path) {
            if ((Test-ZipEntryExists -Path $Path -Pattern 'PSAppDeployToolkit.psm1') -or
                (Test-ZipEntryExists -Path $Path -Pattern 'PSAppDeployToolkit.psd1') -or
                (Test-ZipEntryExists -Path $Path -Pattern 'Invoke-AppDeployToolkit.ps1')) {
                return 'PsadtV4'
            }
            if ((Test-ZipEntryExists -Path $Path -Pattern 'Deploy-Application.ps1') -and
                (Test-ZipEntryExists -Path $Path -Pattern 'AppDeployToolkitMain.ps1')) {
                return 'PsadtV3'
            }
        }
    }

    Write-Log "Scanning binary signatures..."

    # Read first 4MB for signature scanning (or full file if smaller). 512KB
    # was too small -- modern installers (GIMP, Audacity, Git, Positron,
    # PostgreSQL) embed their framework signature strings well past that.
    # 4MB catches Inno Setup in every modern build tested and lets BitRock's
    # marker (usually around 2-3 MB in) through.
    $maxRead = 4MB
    $fileSize = (Get-Item -LiteralPath $Path).Length
    $readSize = [Math]::Min($maxRead, $fileSize)

    $stream = $null
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $bytes = New-Object byte[] $readSize
        $stream.Read($bytes, 0, $readSize) | Out-Null
    }
    finally {
        if ($stream) { try { $stream.Close() } catch { $null = $_ } }
    }

    $asciiText = [System.Text.Encoding]::ASCII.GetString($bytes)

    # OLE Compound Document (MSI in disguise, e.g., .exe wrapping MSI)
    if ($bytes.Length -ge 8 -and $bytes[0] -eq 0xD0 -and $bytes[1] -eq 0xCF -and $bytes[2] -eq 0x11 -and $bytes[3] -eq 0xE0) {
        return 'MSI'
    }

    # Squirrel / Electron Setup.exe -- check BEFORE NSIS. Squirrel's bootstrapper is
    # not NSIS-built so it should not carry NullsoftInst markers, but being earlier
    # in the chain is defensive against future false positives. Require 2+ distinct
    # Squirrel markers to suppress accidental hits on the literal string "Squirrel".
    $squirrelMarkers = @('SquirrelTemp', 'squirrel-install', 'squirrel-updated',
                         'squirrel-uninstall', 'squirrel-firstrun', 'squirrel-obsolete')
    $squirrelHits = 0
    foreach ($m in $squirrelMarkers) {
        if ($asciiText -match [regex]::Escape($m)) { $squirrelHits++ }
    }
    if ($squirrelHits -ge 2) {
        return 'Squirrel'
    }
    # Weaker form: a single lifecycle marker combined with Update.exe string is enough
    if ($squirrelHits -ge 1 -and $asciiText -match 'Update\.exe') {
        return 'Squirrel'
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

    # BitRock InstallBuilder -- used by PostgreSQL, Bitnami, JFrog Artifactory,
    # and other vendors that need a cross-platform installer framework. The
    # signature string "BitRock" lives in the bootstrap metadata a couple MB in.
    if ($asciiText -match 'BitRock') {
        return 'BitRock'
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
# NuGet / Chocolatey
# ---------------------------------------------------------------------------

function Get-ChocolateyMetadata {
    <#
    .SYNOPSIS
        Parses a Chocolatey or plain NuGet .nupkg and returns its nuspec metadata.
    .DESCRIPTION
        Returns a PSCustomObject with standardized fields (DisplayName, DisplayVersion,
        Publisher, Architecture, ProductCodeOrEquivalent, SilentInstallCommand,
        SilentUninstallCommand) plus a raw Nuspec hashtable of every element found.
        Returns $null if the package cannot be parsed.

        Detects Chocolatey vs plain NuGet by presence of tools/chocolateyInstall.ps1.
        Nuspec namespace: http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd
        Source: https://learn.microsoft.com/en-us/nuget/reference/nuspec
    #>
    param([Parameter(Mandatory)][string]$Path)

    Write-Log "Reading nuspec from: $Path"

    if (-not (Test-IsZipFile -Path $Path)) { return $null }

    $nuspecPath = Get-ZipRootEntryByPattern -Path $Path -Pattern '*.nuspec'
    if (-not $nuspecPath) {
        Write-Log "No .nuspec at archive root" -Level WARN
        return $null
    }

    $xmlText = Get-ZipEntryText -Path $Path -EntryName $nuspecPath
    if (-not $xmlText) { return $null }

    # Strip BOM if present (some packagers emit UTF-8 BOM in nuspec)
    if ($xmlText.Length -gt 0 -and $xmlText[0] -eq [char]0xFEFF) {
        $xmlText = $xmlText.Substring(1)
    }

    try {
        $xml = [xml]$xmlText
    }
    catch {
        Write-Log "Failed to parse nuspec XML: $_" -Level ERROR
        return $null
    }

    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('nu', 'http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd')

    $meta = $xml.SelectSingleNode('/nu:package/nu:metadata', $ns)
    if (-not $meta) { $meta = $xml.SelectSingleNode('/package/metadata') }
    if (-not $meta) {
        Write-Log "No <metadata> element in nuspec" -Level WARN
        return $null
    }

    $nuspec = [ordered]@{}
    foreach ($child in $meta.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $nuspec[$child.LocalName] = [string]$child.InnerText
        }
    }

    $isChoco = Test-ZipEntryExists -Path $Path -Pattern 'chocolatey*.ps1'
    $installerType = if ($isChoco) { 'Chocolatey' } else { 'NuGet' }

    $displayName = if ($nuspec['title']) { $nuspec['title'] } else { $nuspec['id'] }
    $publisher   = if ($nuspec['authors']) { $nuspec['authors'] } else { $nuspec['owners'] }

    $silentInstall = if ($isChoco) {
        "choco install $($nuspec['id']) --version=$($nuspec['version']) -y --source=`"<SourceDirOrFeed>`""
    } else {
        "nuget install $($nuspec['id']) -Version $($nuspec['version']) -Source `"<SourceDirOrFeed>`""
    }
    $silentUninstall = if ($isChoco) {
        "choco uninstall $($nuspec['id']) -y"
    } else {
        'N/A (NuGet is a package source, not an installer)'
    }

    return [PSCustomObject]@{
        InstallerType            = $installerType
        PackageId                = $nuspec['id']
        DisplayName              = $displayName
        DisplayVersion           = $nuspec['version']
        Publisher                = $publisher
        Architecture             = 'N/A (package manifest)'
        ProductCodeOrEquivalent  = $nuspec['id']
        SilentInstallCommand     = $silentInstall
        SilentUninstallCommand   = $silentUninstall
        IsChocolatey             = $isChoco
        Nuspec                   = $nuspec
    }
}

# ---------------------------------------------------------------------------
# Intune Win32 (.intunewin)
# ---------------------------------------------------------------------------

function Get-IntunewinMetadata {
    <#
    .SYNOPSIS
        Parses a .intunewin package and returns its ApplicationInfo / Detection.xml metadata.
    .DESCRIPTION
        .intunewin is an OPC (ZIP) package produced by the Microsoft Win32 Content Prep Tool.
        The real metadata lives at IntuneWinPackage/Metadata/Detection.xml. The inner
        IntunePackage.intunewin is AES-encrypted and can only be decrypted by Intune itself
        using keys from the service; this function does NOT attempt decryption.

        Source: https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool
                https://svrooij.io/2023/10/04/analysing-win32-content-prep-tool/

        Returns $null if the package cannot be parsed.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Write-Log "Reading Intunewin Detection.xml from: $Path"

    if (-not (Test-IsZipFile -Path $Path)) { return $null }

    $xmlText = Get-ZipEntryText -Path $Path -EntryName 'IntuneWinPackage/Metadata/Detection.xml'
    if (-not $xmlText) {
        Write-Log "No IntuneWinPackage/Metadata/Detection.xml entry" -Level WARN
        return $null
    }

    if ($xmlText.Length -gt 0 -and $xmlText[0] -eq [char]0xFEFF) {
        $xmlText = $xmlText.Substring(1)
    }

    try {
        $xml = [xml]$xmlText
    }
    catch {
        Write-Log "Failed to parse Detection.xml: $_" -Level ERROR
        return $null
    }

    $appInfo = $xml.ApplicationInfo
    if (-not $appInfo) {
        Write-Log "Detection.xml missing <ApplicationInfo> root" -Level WARN
        return $null
    }

    $toolVersion = $appInfo.ToolVersion
    $name        = [string]$appInfo.Name
    $fileName    = [string]$appInfo.FileName
    $setupFile   = [string]$appInfo.SetupFile
    $contentSize = [string]$appInfo.UnencryptedContentSize

    $encInfo = $appInfo.EncryptionInfo
    $enc = if ($encInfo) {
        [ordered]@{
            EncryptionKey        = [string]$encInfo.EncryptionKey
            MacKey               = [string]$encInfo.MacKey
            InitializationVector = [string]$encInfo.InitializationVector
            Mac                  = [string]$encInfo.Mac
            ProfileIdentifier    = [string]$encInfo.ProfileIdentifier
            FileDigest           = [string]$encInfo.FileDigest
            FileDigestAlgorithm  = [string]$encInfo.FileDigestAlgorithm
        }
    } else { [ordered]@{} }

    $msiSource = $false
    $msi = $null
    if ($appInfo.MsiInfo) {
        $msiSource = $true
        $mi = $appInfo.MsiInfo
        $msi = [ordered]@{
            MsiProductCode      = [string]$mi.MsiProductCode
            MsiProductVersion   = [string]$mi.MsiProductVersion
            MsiUpgradeCode      = [string]$mi.MsiUpgradeCode
            MsiExecutionContext = [string]$mi.MsiExecutionContext
            MsiRequiresLogon    = [string]$mi.MsiRequiresLogon
            MsiRequiresReboot   = [string]$mi.MsiRequiresReboot
            MsiIsMachineInstall = [string]$mi.MsiIsMachineInstall
            MsiIsUserInstall    = [string]$mi.MsiIsUserInstall
            MsiPackageCode      = [string]$mi.MsiPackageCode
            MsiPublisher        = [string]$mi.MsiPublisher
        }
    }

    $displayName = if ($name) { $name } else { $setupFile }
    $displayVersion = if ($msi) { $msi['MsiProductVersion'] } else { '' }
    $publisher = if ($msi) { $msi['MsiPublisher'] } else { '' }
    $productCode = if ($msi) { $msi['MsiProductCode'] } else { $fileName }

    # Architecture: MSI context hints at System (per-machine) vs User (per-user) but not x86/x64.
    # The Intune package itself is architecture-agnostic; the original setup file carried the arch.
    $architecture = if ($msiSource) {
        switch ($msi['MsiExecutionContext']) {
            'System' { 'Per-machine (MSI)' }
            'User'   { 'Per-user (MSI)' }
            'Any'    { 'Per-machine or per-user (MSI)' }
            default  { 'N/A (see embedded setup file)' }
        }
    } else {
        'N/A (see embedded setup file)'
    }

    $silentInstall = if ($msiSource) {
        "msiexec.exe /i `"<ExtractedSetup>`" /qn /norestart  # decrypted by Intune Management Extension; original: $setupFile"
    } else {
        "`"<ExtractedSetup>`" <OriginalSilentSwitches>  # decrypted by Intune Management Extension; original: $setupFile"
    }
    $silentUninstall = if ($msiSource -and $msi['MsiProductCode']) {
        "msiexec.exe /x `"$($msi['MsiProductCode'])`" /qn /norestart"
    } else {
        'N/A (uninstall command defined in Intune portal, not in the .intunewin)'
    }

    return [PSCustomObject]@{
        InstallerType           = 'Intunewin'
        ToolVersion             = $toolVersion
        Name                    = $name
        DisplayName             = $displayName
        DisplayVersion          = $displayVersion
        Publisher               = $publisher
        Architecture            = $architecture
        ProductCodeOrEquivalent = $productCode
        SetupFile               = $setupFile
        FileName                = $fileName
        UnencryptedContentSize  = $contentSize
        IsMsiSource             = $msiSource
        MsiInfo                 = $msi
        EncryptionInfo          = $enc
        SilentInstallCommand    = $silentInstall
        SilentUninstallCommand  = $silentUninstall
    }
}

# ---------------------------------------------------------------------------
# MSIX / APPX (single package + bundle)
# ---------------------------------------------------------------------------

function Get-MsixManifest {
    <#
    .SYNOPSIS
        Parses an MSIX / APPX package (single or bundle) and returns its identity metadata.
    .DESCRIPTION
        Reads AppxManifest.xml for single packages (namespace
        http://schemas.microsoft.com/appx/manifest/foundation/windows10) or
        AppxMetadata/AppxBundleManifest.xml for bundles (namespace
        http://schemas.microsoft.com/appx/2013/bundle). Returns a standardized
        PSCustomObject plus raw Identity / Packages data.

        Returns $null if neither manifest is present or parseable.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Write-Log "Reading MSIX/APPX manifest from: $Path"

    if (-not (Test-IsZipFile -Path $Path)) { return $null }

    # Try bundle first: AppxMetadata/AppxBundleManifest.xml
    $bundleText = Get-ZipEntryText -Path $Path -EntryName 'AppxMetadata/AppxBundleManifest.xml'
    if ($bundleText) {
        return (ConvertFrom-MsixBundleManifest -XmlText $bundleText)
    }

    # Fall through to single package: AppxManifest.xml
    $manifestText = Get-ZipEntryText -Path $Path -EntryName 'AppxManifest.xml'
    if ($manifestText) {
        return (ConvertFrom-MsixPackageManifest -XmlText $manifestText)
    }

    Write-Log "No AppxManifest.xml or AppxBundleManifest.xml entry found" -Level WARN
    return $null
}

function ConvertFrom-MsixPackageManifest {
    <#
    .SYNOPSIS
        Parses the raw XML text of an AppxManifest.xml from a single-package .msix/.appx.
    #>
    param([Parameter(Mandatory)][string]$XmlText)

    if ($XmlText.Length -gt 0 -and $XmlText[0] -eq [char]0xFEFF) {
        $XmlText = $XmlText.Substring(1)
    }

    try { $xml = [xml]$XmlText }
    catch {
        Write-Log "Failed to parse AppxManifest.xml: $_" -Level ERROR
        return $null
    }

    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('p',    'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $ns.AddNamespace('uap',  'http://schemas.microsoft.com/appx/manifest/uap/windows10')
    $ns.AddNamespace('rescap', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities')

    $pkg = $xml.SelectSingleNode('/p:Package', $ns)
    if (-not $pkg) { $pkg = $xml.SelectSingleNode('/Package') }
    if (-not $pkg) {
        Write-Log "AppxManifest.xml has no <Package> root" -Level WARN
        return $null
    }

    $identity = $pkg.SelectSingleNode('p:Identity', $ns)
    if (-not $identity) { $identity = $pkg.SelectSingleNode('Identity') }
    $properties = $pkg.SelectSingleNode('p:Properties', $ns)
    if (-not $properties) { $properties = $pkg.SelectSingleNode('Properties') }

    $id = if ($identity) {
        [ordered]@{
            Name                 = [string]$identity.Name
            Publisher            = [string]$identity.Publisher
            Version              = [string]$identity.Version
            ProcessorArchitecture = [string]$identity.ProcessorArchitecture
            ResourceId           = [string]$identity.ResourceId
        }
    } else { [ordered]@{} }

    $displayName = ''; $publisherDisplay = ''; $description = ''; $logo = ''
    if ($properties) {
        foreach ($child in $properties.ChildNodes) {
            if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            switch ($child.LocalName) {
                'DisplayName'          { $displayName = [string]$child.InnerText }
                'PublisherDisplayName' { $publisherDisplay = [string]$child.InnerText }
                'Description'          { $description = [string]$child.InnerText }
                'Logo'                 { $logo = [string]$child.InnerText }
            }
        }
    }

    $architecture = if ($id['ProcessorArchitecture']) { $id['ProcessorArchitecture'] } else { 'Neutral' }

    return [PSCustomObject]@{
        InstallerType           = 'Msix'
        PackageKind             = 'SinglePackage'
        DisplayName             = if ($displayName) { $displayName } else { $id['Name'] }
        DisplayVersion          = $id['Version']
        Publisher               = if ($publisherDisplay) { $publisherDisplay } else { $id['Publisher'] }
        Architecture            = $architecture
        ProductCodeOrEquivalent = $id['Name']
        Identity                = $id
        PropertiesDescription   = $description
        PropertiesLogo          = $logo
        BundledPackages         = @()
        SilentInstallCommand    = 'Add-AppxPackage -Path "<msix>"   # per-user;  use Add-AppxProvisionedPackage -Online -PackagePath "<msix>" -SkipLicense for all-users'
        SilentUninstallCommand  = 'Remove-AppxPackage -Package "<PackageFullName>"   # get FullName via Get-AppxPackage'
    }
}

function ConvertFrom-MsixBundleManifest {
    <#
    .SYNOPSIS
        Parses the raw XML text of an AppxBundleManifest.xml from a .msixbundle / .appxbundle.
    #>
    param([Parameter(Mandatory)][string]$XmlText)

    if ($XmlText.Length -gt 0 -and $XmlText[0] -eq [char]0xFEFF) {
        $XmlText = $XmlText.Substring(1)
    }

    try { $xml = [xml]$XmlText }
    catch {
        Write-Log "Failed to parse AppxBundleManifest.xml: $_" -Level ERROR
        return $null
    }

    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('b', 'http://schemas.microsoft.com/appx/2013/bundle')

    $bundle = $xml.SelectSingleNode('/b:Bundle', $ns)
    if (-not $bundle) { $bundle = $xml.SelectSingleNode('/Bundle') }
    if (-not $bundle) {
        Write-Log "AppxBundleManifest.xml has no <Bundle> root" -Level WARN
        return $null
    }

    $identity = $bundle.SelectSingleNode('b:Identity', $ns)
    if (-not $identity) { $identity = $bundle.SelectSingleNode('Identity') }

    $id = if ($identity) {
        [ordered]@{
            Name      = [string]$identity.Name
            Publisher = [string]$identity.Publisher
            Version   = [string]$identity.Version
        }
    } else { [ordered]@{} }

    $pkgNodes = $bundle.SelectNodes('b:Packages/b:Package', $ns)
    if (-not $pkgNodes -or $pkgNodes.Count -eq 0) {
        $pkgNodes = $bundle.SelectNodes('Packages/Package')
    }
    $bundled = @()
    if ($pkgNodes) {
        foreach ($p in $pkgNodes) {
            $bundled += [PSCustomObject]@{
                Type         = [string]$p.Type
                Version      = [string]$p.Version
                Architecture = [string]$p.Architecture
                FileName     = [string]$p.FileName
                ResourceId   = [string]$p.ResourceId
            }
        }
    }

    $architectures = @($bundled | Where-Object { $_.Architecture } | ForEach-Object Architecture | Sort-Object -Unique) -join ', '
    if (-not $architectures) { $architectures = 'Bundle' }

    return [PSCustomObject]@{
        InstallerType           = 'MsixBundle'
        PackageKind             = 'Bundle'
        DisplayName             = $id['Name']
        DisplayVersion          = $id['Version']
        Publisher               = $id['Publisher']
        Architecture            = $architectures
        ProductCodeOrEquivalent = $id['Name']
        Identity                = $id
        PropertiesDescription   = ''
        PropertiesLogo          = ''
        BundledPackages         = $bundled
        SilentInstallCommand    = 'Add-AppxPackage -Path "<msixbundle>"'
        SilentUninstallCommand  = 'Remove-AppxPackage -Package "<PackageFullName>"'
    }
}

# ---------------------------------------------------------------------------
# PSAppDeployToolkit (PSADT)
# ---------------------------------------------------------------------------

function Get-ZipEntryPathByPattern {
    <#
    .SYNOPSIS
        Returns the first ZIP entry full path whose file-name matches a wildcard, or $null.
    .DESCRIPTION
        Searches the whole archive (any depth). Useful for sentinel files that may live
        under a top-level folder (e.g. PSADT's AppDeployToolkit/AppDeployToolkitMain.ps1).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        foreach ($entry in $archive.Entries) {
            if ($entry.Name -like $Pattern) { return $entry.FullName }
        }
        return $null
    }
    catch {
        return $null
    }
    finally {
        if ($archive) { $archive.Dispose() }
    }
}

function ConvertFrom-PsadtDeployApplication {
    <#
    .SYNOPSIS
        Parses Deploy-Application.ps1 / Invoke-AppDeployToolkit.ps1 header variables
        ($appVendor, $appName, $appVersion, $appArch, $appLang, $appRevision,
         $appScriptVersion, $appScriptDate, $appScriptAuthor).
    .DESCRIPTION
        Works on both v3 (`[String]$appName = 'X'`) and v4 (`$adtSession = @{ AppName = 'X' }`)
        layouts. Returns an ordered hashtable of whichever fields were found.
    #>
    param([Parameter(Mandatory)][string]$ScriptText)

    $result = [ordered]@{
        AppVendor      = ''
        AppName        = ''
        AppVersion     = ''
        AppArch        = ''
        AppLang        = ''
        AppRevision    = ''
        ScriptVersion  = ''
        ScriptDate     = ''
        ScriptAuthor   = ''
    }

    # v3 pattern: [String]$appName = 'X'  or  [String]$appName = "X"
    $v3Patterns = [ordered]@{
        AppVendor     = '(?im)^\s*\[String\]\s*\$appVendor\s*=\s*[''"]([^''"]*)[''"]'
        AppName       = '(?im)^\s*\[String\]\s*\$appName\s*=\s*[''"]([^''"]*)[''"]'
        AppVersion    = '(?im)^\s*\[String\]\s*\$appVersion\s*=\s*[''"]([^''"]*)[''"]'
        AppArch       = '(?im)^\s*\[String\]\s*\$appArch\s*=\s*[''"]([^''"]*)[''"]'
        AppLang       = '(?im)^\s*\[String\]\s*\$appLang\s*=\s*[''"]([^''"]*)[''"]'
        AppRevision   = '(?im)^\s*\[String\]\s*\$appRevision\s*=\s*[''"]([^''"]*)[''"]'
        ScriptVersion = '(?im)^\s*\[String\]\s*\$appScriptVersion\s*=\s*[''"]([^''"]*)[''"]'
        ScriptDate    = '(?im)^\s*\[String\]\s*\$appScriptDate\s*=\s*[''"]([^''"]*)[''"]'
        ScriptAuthor  = '(?im)^\s*\[String\]\s*\$appScriptAuthor\s*=\s*[''"]([^''"]*)[''"]'
    }
    foreach ($key in $v3Patterns.Keys) {
        $m = [regex]::Match($ScriptText, $v3Patterns[$key])
        if ($m.Success) { $result[$key] = $m.Groups[1].Value }
    }

    # v4 pattern: key inside @{ AppName = 'X' } (loose match; same InnerText target)
    $v4Patterns = [ordered]@{
        AppVendor     = '(?im)\bAppVendor\s*=\s*[''"]([^''"]*)[''"]'
        AppName       = '(?im)\bAppName\s*=\s*[''"]([^''"]*)[''"]'
        AppVersion    = '(?im)\bAppVersion\s*=\s*[''"]([^''"]*)[''"]'
        AppArch       = '(?im)\bAppArch\s*=\s*[''"]([^''"]*)[''"]'
        AppLang       = '(?im)\bAppLang\s*=\s*[''"]([^''"]*)[''"]'
        AppRevision   = '(?im)\bAppRevision\s*=\s*[''"]([^''"]*)[''"]'
        ScriptVersion = '(?im)\bAppScriptVersion\s*=\s*[''"]([^''"]*)[''"]'
        ScriptDate    = '(?im)\bAppScriptDate\s*=\s*[''"]([^''"]*)[''"]'
        ScriptAuthor  = '(?im)\bAppScriptAuthor\s*=\s*[''"]([^''"]*)[''"]'
    }
    foreach ($key in $v4Patterns.Keys) {
        if ($result[$key]) { continue }   # v3 match takes precedence
        $m = [regex]::Match($ScriptText, $v4Patterns[$key])
        if ($m.Success) { $result[$key] = $m.Groups[1].Value }
    }

    return $result
}

function Get-PsadtMetadata {
    <#
    .SYNOPSIS
        Parses a PSAppDeployToolkit-wrapped ZIP and returns its toolkit version + per-app header.
    .DESCRIPTION
        Detects v3 (Deploy-Application.ps1 + AppDeployToolkit/AppDeployToolkitMain.ps1) or
        v4 (Invoke-AppDeployToolkit.ps1 + PSAppDeployToolkit module) layouts. Reads the
        toolkit engine version from the engine script/module and the per-app metadata
        ($appName, $appVersion, $appVendor, etc.) from the deployment script.

        Sources:
          https://psappdeploytoolkit.com/docs/4.0.x/deployment-concepts/deployment-structure
          https://psappdeploytoolkit.com/docs/deployment-concepts/invoke-appdeploytoolkit
    #>
    param([Parameter(Mandatory)][string]$Path)

    Write-Log "Reading PSADT layout from: $Path"

    if (-not (Test-IsZipFile -Path $Path)) { return $null }

    # v4 detection: module manifest OR module psm1 OR Invoke-AppDeployToolkit.ps1
    $v4ManifestPath = Get-ZipEntryPathByPattern -Path $Path -Pattern 'PSAppDeployToolkit.psd1'
    $v4ModulePath   = Get-ZipEntryPathByPattern -Path $Path -Pattern 'PSAppDeployToolkit.psm1'
    $v4InvokePath   = Get-ZipEntryPathByPattern -Path $Path -Pattern 'Invoke-AppDeployToolkit.ps1'

    # v3 detection: AppDeployToolkitMain.ps1 + Deploy-Application.ps1
    $v3MainPath     = Get-ZipEntryPathByPattern -Path $Path -Pattern 'AppDeployToolkitMain.ps1'
    $v3DeployPath   = Get-ZipEntryPathByPattern -Path $Path -Pattern 'Deploy-Application.ps1'

    $isV4 = [bool]($v4ManifestPath -or $v4ModulePath -or $v4InvokePath)
    $isV3 = [bool]($v3MainPath -and $v3DeployPath)

    if (-not $isV4 -and -not $isV3) {
        Write-Log "No PSADT sentinel files found in archive" -Level WARN
        return $null
    }

    $toolkitVersion = ''
    $toolkitVariant = if ($isV4) { 'v4' } else { 'v3' }

    if ($isV4) {
        if ($v4ManifestPath) {
            $psd1Text = Get-ZipEntryText -Path $Path -EntryName $v4ManifestPath
            if ($psd1Text) {
                $m = [regex]::Match($psd1Text, "(?im)^\s*ModuleVersion\s*=\s*['""]([^'""]+)['""]")
                if ($m.Success) { $toolkitVersion = $m.Groups[1].Value }
            }
        }
    }
    else {
        if ($v3MainPath) {
            $mainText = Get-ZipEntryText -Path $Path -EntryName $v3MainPath
            if ($mainText) {
                # Pattern: [Version]$appDeployMainScriptVersion = [Version]'3.9.2'
                $m = [regex]::Match($mainText, "(?im)\`$appDeployMainScriptVersion\s*=\s*\[Version\]\s*['""]([^'""]+)['""]")
                if ($m.Success) {
                    $toolkitVersion = $m.Groups[1].Value
                } else {
                    $m2 = [regex]::Match($mainText, "(?im)\`$appDeployMainScriptVersion\s*=\s*['""]([^'""]+)['""]")
                    if ($m2.Success) { $toolkitVersion = $m2.Groups[1].Value }
                }
            }
        }
    }

    # Per-app metadata: prefer Invoke-AppDeployToolkit.ps1 on v4, Deploy-Application.ps1 on v3
    $appScriptPath = if ($isV4 -and $v4InvokePath) { $v4InvokePath } elseif ($v3DeployPath) { $v3DeployPath } else { $null }
    $appMeta = [ordered]@{}
    if ($appScriptPath) {
        $scriptText = Get-ZipEntryText -Path $Path -EntryName $appScriptPath
        if ($scriptText) {
            $appMeta = ConvertFrom-PsadtDeployApplication -ScriptText $scriptText
        }
    }

    $displayName = if ($appMeta['AppName']) {
        if ($appMeta['AppVendor']) { "$($appMeta['AppVendor']) $($appMeta['AppName'])" } else { $appMeta['AppName'] }
    } else { '' }

    $architecture = if ($appMeta['AppArch']) { $appMeta['AppArch'] } else { 'N/A (see embedded installer)' }
    $installerType = if ($isV4) { 'PsadtV4' } else { 'PsadtV3' }

    $silentInstall = if ($isV4) {
        'Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode Silent'
    } else {
        'Deploy-Application.exe -DeploymentType Install -DeployMode Silent'
    }
    $silentUninstall = if ($isV4) {
        'Invoke-AppDeployToolkit.exe -DeploymentType Uninstall -DeployMode Silent'
    } else {
        'Deploy-Application.exe -DeploymentType Uninstall -DeployMode Silent'
    }

    return [PSCustomObject]@{
        InstallerType           = $installerType
        ToolkitVariant          = $toolkitVariant
        ToolkitVersion          = $toolkitVersion
        DisplayName             = $displayName
        DisplayVersion          = $appMeta['AppVersion']
        Publisher               = $appMeta['AppVendor']
        Architecture            = $architecture
        ProductCodeOrEquivalent = if ($appMeta['AppName']) { $appMeta['AppName'] } else { 'N/A' }
        AppMetadata             = $appMeta
        EngineScriptPath        = if ($isV4) { $v4ManifestPath } else { $v3MainPath }
        DeploymentScriptPath    = $appScriptPath
        SilentInstallCommand    = $silentInstall
        SilentUninstallCommand  = $silentUninstall
    }
}

# ---------------------------------------------------------------------------
# Squirrel / Electron Setup.exe
# ---------------------------------------------------------------------------

function Get-SquirrelMetadata {
    <#
    .SYNOPSIS
        Extracts Squirrel / Electron Setup.exe app metadata from embedded NuGet references.
    .DESCRIPTION
        Squirrel's Setup.exe is a PE bootstrapper that embeds a NuGet .nupkg payload and a
        RELEASES manifest (plaintext: "<sha1> <filename>.nupkg <size>"). This function does
        a binary-string scan of the first 4MB (enough for typical small Electron bundles
        but may miss deeply-embedded strings in very large installers) and extracts:
          - AppName and Version from "<Name>-<Version>-full.nupkg"
          - Any http(s):// URLs that look like update feeds
          - A list of Squirrel lifecycle markers observed (provides confidence signal)

        Returns a standardized PackageMetadata PSCustomObject. Returns $null if no markers
        are found.

        Sources:
          https://github.com/Squirrel/Squirrel.Windows
          https://deepwiki.com/electron/windows-installer/4.1-squirrel.windows-overview
          https://www.electronforge.io/config/makers/squirrel.windows
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxBytes = 4MB
    )

    Write-Log "Scanning Squirrel binary: $Path"

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $stream = $null
    try {
        $fileSize = (Get-Item -LiteralPath $Path).Length
        $readSize = [Math]::Min($MaxBytes, $fileSize)
        $stream = [System.IO.File]::OpenRead($Path)
        $bytes = New-Object byte[] $readSize
        [void]$stream.Read($bytes, 0, $readSize)
    }
    catch {
        Write-Log "Failed to read binary: $_" -Level ERROR
        return $null
    }
    finally {
        if ($stream) { try { $stream.Close() } catch { $null = $_ } }
    }

    $asciiText = [System.Text.Encoding]::ASCII.GetString($bytes)

    $markerPatterns = @(
        'SquirrelTemp', 'squirrel-install', 'squirrel-updated',
        'squirrel-uninstall', 'squirrel-firstrun', 'squirrel-obsolete'
    )
    $markersFound = @()
    foreach ($m in $markerPatterns) {
        if ($asciiText -match [regex]::Escape($m)) { $markersFound += $m }
    }
    $hasUpdateExe = ($asciiText -match 'Update\.exe')

    if ($markersFound.Count -eq 0 -and -not $hasUpdateExe) {
        Write-Log "No Squirrel markers detected in first $readSize bytes" -Level WARN
        return $null
    }

    # Extract embedded nupkg references. Squirrel nupkgs are named:
    #   <AppId>-<Version>-full.nupkg   (full package)
    #   <AppId>-<Version>-delta.nupkg  (delta package)
    $appName = ''
    $version = ''
    # AppName + Version + -full|-delta.nupkg. Underscore is intentionally NOT in the
    # AppName class: if it were, the regex would swallow adjacent padding through
    # underscore-separated data (e.g. "pad_SquirrelTemp_pad_AppName-1.0.0-full.nupkg").
    # Squirrel / Electron package ids in practice use dots, hyphens, and alphanumerics.
    $nupkgMatches = [regex]::Matches($asciiText, '([A-Za-z0-9][A-Za-z0-9.-]*)-(\d+\.\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9.-]+)?)-(full|delta)\.nupkg')
    $nupkgRefs = @()
    foreach ($m in $nupkgMatches) {
        $nupkgRefs += [PSCustomObject]@{
            FileName = $m.Value
            AppName  = $m.Groups[1].Value
            Version  = $m.Groups[2].Value
            Kind     = $m.Groups[3].Value
        }
    }
    if ($nupkgRefs.Count -gt 0) {
        $preferred = $nupkgRefs | Where-Object Kind -EQ 'full' | Select-Object -First 1
        if (-not $preferred) { $preferred = $nupkgRefs[0] }
        $appName = $preferred.AppName
        $version = $preferred.Version
    }

    # URLs (may include the update feed; these are hints, not authoritative)
    $urls = @([regex]::Matches($asciiText, 'https?://[^\s"''<>\x00]+') |
              ForEach-Object { $_.Value } |
              Sort-Object -Unique |
              Select-Object -First 20)

    $confidence = if ($markersFound.Count -ge 3 -and $nupkgRefs.Count -gt 0) { 'High' }
                  elseif ($markersFound.Count -ge 2) { 'High' }
                  elseif ($markersFound.Count -ge 1 -and $hasUpdateExe) { 'Medium' }
                  elseif ($hasUpdateExe) { 'Low' }
                  else { 'Low' }

    $displayName = if ($appName) { $appName } else { [System.IO.Path]::GetFileNameWithoutExtension($Path) }

    return [PSCustomObject]@{
        InstallerType           = 'Squirrel'
        DisplayName             = $displayName
        DisplayVersion          = $version
        Publisher               = ''
        Architecture            = 'N/A (see embedded PE of bundled app)'
        ProductCodeOrEquivalent = $appName
        MarkersFound            = $markersFound
        HasUpdateExe            = $hasUpdateExe
        NupkgReferences         = $nupkgRefs
        ObservedUrls            = $urls
        Confidence              = $confidence
        SilentInstallCommand    = '"<Setup.exe>" --silent   # installs to %LOCALAPPDATA%\<AppName>\ per-user'
        SilentUninstallCommand  = '"%LOCALAPPDATA%\<AppName>\Update.exe" --uninstall -s'
    }
}

# ---------------------------------------------------------------------------
# MSI Analysis
# ---------------------------------------------------------------------------

function Test-MsiModuleAvailable {
    <#
    .SYNOPSIS
        Checks if the MSI module is available -- currently loaded in the session
        (vendored under Lib\MSI\ and imported by the shell at startup) OR
        installed on the system (PSGallery).
    #>
    if ($null -eq $script:MsiModuleAvailable) {
        $loaded = $null -ne (Get-Module -Name MSI -ErrorAction SilentlyContinue)
        $onDisk = $null -ne (Get-Module -ListAvailable -Name MSI -ErrorAction SilentlyContinue)
        $script:MsiModuleAvailable = $loaded -or $onDisk
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns an ordered hashtable of every MSI Property table row by design; Get-MsiProperty would imply a single named property.')]
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
        while ($true) {
            $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
            if ($null -eq $record) { break }
            $propName = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
            $propValue = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 2)
            $result[$propName] = $propValue
            [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) | Out-Null
        }

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
        $summaryInfo = $db.GetType().InvokeMember("SummaryInformation", "GetProperty", $null, $db, @(0))

        $template = $summaryInfo.GetType().InvokeMember("Property", "GetProperty", $null, $summaryInfo, @(7))
        $revision = $summaryInfo.GetType().InvokeMember("Property", "GetProperty", $null, $summaryInfo, @(9))
        $subject  = $summaryInfo.GetType().InvokeMember("Property", "GetProperty", $null, $summaryInfo, @(3))
        $author   = $summaryInfo.GetType().InvokeMember("Property", "GetProperty", $null, $summaryInfo, @(4))

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
# Deployment Field Resolution
# ---------------------------------------------------------------------------

function Get-DeploymentFields {
    <#
    .SYNOPSIS
        Resolves common Add/Remove Programs registry fields from available installer metadata.
    .DESCRIPTION
        Derives DisplayName, DisplayVersion, SilentUninstallString, and Vendor from the best
        available source. Priority (highest first):
        1. PackageMetadata (from Get-ChocolateyMetadata / Get-IntunewinMetadata / Get-MsixManifest / Get-PsadtMetadata / Get-SquirrelMetadata)
        2. MSI properties
        3. FileVersionInfo
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns a PSCustomObject aggregating multiple ARP fields; singular would imply a single-field lookup.')]
    param(
        [Parameter(Mandatory)][PSCustomObject]$FileInfo,
        [hashtable]$MsiProperties,
        [PSCustomObject]$Switches,
        [PSCustomObject]$PackageMetadata
    )

    # DisplayName: PackageMetadata.DisplayName > MSI ProductName > FileVersionInfo ProductName > FileDescription
    $displayName = if ($PackageMetadata -and $PackageMetadata.DisplayName) {
        $PackageMetadata.DisplayName
    } elseif ($MsiProperties -and $MsiProperties.Contains('ProductName') -and $MsiProperties['ProductName']) {
        $MsiProperties['ProductName']
    } elseif ($FileInfo.ProductName) {
        $FileInfo.ProductName
    } elseif ($FileInfo.FileDescription) {
        $FileInfo.FileDescription
    } else { '' }

    # DisplayVersion: PackageMetadata.DisplayVersion > MSI ProductVersion > FileVersionInfo ProductVersion > FileVersion
    $displayVersion = if ($PackageMetadata -and $PackageMetadata.DisplayVersion) {
        $PackageMetadata.DisplayVersion
    } elseif ($MsiProperties -and $MsiProperties.Contains('ProductVersion') -and $MsiProperties['ProductVersion']) {
        $MsiProperties['ProductVersion']
    } elseif ($FileInfo.ProductVersion) {
        $FileInfo.ProductVersion
    } elseif ($FileInfo.FileVersion) {
        $FileInfo.FileVersion
    } else { '' }

    # SilentUninstallString: PackageMetadata.SilentUninstallCommand > Switches.Uninstall
    $silentUninstallString = if ($PackageMetadata -and $PackageMetadata.SilentUninstallCommand) {
        $PackageMetadata.SilentUninstallCommand
    } elseif ($Switches) {
        $Switches.Uninstall
    } else { '' }

    # Vendor: PackageMetadata.Publisher > MSI Manufacturer > FileVersionInfo CompanyName
    $vendor = if ($PackageMetadata -and $PackageMetadata.Publisher) {
        $PackageMetadata.Publisher
    } elseif ($MsiProperties -and $MsiProperties.Contains('Manufacturer') -and $MsiProperties['Manufacturer']) {
        $MsiProperties['Manufacturer']
    } elseif ($FileInfo.CompanyName) {
        $FileInfo.CompanyName
    } else { '' }

    return [PSCustomObject]@{
        DisplayName          = $displayName
        DisplayVersion       = $displayVersion
        SilentUninstallString = $silentUninstallString
        Vendor               = $vendor
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
        'BitRock' = @{
            Install   = '"<EXE>" --mode unattended --unattendedmodeui none'
            Uninstall = '"<UninstallEXE>" --mode unattended --unattendedmodeui none'
            Notes     = 'BitRock InstallBuilder (used by PostgreSQL, Bitnami, JFrog Artifactory, etc.). Modes: unattended, text, gtk, win32, osx, xwindow. Run with --help for the full switch list on a specific product. Uninstaller lives at %INSTALLDIR%\uninstall.exe by default.'
        }
        'Chocolatey' = @{
            Install   = 'choco install <PackageId> --version=<Version> -y --source="<SourceDirOrFeed>"'
            Uninstall = 'choco uninstall <PackageId> -y'
            Notes     = 'Requires Chocolatey runtime (choco.exe). Package metadata lives in <PackageId>.nuspec at archive root; install script at tools/chocolateyInstall.ps1.'
        }
        'Intunewin' = @{
            Install   = '"<ExtractedSetup>" <OriginalSilentSwitches>  # decrypted server-side by Intune Management Extension'
            Uninstall = 'Defined in the Intune portal, not in the .intunewin file.'
            Notes     = 'Not directly executable. The inner IntunePackage.intunewin is AES-encrypted; decryption keys are delivered by Intune to the managed endpoint. Metadata lives in IntuneWinPackage/Metadata/Detection.xml; MsiInfo sub-element appears only when the source installer was an MSI.'
        }
        'Msix' = @{
            Install   = 'Add-AppxPackage -Path "<msix>"   # per-user install'
            Uninstall = 'Remove-AppxPackage -Package "<PackageFullName>"'
            Notes     = 'Per-user: Add-AppxPackage. All-users / provisioned: Add-AppxProvisionedPackage -Online -PackagePath "<msix>" -SkipLicense. PackageFullName = Name_Version_Arch_ResourceId_PublisherHash; retrieve via Get-AppxPackage after install. Applies to .msix and .appx.'
        }
        'MsixBundle' = @{
            Install   = 'Add-AppxPackage -Path "<msixbundle>"'
            Uninstall = 'Remove-AppxPackage -Package "<PackageFullName>"'
            Notes     = 'Same cmdlets as single MSIX. Bundle targets multiple architectures (x86/x64/ARM64) and/or language resource packs; AppxBundleManifest.xml lists which.'
        }
        'PsadtV3' = @{
            Install   = 'Deploy-Application.exe -DeploymentType Install -DeployMode Silent'
            Uninstall = 'Deploy-Application.exe -DeploymentType Uninstall -DeployMode Silent'
            Notes     = 'PowerShell App Deployment Toolkit v3. Wrapper script -- the Deploy-Application.ps1 file contains per-app install/uninstall logic. Pure .ps1 form: powershell.exe -ExecutionPolicy Bypass -File Deploy-Application.ps1 -DeploymentType Install -DeployMode Silent'
        }
        'PsadtV4' = @{
            Install   = 'Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode Silent'
            Uninstall = 'Invoke-AppDeployToolkit.exe -DeploymentType Uninstall -DeployMode Silent'
            Notes     = 'PowerShell App Deployment Toolkit v4. Toolkit logic lives in the PSAppDeployToolkit module; per-app logic in Invoke-AppDeployToolkit.ps1. Pure .ps1 form: powershell.exe -ExecutionPolicy Bypass -File Invoke-AppDeployToolkit.ps1 -DeploymentType Install -DeployMode Silent'
        }
        'Squirrel' = @{
            Install   = '"<Setup.exe>" --silent'
            Uninstall = '"%LOCALAPPDATA%\<AppName>\Update.exe" --uninstall -s'
            Notes     = 'Squirrel.Windows / Electron Setup.exe. Installs per-user to %LOCALAPPDATA%\<AppName>\. Use --silent (double-dash, lowercase), NOT the /S NSIS switch. Update.exe ships alongside the app and handles uninstalls and in-place updates.'
        }
        'NuGet' = @{
            Install   = 'nuget install <PackageId> -Version <Version> -Source "<SourceDirOrFeed>"'
            Uninstall = 'N/A (NuGet is a package source, not an installer)'
            Notes     = 'Plain NuGet package without Chocolatey tools. Not end-user installable by itself.'
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns both install and uninstall switches on one object; plural matches the pair being returned.')]
    param(
        [Parameter(Mandatory)][string]$InstallerType,
        [Parameter(Mandatory)][string]$FilePath,
        [hashtable]$MsiProperties
    )

    $db = Get-SilentSwitchDatabase
    $fileName = Split-Path -Leaf $FilePath

    if (-not $db.Contains($InstallerType)) { $InstallerType = 'Unknown' }
    $entry = $db[$InstallerType]

    $install   = $entry.Install -replace '<EXE>', $fileName -replace '<MSI>', $fileName
    $uninstall = $entry.Uninstall -replace '<EXE>', $fileName -replace '<UninstallEXE>', 'uninstall.exe'

    if ($MsiProperties -and $MsiProperties.Contains('ProductCode')) {
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
    .DESCRIPTION
        Preferred path wins if valid; otherwise the standard Program Files
        locations; otherwise whatever `Get-Command 7z.exe` resolves from
        PATH (covers scoop / chocolatey / user-local installs).
    #>
    param([string]$PreferredPath)

    if ($PreferredPath -and (Test-Path -LiteralPath $PreferredPath)) { return $PreferredPath }

    $candidates = @(
        'C:\Program Files\7-Zip\7z.exe'
        'C:\Program Files (x86)\7-Zip\7z.exe'
    )
    # Also consider whatever is on PATH (covers non-standard install locations
    # like scoop, chocolatey user-local, portable copies).
    $fromPath = Get-Command '7z.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1
    if ($fromPath) { $candidates += $fromPath }

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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns the full contents listing from 7z l; plural matches the collection being returned.')]
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns the collection of printable strings found in the binary.')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MinLength = 8,
        [int]$MaxBytes = 2MB
    )

    $fileSize = (Get-Item -LiteralPath $Path).Length
    $readSize = [Math]::Min($MaxBytes, $fileSize)

    $stream = $null
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $bytes = New-Object byte[] $readSize
        $stream.Read($bytes, 0, $readSize) | Out-Null
    }
    finally {
        if ($stream) { try { $stream.Close() } catch { $null = $_ } }
    }

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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Returns a categorized collection of interesting strings.')]
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
        Returns a clipboard-ready text summary of the analysis, including any
        format-specific PACKAGE METADATA section for modern package types.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Pure function that builds a string; does not touch external state.')]
    param(
        [Parameter(Mandatory)][PSCustomObject]$FileInfo,
        [Parameter(Mandatory)][string]$InstallerType,
        [PSCustomObject]$Switches,
        [hashtable]$MsiProperties,
        [PSCustomObject]$DeploymentFields,
        [PSCustomObject]$PackageMetadata
    )

    $lines = @(
        "Installer Analysis: $($FileInfo.FileName)",
        ("-" * 50),
        "Type:         $InstallerType",
        "Architecture: $($FileInfo.Architecture)",
        "Version:      $(if ($DeploymentFields) { $DeploymentFields.DisplayVersion } elseif ($FileInfo.ProductVersion) { $FileInfo.ProductVersion } else { $FileInfo.FileVersion })",
        "Company:      $($FileInfo.CompanyName)",
        "Size:         $($FileInfo.FileSizeFormatted)",
        "SHA-256:      $($FileInfo.SHA256)",
        "Signed:       $($FileInfo.SignatureStatus)$(if ($FileInfo.SignerSubject) { " ($($FileInfo.SignerSubject))" })",
        "",
        "Silent Install:    $($Switches.Install)",
        "Silent Uninstall:  $($Switches.Uninstall)",
        "Notes:             $($Switches.Notes)"
    )

    if ($DeploymentFields) {
        $lines += ""
        $lines += "Deployment Fields:"
        $lines += "  DisplayName:           $($DeploymentFields.DisplayName)"
        $lines += "  DisplayVersion:        $($DeploymentFields.DisplayVersion)"
        $lines += "  Vendor:                $($DeploymentFields.Vendor)"
        $lines += "  SilentUninstallString: $($DeploymentFields.SilentUninstallString)"
    }

    if ($MsiProperties -and $MsiProperties.Count -gt 0) {
        $lines += ""
        $lines += "MSI Properties:"
        if ($MsiProperties.Contains('ProductCode'))  { $lines += "  Product Code:  $($MsiProperties['ProductCode'])" }
        if ($MsiProperties.Contains('UpgradeCode'))  { $lines += "  Upgrade Code:  $($MsiProperties['UpgradeCode'])" }
        if ($MsiProperties.Contains('ProductVersion')) { $lines += "  Version:       $($MsiProperties['ProductVersion'])" }
        if ($MsiProperties.Contains('Manufacturer'))  { $lines += "  Manufacturer:  $($MsiProperties['Manufacturer'])" }
    }

    if ($PackageMetadata) {
        $pkg = $PackageMetadata
        $pkgType = if ($pkg.PSObject.Properties['InstallerType']) { [string]$pkg.InstallerType } else { $InstallerType }
        $hasAnyPkg = $false

        switch ($pkgType) {
            { $_ -in 'Chocolatey','NuGet' } {
                $lines += ""; $lines += "Package Metadata (nuspec):"
                if ($pkg.PSObject.Properties['PackageId'])  { $lines += "  Id:            $($pkg.PackageId)" }
                if ($pkg.PSObject.Properties['DisplayVersion']) { $lines += "  Version:       $($pkg.DisplayVersion)" }
                if ($pkg.PSObject.Properties['Publisher']) { $lines += "  Authors:       $($pkg.Publisher)" }
                if ($pkg.PSObject.Properties['ProjectUrl']) { $lines += "  Project URL:   $($pkg.ProjectUrl)" }
                if ($pkg.PSObject.Properties['Tags'])        { $lines += "  Tags:          $($pkg.Tags)" }
                if ($pkg.PSObject.Properties['Description'] -and $pkg.Description) {
                    $desc = [string]$pkg.Description
                    if ($desc.Length -gt 140) { $desc = $desc.Substring(0,137) + '...' }
                    $lines += "  Description:   $desc"
                }
                $hasAnyPkg = $true
            }
            'Intunewin' {
                $lines += ""; $lines += "Package Metadata (IntuneWinPackage\Metadata\Detection.xml):"
                if ($pkg.PSObject.Properties['DisplayName']) { $lines += "  Name:          $($pkg.DisplayName)" }
                if ($pkg.PSObject.Properties['SetupFile'])    { $lines += "  Setup File:    $($pkg.SetupFile)" }
                if ($pkg.PSObject.Properties['ToolVersion'])  { $lines += "  Tool Version:  $($pkg.ToolVersion)" }
                if ($pkg.PSObject.Properties['EncryptionInfo'] -and $pkg.EncryptionInfo) {
                    $lines += "  Encrypted:     yes (payload keys live in Intune; cannot decrypt locally)"
                }
                if ($pkg.PSObject.Properties['MsiInfo'] -and $pkg.MsiInfo) {
                    $mi = $pkg.MsiInfo
                    $lines += "  Source MSI:"
                    foreach ($prop in 'MsiProductCode','MsiProductVersion','MsiUpgradeCode','MsiExecutionContext','MsiRequiresReboot') {
                        if ($mi.PSObject.Properties[$prop] -and $mi.$prop) {
                            $lines += ("    {0,-22} {1}" -f ($prop + ':'), $mi.$prop)
                        }
                    }
                }
                $hasAnyPkg = $true
            }
            { $_ -in 'Msix','MsixBundle' } {
                $lines += ""; $lines += "Package Metadata (AppxManifest):"
                if ($pkg.PSObject.Properties['Identity'] -and $pkg.Identity) {
                    $id = $pkg.Identity
                    $lines += "  Identity:"
                    foreach ($key in 'Name','Publisher','Version','ProcessorArchitecture','ResourceId') {
                        if ($id.$key) { $lines += ("    {0,-22} {1}" -f ($key + ':'), $id.$key) }
                    }
                }
                if ($pkg.PSObject.Properties['PropertiesDescription'] -and $pkg.PropertiesDescription) {
                    $lines += "  Description:   $($pkg.PropertiesDescription)"
                }
                if ($pkgType -eq 'MsixBundle' -and $pkg.PSObject.Properties['BundledPackages']) {
                    $bp = @($pkg.BundledPackages)
                    $lines += "  Bundled Packages: $($bp.Count)"
                    foreach ($b in $bp) {
                        $tok = @()
                        if ($b.Type)         { $tok += "[$($b.Type)]" }
                        if ($b.Architecture) { $tok += "arch=$($b.Architecture)" }
                        if ($b.Version)      { $tok += "v$($b.Version)" }
                        if ($b.ResourceId)   { $tok += "resource=$($b.ResourceId)" }
                        $tok += ($b.FileName)
                        $lines += ("    - " + ($tok -join '  '))
                    }
                }
                $hasAnyPkg = $true
            }
            { $_ -in 'PsadtV3','PsadtV4' } {
                $lines += ""; $lines += "Package Metadata (PSAppDeployToolkit $($pkg.ToolkitVariant) header):"
                if ($pkg.PSObject.Properties['ToolkitVersion'] -and $pkg.ToolkitVersion) {
                    $lines += "  Toolkit Ver:   $($pkg.ToolkitVersion)"
                }
                if ($pkg.PSObject.Properties['AppMetadata'] -and $pkg.AppMetadata) {
                    $am = $pkg.AppMetadata
                    $lines += "  App Header:"
                    foreach ($field in 'AppVendor','AppName','AppVersion','AppArch','AppLang','AppRevision','ScriptVersion','ScriptDate','ScriptAuthor') {
                        # AppMetadata is an ordered dictionary from ConvertFrom-PsadtDeployApplication
                        # ([ordered]@{}) which is System.Collections.IDictionary but NOT [hashtable].
                        # PSCustomObject AppMetadata also possible; accept both shapes.
                        $val = if ($am -is [System.Collections.IDictionary]) { $am[$field] } elseif ($am.PSObject.Properties[$field]) { $am.$field } else { '' }
                        if ($val) { $lines += ("    {0,-18} {1}" -f ($field + ':'), $val) }
                    }
                }
                $hasAnyPkg = $true
            }
            'Squirrel' {
                $lines += ""; $lines += "Package Metadata (Squirrel / Electron Setup.exe):"
                if ($pkg.PSObject.Properties['DisplayName'])    { $lines += "  App Name:      $($pkg.DisplayName)" }
                if ($pkg.PSObject.Properties['DisplayVersion']) { $lines += "  Version:       $($pkg.DisplayVersion)" }
                if ($pkg.PSObject.Properties['MarkersFound'] -and $pkg.MarkersFound) {
                    $markers = @($pkg.MarkersFound)
                    $lines += "  Markers:       $($markers.Count) found -> $($markers -join ', ')"
                }
                if ($pkg.PSObject.Properties['EmbeddedNupkg'] -and $pkg.EmbeddedNupkg) {
                    $lines += "  Embedded nupkg: $($pkg.EmbeddedNupkg)"
                }
                if ($pkg.PSObject.Properties['Confidence'] -and $pkg.Confidence) {
                    $lines += "  Confidence:    $($pkg.Confidence)"
                }
                $hasAnyPkg = $true
            }
            default { }
        }

        if (-not $hasAnyPkg) {
            # Generic fallback: dump well-known cross-format fields if present.
            $lines += ""; $lines += "Package Metadata:"
            foreach ($prop in 'DisplayName','DisplayVersion','Publisher','Architecture','ProductCodeOrEquivalent') {
                if ($pkg.PSObject.Properties[$prop] -and $pkg.$prop) {
                    $lines += ("  {0,-14} {1}" -f ($prop + ':'), $pkg.$prop)
                }
            }
        }
    }

    return ($lines -join "`r`n")
}

function ConvertTo-DeploymentJson {
    <#
    .SYNOPSIS
        Builds a MECM-packaging-friendly JSON digest of the analysis result.
    .DESCRIPTION
        Returns a single JSON string suitable for pasting into packaging scripts or
        the clipboard. Shape is a flat digest of the fields a packager needs:
        source-file metadata, application identity, deploy commands, and a detection
        hint keyed to the installer type. Format-specific extras are nested under
        Raw.PackageMetadata; MSI properties are nested under Raw.MsiProperties.

        Values default to empty strings (never $null) so downstream scripts can rely
        on the schema. Pair with Get-InstallerFileInfo / Get-DeploymentFields /
        Get-SilentSwitches / Get-MsiProperties / Get-*Metadata to fill the inputs.
    .EXAMPLE
        $json = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType 'NSIS' `
            -Switches $sw -DeploymentFields $df
        Set-Clipboard -Value $json
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Pure function that builds a JSON string; does not touch external state.')]
    param(
        [Parameter(Mandatory)][PSCustomObject]$FileInfo,
        [Parameter(Mandatory)][string]$InstallerType,
        [PSCustomObject]$Switches,
        [hashtable]$MsiProperties,
        [PSCustomObject]$DeploymentFields,
        [PSCustomObject]$PackageMetadata,
        [int]$Depth = 6
    )

    $productCode = ''
    $upgradeCode = ''
    if ($MsiProperties) {
        if ($MsiProperties.Contains('ProductCode') -and $MsiProperties['ProductCode']) { $productCode = [string]$MsiProperties['ProductCode'] }
        if ($MsiProperties.Contains('UpgradeCode') -and $MsiProperties['UpgradeCode']) { $upgradeCode = [string]$MsiProperties['UpgradeCode'] }
    }
    if (-not $productCode -and $PackageMetadata -and $PackageMetadata.PSObject.Properties['ProductCodeOrEquivalent']) {
        $productCode = [string]$PackageMetadata.ProductCodeOrEquivalent
    }

    $displayName = if ($DeploymentFields -and $DeploymentFields.DisplayName) { [string]$DeploymentFields.DisplayName }
                   elseif ($PackageMetadata -and $PackageMetadata.PSObject.Properties['DisplayName']) { [string]$PackageMetadata.DisplayName }
                   elseif ($FileInfo.ProductName) { [string]$FileInfo.ProductName }
                   elseif ($FileInfo.FileDescription) { [string]$FileInfo.FileDescription }
                   else { '' }

    $displayVersion = if ($DeploymentFields -and $DeploymentFields.DisplayVersion) { [string]$DeploymentFields.DisplayVersion }
                      elseif ($PackageMetadata -and $PackageMetadata.PSObject.Properties['DisplayVersion']) { [string]$PackageMetadata.DisplayVersion }
                      elseif ($FileInfo.ProductVersion) { [string]$FileInfo.ProductVersion }
                      elseif ($FileInfo.FileVersion) { [string]$FileInfo.FileVersion }
                      else { '' }

    $publisher = if ($DeploymentFields -and $DeploymentFields.Vendor) { [string]$DeploymentFields.Vendor }
                 elseif ($PackageMetadata -and $PackageMetadata.PSObject.Properties['Publisher']) { [string]$PackageMetadata.Publisher }
                 elseif ($FileInfo.CompanyName) { [string]$FileInfo.CompanyName }
                 else { '' }

    $architecture = if ($FileInfo.Architecture) { [string]$FileInfo.Architecture }
                    elseif ($PackageMetadata -and $PackageMetadata.PSObject.Properties['Architecture']) { [string]$PackageMetadata.Architecture }
                    else { '' }

    $installCmd = ''
    $uninstallCmd = ''
    $notes = ''
    if ($Switches) {
        if ($Switches.PSObject.Properties['Install'])   { $installCmd   = [string]$Switches.Install }
        if ($Switches.PSObject.Properties['Uninstall']) { $uninstallCmd = [string]$Switches.Uninstall }
        if ($Switches.PSObject.Properties['Notes'])     { $notes        = [string]$Switches.Notes }
    }
    if ($DeploymentFields -and $DeploymentFields.SilentUninstallString) {
        $uninstallCmd = [string]$DeploymentFields.SilentUninstallString
    }
    if ($PackageMetadata -and $PackageMetadata.PSObject.Properties['SilentInstallCommand'] -and $PackageMetadata.SilentInstallCommand) {
        $installCmd = [string]$PackageMetadata.SilentInstallCommand
    }
    if ($PackageMetadata -and $PackageMetadata.PSObject.Properties['SilentUninstallCommand'] -and $PackageMetadata.SilentUninstallCommand) {
        $uninstallCmd = [string]$PackageMetadata.SilentUninstallCommand
    }

    $detectionHint = switch ($InstallerType) {
        'MSI'        { if ($productCode) { "MSI ProductCode detection: $productCode" } else { 'MSI detection: use ProductCode from the MSI Property table' } }
        'NSIS'       { 'Registry uninstall key detection (HKLM\...\Uninstall\<DisplayName>) or file-version on the primary EXE' }
        'InnoSetup'  { 'Registry uninstall key detection (HKLM\...\Uninstall\<AppId>_is1) or file-version on the primary EXE' }
        'InstallShield' { 'Registry uninstall key detection or file-version on the primary EXE' }
        'WixBurn'    { 'BundleUpgradeCode or related MSI ProductCode under HKLM\...\Uninstall' }
        'BitRock'    { 'Registry uninstall key detection keyed on DisplayName (BitRock writes HKLM\...\Uninstall\<AppName> by default)' }
        'Msix'       { if ($PackageMetadata -and $PackageMetadata.PSObject.Properties['Identity']) { "MSIX family-name detection via Get-AppxPackage -Name $($PackageMetadata.Identity.Name)" } else { 'MSIX family-name detection via Get-AppxPackage' } }
        'MsixBundle' { if ($PackageMetadata -and $PackageMetadata.PSObject.Properties['Identity']) { "MSIX bundle family-name detection via Get-AppxPackage -Name $($PackageMetadata.Identity.Name)" } else { 'MSIX bundle family-name detection via Get-AppxPackage' } }
        'Chocolatey' { if ($PackageMetadata -and $PackageMetadata.PSObject.Properties['PackageId']) { "Chocolatey package detection: choco list --local-only $($PackageMetadata.PackageId)" } else { 'Chocolatey package detection via choco list --local-only' } }
        'NuGet'      { 'NuGet-package detection via nuget list or the consumer package manager' }
        'Intunewin'  { 'Intune-managed detection defined in the Intune portal; see Detection.xml for the source installer hints' }
        'PsadtV3'    { 'Registry uninstall key detection keyed on AppName/AppVersion (configure in Deploy-Application.ps1)' }
        'PsadtV4'    { 'Registry uninstall key detection keyed on AppName/AppVersion (configure in Invoke-AppDeployToolkit.ps1)' }
        'Squirrel'   { 'Registry uninstall key in HKCU\...\Uninstall\<AppName> (per-user) or file-version on the installed AppName.exe' }
        '7zSFX'      { 'Not a true installer; detection depends on the extracted payload' }
        'WinRarSFX'  { 'Not a true installer; detection depends on the extracted payload' }
        default      { 'Pick a file-version or registry-uninstall detection per the extracted payload' }
    }

    $blob = [ordered]@{
        SchemaVersion    = '1.0'
        Source           = [ordered]@{
            FileName = if ($FileInfo.FileName) { [string]$FileInfo.FileName } else { '' }
            FileSize = if ($FileInfo.FileSize) { [long]$FileInfo.FileSize } else { 0 }
            SHA256   = if ($FileInfo.SHA256)   { [string]$FileInfo.SHA256 } else { '' }
        }
        Application      = [ordered]@{
            DisplayName    = $displayName
            DisplayVersion = $displayVersion
            Publisher      = $publisher
            Architecture   = $architecture
            InstallerType  = $InstallerType
            ProductCode    = $productCode
            UpgradeCode    = $upgradeCode
        }
        Deployment       = [ordered]@{
            InstallCommand   = $installCmd
            UninstallCommand = $uninstallCmd
            Notes            = $notes
        }
        Detection        = [ordered]@{
            Hint = [string]$detectionHint
        }
        Raw              = [ordered]@{
            MsiProperties   = if ($MsiProperties) { $MsiProperties } else { [ordered]@{} }
            PackageMetadata = if ($PackageMetadata) { $PackageMetadata } else { $null }
        }
    }

    return ($blob | ConvertTo-Json -Depth $Depth)
}
