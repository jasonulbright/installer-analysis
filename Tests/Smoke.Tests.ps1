#Requires -Modules Pester
# Smoke test of Installer Analysis. It was a stand-alone script that printed PASS and FAIL
# lines and set an exit code. It is now a Pester file with the same checks, so that
# Invoke-Checks.ps1 runs it: the module loads, every exported function exists, every
# package format reads from a small synthetic file, and the core pipeline returns a
# result. Window.Tests.ps1 covers the window XAML.
# The optional run against real installers (stage 6 of the old script) stays: it runs
# only when the folder given by IA_REAL_FIXTURE_DIR (default c:\temp\ap) holds installers.

BeforeDiscovery {
    $script:RealDir = if ($env:IA_REAL_FIXTURE_DIR) { $env:IA_REAL_FIXTURE_DIR } else { 'c:\temp\ap' }
    $script:RealInstallers = @()
    if (Test-Path -LiteralPath $script:RealDir) {
        $script:RealInstallers = @(Get-ChildItem -LiteralPath $script:RealDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.msi', '.exe', '.msix', '.msixbundle', '.appx', '.intunewin', '.nupkg' } |
                Select-Object -First 3 | ForEach-Object { @{ Path = $_.FullName; Leaf = $_.Name } })
    }
}

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    # BeforeDiscovery variables are not visible while the tests run.
    $realDir = if ($env:IA_REAL_FIXTURE_DIR) { $env:IA_REAL_FIXTURE_DIR } else { 'c:\temp\ap' }
    $script:RealInstallers = @()
    if (Test-Path -LiteralPath $realDir) {
        $script:RealInstallers = @(Get-ChildItem -LiteralPath $realDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.msi', '.exe', '.msix', '.msixbundle', '.appx', '.intunewin', '.nupkg' } |
                Select-Object -First 3 | ForEach-Object { @{ Path = $_.FullName; Leaf = $_.Name } })
    }
    Import-AppModule
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-smoke-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    function script:New-SmokeZip {
        param([string]$Path, [hashtable]$Entries)
        $archive = [System.IO.Compression.ZipFile]::Open($Path, 'Create')
        try {
            foreach ($key in $Entries.Keys) {
                $entry = $archive.CreateEntry($key)
                $stream = $entry.Open()
                try {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Entries[$key])
                    $stream.Write($bytes, 0, $bytes.Length)
                }
                finally { $stream.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }

    $nuspec = '<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd"><metadata><id>smoke</id><version>1.0.0</version><authors>smoke</authors><description>smoke fixture</description></metadata></package>'
    $detection = '<?xml version="1.0" encoding="utf-8"?><ApplicationInfo ToolVersion="1.8.5"><Name>Smoke</Name><SetupFile>setup.exe</SetupFile><EncryptionInfo><EncryptionKey>x</EncryptionKey></EncryptionInfo></ApplicationInfo>'
    $msix = '<?xml version="1.0" encoding="utf-8"?><Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Smoke.App" Publisher="CN=Smoke" Version="1.0.0.0" ProcessorArchitecture="x64"/><Properties><DisplayName>Smoke App</DisplayName><PublisherDisplayName>Smoke</PublisherDisplayName></Properties></Package>'
    $bundle = '<?xml version="1.0" encoding="utf-8"?><Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Smoke.Bundle" Publisher="CN=Smoke" Version="9.0.0.0"/><Packages><Package Type="application" Version="9.0.0.0" Architecture="x64" FileName="Smoke.x64.msix"/></Packages></Bundle>'
    $script:Fixture = @{
        Chocolatey = Join-Path $script:Work 'smoke.nupkg'
        Intunewin  = Join-Path $script:Work 'smoke.intunewin'
        Msix       = Join-Path $script:Work 'smoke.msix'
        Bundle     = Join-Path $script:Work 'smoke.msixbundle'
        PsadtV3    = Join-Path $script:Work 'psadt3.zip'
        PsadtV4    = Join-Path $script:Work 'psadt4.zip'
        Squirrel   = Join-Path $script:Work 'SmokeSetup.exe'
    }
    New-SmokeZip -Path $script:Fixture.Chocolatey -Entries @{ 'smoke.nuspec' = $nuspec; 'tools/chocolateyinstall.ps1' = '# noop' }
    New-SmokeZip -Path $script:Fixture.Intunewin -Entries @{ 'IntuneWinPackage/Metadata/Detection.xml' = $detection }
    New-SmokeZip -Path $script:Fixture.Msix -Entries @{ 'AppxManifest.xml' = $msix }
    New-SmokeZip -Path $script:Fixture.Bundle -Entries @{ 'AppxMetadata/AppxBundleManifest.xml' = $bundle }
    New-SmokeZip -Path $script:Fixture.PsadtV3 -Entries @{
        'Deploy-Application.ps1'                    = "[String]`$appVendor = 'Smoke'`r`n[String]`$appName = 'Smoke'`r`n[String]`$appVersion = '1.0.0'"
        'AppDeployToolkit/AppDeployToolkitMain.ps1' = '# v3 engine'
    }
    New-SmokeZip -Path $script:Fixture.PsadtV4 -Entries @{
        'Invoke-AppDeployToolkit.ps1' = "`$adtSession = @{ AppVendor = 'Smoke'; AppName = 'Smoke'; AppVersion = '1.0.0' }"
        'PSAppDeployToolkit.psd1'     = '# v4 manifest'
    }
    $markers = "SquirrelTemp`0squirrel-install`0squirrel-updated`0Update.exe`0Smoke-1.0.0-full.nupkg"
    [System.IO.File]::WriteAllBytes($script:Fixture.Squirrel, ([byte[]](1..64) + [System.Text.Encoding]::ASCII.GetBytes($markers)))
}

AfterAll {
    Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Module load' {
    It 'registers every function that the manifest exports' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:AppRoot 'Module\InstallerAnalysisCommon.psd1')
        $missing = @($manifest.FunctionsToExport | Where-Object { -not (Get-Command -Name $_ -Module InstallerAnalysisCommon -ErrorAction SilentlyContinue) })
        $missing | Should -BeNullOrEmpty
        @($manifest.FunctionsToExport).Count | Should -BeGreaterThan 20
    }
}

Describe 'Synthetic package formats' {
    It 'reads <Case> and returns a result' -ForEach @(
        @{ Case = 'a Chocolatey package'; Key = 'Chocolatey'; Command = 'Get-ChocolateyMetadata'; Parameter = 'Path' }
        @{ Case = 'an Intunewin package'; Key = 'Intunewin'; Command = 'Get-IntunewinMetadata'; Parameter = 'Path' }
        @{ Case = 'an MSIX package'; Key = 'Msix'; Command = 'Get-MsixManifest'; Parameter = 'Path' }
        @{ Case = 'an MSIX bundle'; Key = 'Bundle'; Command = 'Get-MsixManifest'; Parameter = 'Path' }
        @{ Case = 'a PSADT v3 layout'; Key = 'PsadtV3'; Command = 'Get-PsadtMetadata'; Parameter = 'Path' }
        @{ Case = 'a PSADT v4 layout'; Key = 'PsadtV4'; Command = 'Get-PsadtMetadata'; Parameter = 'Path' }
        @{ Case = 'a Squirrel installer'; Key = 'Squirrel'; Command = 'Get-SquirrelMetadata'; Parameter = 'Path' }
    ) {
        $arguments = @{ $Parameter = $script:Fixture[$Key] }
        $result = & $Command @arguments
        $result | Should -Not -BeNullOrEmpty
    }
}

Describe 'Core pipeline' {
    It 'turns a silent-switch result and file information into deployment fields and a JSON digest' {
        $fileInfo = [PSCustomObject]@{ FileName = 'setup.exe'; ProductName = 'Smoke Product'; ProductVersion = '1.0.0'; FileVersion = '1.0.0.0'; FileDescription = 'Smoke setup'; CompanyName = 'Smoke Vendor' }
        $switches = Get-SilentSwitches -InstallerType 'NSIS' -FilePath 'C:\tmp\setup.exe'
        $switches | Should -Not -BeNullOrEmpty
        $deploy = Get-DeploymentFields -FileInfo $fileInfo -Switches $switches
        $deploy.DisplayName | Should -Not -BeNullOrEmpty
        $json = ConvertTo-DeploymentJson -FileInfo $fileInfo -InstallerType 'NSIS' -Switches $switches -DeploymentFields $deploy
        $parsed = $json | ConvertFrom-Json
        $parsed.SchemaVersion | Should -Not -BeNullOrEmpty
        $parsed.Application.InstallerType | Should -Be 'NSIS'
    }
}

Describe 'Real installers (optional)' {
    It 'analyzes each installer in the real-installer folder end to end' -Skip:($script:RealInstallers.Count -eq 0) {
        foreach ($installer in $script:RealInstallers) {
            $Path = $installer.Path
            $fi = Get-InstallerFileInfo -Path $Path
            $type = Get-InstallerType -Path $Path
            $fi | Should -Not -BeNullOrEmpty -Because $installer.Leaf
            $type | Should -Not -BeNullOrEmpty -Because $installer.Leaf
            $msi = if ($type -eq 'MSI') { Get-MsiProperties -MsiPath $Path }
            $switches = Get-SilentSwitches -InstallerType $type -FilePath $Path -MsiProperties $msi
            $deploy = Get-DeploymentFields -FileInfo $fi -MsiProperties $msi -Switches $switches
            $parsed = ConvertTo-DeploymentJson -FileInfo $fi -InstallerType $type -Switches $switches -DeploymentFields $deploy -MsiProperties $msi | ConvertFrom-Json
            $parsed.Application.DisplayName | Should -Not -BeNullOrEmpty -Because $installer.Leaf
        }
    }
}