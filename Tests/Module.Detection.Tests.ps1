#Requires -Modules Pester
# Prediction of the Add/Remove Programs key and the detection hint of the JSON digest, for each
# installer type, with the inputs that decide the result and with inputs that are missing.

BeforeDiscovery {
    $arp64 = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    $arp32 = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    $arpUser = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    $script:KeyCases = @(
        @{ Case = 'MSI per machine, x64 template'; Type = 'MSI'; Msi = @{ ProductCode = '{PC}' }; Arch = 'x64'; Path = "$arp64\{PC}"; Hive = 'HKLM'; Note = '*Per-machine MSI*' }
        @{ Case = 'MSI per machine, x86 template'; Type = 'MSI'; Msi = @{ ProductCode = '{PC}' }; Arch = 'x86'; Path = "$arp32\{PC}"; Hive = 'HKLM'; Note = '*WOW6432Node*' }
        @{ Case = 'MSI per machine, template not supplied'; Type = 'MSI'; Msi = @{ ProductCode = '{PC}' }; FileArch = 'N/A (see MSI Summary)'; Path = "$arp64\{PC}"; Hive = 'HKLM'; Note = '*Architecture unknown*' }
        @{ Case = 'MSI with ALLUSERS=1'; Type = 'MSI'; Msi = @{ ProductCode = '{PC}'; ALLUSERS = '1' }; Arch = 'x64'; Path = "$arp64\{PC}"; Hive = 'HKLM'; Note = '*' }
        @{ Case = 'MSI with empty ALLUSERS'; Type = 'MSI'; Msi = @{ ProductCode = '{PC}'; ALLUSERS = '' }; Arch = 'x64'; Path = "$arpUser\{PC}"; Hive = 'HKCU'; Note = '*per-user*' }
        @{ Case = 'MSI with ALLUSERS=2 and MSIINSTALLPERUSER=1'; Type = 'MSI'; Msi = @{ ProductCode = '{PC}'; ALLUSERS = '2'; MSIINSTALLPERUSER = '1' }; Arch = 'x64'; Path = "$arpUser\{PC}"; Hive = 'HKCU'; Note = '*per-user*' }
        @{ Case = 'MSI with ALLUSERS=2 and no per-user flag'; Type = 'MSI'; Msi = @{ ProductCode = '{PC}'; ALLUSERS = '2' }; Arch = 'x64'; Path = "$arp64\{PC}"; Hive = 'HKLM'; Note = '*' }
        @{ Case = 'MSI with MSIINSTALLPERUSER=1 and no ALLUSERS'; Type = 'MSI'; Msi = @{ ProductCode = '{PC}'; MSIINSTALLPERUSER = '1' }; Arch = 'x64'; Path = "$arpUser\{PC}"; Hive = 'HKCU'; Note = '*per-user*' }
        @{ Case = 'WiX Burn with a bundle key'; Type = 'WixBurn'; Pkg = @{ UninstallRegistryKey = 'HKLM:\...\{Bundle}'; UninstallRegistryKeyNote = 'burn note' }; Path = 'HKLM:\...\{Bundle}'; Hive = 'HKLM'; Note = 'burn note' }
        @{ Case = 'Velopack with a key'; Type = 'Velopack'; Pkg = @{ HeaderAvailable = $true; UninstallRegistryKey = 'HKCU:\...\AcmeApp' }; Path = 'HKCU:\...\AcmeApp'; Hive = 'HKCU'; Note = '*Velopack*' }
        @{ Case = 'Squirrel with the app id'; Type = 'Squirrel'; Pkg = @{ ProductCodeOrEquivalent = 'acme' }; Path = "$arpUser\acme"; Hive = 'HKCU'; Note = '' }
        @{ Case = 'Squirrel with only a display name'; Type = 'Squirrel'; Pkg = @{ DisplayName = 'Acme App' }; Path = "$arpUser\Acme App"; Hive = 'HKCU'; Note = '' }
        @{ Case = 'Inno Setup with a decoded header'; Type = 'InnoSetup'; Pkg = @{ HeaderAvailable = $true; UninstallRegistryKey = 'HKLM:\...\{AppId}_is1'; RegistryHive = 'HKCU' }; Path = 'HKLM:\...\{AppId}_is1'; Hive = 'HKCU'; Note = '*_is1*' }
        @{ Case = 'Inno Setup with only a note'; Type = 'InnoSetup'; Pkg = @{ HeaderAvailable = $true; UninstallRegistryKeyNote = 'AppId unknown' }; Path = ''; Hive = ''; Note = 'AppId unknown' }
        @{ Case = 'Inno Setup by display name'; Type = 'InnoSetup'; Deploy = @{ DisplayName = 'Acme' }; Path = "$arp64\Acme_is1"; Hive = 'HKLM'; Note = '*_is1*' }
        @{ Case = 'NSIS with a decoded key'; Type = 'NSIS'; Pkg = @{ UninstallRegistryKey = 'HKCU:\...\Acme'; RegistryHive = 'HKCU' }; Path = 'HKCU:\...\Acme'; Hive = 'HKCU'; Note = '*WriteRegStr*' }
        @{ Case = 'NSIS by display name'; Type = 'NSIS'; Deploy = @{ DisplayName = 'Acme' }; Path = "$arp64\Acme"; Hive = 'HKLM'; Note = '*script-defined*' }
        @{ Case = 'NSIS by display name with a note'; Type = 'NSIS'; Deploy = @{ DisplayName = 'Acme' }; Pkg = @{ UninstallRegistryKeyNote = 'custom note' }; Path = "$arp64\Acme"; Hive = 'HKLM'; Note = 'custom note' }
        @{ Case = 'InstallShield with a product code'; Type = 'InstallShield'; Msi = @{ ProductCode = '{IS}' }; Path = "$arp64\{IS}"; Hive = 'HKLM'; Note = '*InstallShield*' }
        @{ Case = 'PSADT v4 by AppName'; Type = 'PsadtV4'; Pkg = @{ AppMetadata = ([ordered]@{ AppName = 'Acme' }) }; Path = "$arp64\Acme"; Hive = 'HKLM'; Note = '*PSADT*' }
        @{ Case = 'PSADT v3 by display name'; Type = 'PsadtV3'; Deploy = @{ DisplayName = 'Acme' }; Path = "$arp64\Acme"; Hive = 'HKLM'; Note = '*PSADT*' }
        @{ Case = 'BitRock by display name'; Type = 'BitRock'; Deploy = @{ DisplayName = 'Acme' }; Path = "$arp64\Acme"; Hive = 'HKLM'; Note = '*BitRock*' }
        @{ Case = 'Advanced Installer with a product code'; Type = 'AdvancedInstaller'; Msi = @{ ProductCode = '{AI}' }; Path = "$arp64\{AI}"; Hive = 'HKLM'; Note = '*Advanced Installer*' }
        @{ Case = 'MSIX by identity name'; Type = 'Msix'; Pkg = @{ Identity = [pscustomobject]@{ Name = 'Acme.App' } }; Path = "Get-AppxPackage -Name 'Acme.App'"; Hive = 'AppX (not ARP)'; Note = '*do NOT register*' }
    )
    $script:NoKeyCases = @(
        @{ Case = 'MSI without a product code'; Type = 'MSI'; Msi = @{ ProductName = 'x' } }
        @{ Case = 'WiX Burn without a bundle key'; Type = 'WixBurn' }
        @{ Case = 'Velopack without a header'; Type = 'Velopack'; Pkg = @{ HeaderAvailable = $false } }
        @{ Case = 'Squirrel without any name'; Type = 'Squirrel'; Pkg = @{ Other = 1 } }
        @{ Case = 'Inno Setup without a name'; Type = 'InnoSetup' }
        @{ Case = 'NSIS without a name'; Type = 'NSIS' }
        @{ Case = 'InstallShield without a product code'; Type = 'InstallShield' }
        @{ Case = 'PSADT without a name'; Type = 'PsadtV4' }
        @{ Case = 'BitRock without a name'; Type = 'BitRock' }
        @{ Case = 'Advanced Installer without a product code'; Type = 'AdvancedInstaller' }
        @{ Case = 'MSIX without an identity'; Type = 'Msix' }
        @{ Case = 'an unknown type'; Type = 'Unknown' }
        @{ Case = 'a 7-Zip SFX'; Type = '7zSFX' }
    )
    $script:HintCases = @(
        @{ Type = 'NSIS'; Pkg = @{ UninstallRegistryKey = 'HKLM\...\Acme'; RegistryHive = 'HKCU' }; Hint = '*per-user: evaluate in the user context*' }
        @{ Type = 'NSIS'; Pkg = @{ UninstallRegistryKey = 'HKLM\...\Acme'; RegistryView = '32' }; Hint = '*32-bit registry view*' }
        @{ Type = 'NSIS'; Pkg = @{ UninstallRegistryKey = 'HKLM\...\Acme' }; Hint = 'Registry uninstall key detection: HKLM\...\Acme DisplayVersion' }
        @{ Type = 'NSIS'; Hint = 'Registry uninstall key detection (HKLM\...\Uninstall\Acme Tool) or file-version on the primary EXE' }
        @{ Type = 'InnoSetup'; Hint = '*_is1*' }
        @{ Type = 'InstallShield'; Hint = 'Registry uninstall key detection or file-version on the primary EXE' }
        @{ Type = 'WixBurn'; Hint = '*BundleUpgradeCode*' }
        @{ Type = 'BitRock'; Hint = '*BitRock*' }
        @{ Type = 'Msix'; Pkg = @{ Identity = [pscustomobject]@{ Name = 'Acme.App' } }; Hint = 'MSIX family-name detection via Get-AppxPackage -Name Acme.App' }
        @{ Type = 'Msix'; Hint = 'MSIX family-name detection via Get-AppxPackage' }
        @{ Type = 'MsixBundle'; Pkg = @{ Identity = [pscustomobject]@{ Name = 'Acme.App' } }; Hint = 'MSIX bundle family-name detection via Get-AppxPackage -Name Acme.App' }
        @{ Type = 'MsixBundle'; Hint = 'MSIX bundle family-name detection via Get-AppxPackage' }
        @{ Type = 'Chocolatey'; Pkg = @{ PackageId = 'acme' }; Hint = 'Chocolatey package detection: choco list --local-only acme' }
        @{ Type = 'Chocolatey'; Hint = 'Chocolatey package detection via choco list --local-only' }
        @{ Type = 'NuGet'; Hint = '*nuget list*' }
        @{ Type = 'Intunewin'; Hint = '*Intune portal*' }
        @{ Type = 'PsadtV3'; Hint = '*Deploy-Application.ps1*' }
        @{ Type = 'PsadtV4'; Hint = '*Invoke-AppDeployToolkit.ps1*' }
        @{ Type = 'Squirrel'; Hint = '*HKCU*' }
        @{ Type = 'Velopack'; Hint = '*embedded nuspec id*' }
        @{ Type = '7zSFX'; Hint = 'Not a true installer; detection depends on the extracted payload' }
        @{ Type = 'WinRarSFX'; Hint = 'Not a true installer; detection depends on the extracted payload' }
        @{ Type = 'Unknown'; Hint = 'Pick a file-version or registry-uninstall detection per the extracted payload' }
    )
}

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    Import-AppModule
}

Describe 'Get-UninstallRegistryKey' {
    It 'predicts the key for <Case>' -ForEach $script:KeyCases {
        $arguments = @{ InstallerType = $Type }
        if ($Msi) { $arguments.MsiProperties = $Msi }
        if ($Pkg) { $arguments.PackageMetadata = [pscustomobject]$Pkg }
        if ($Deploy) { $arguments.DeploymentFields = [pscustomobject]$Deploy }
        if ($Arch) { $arguments.MsiArchitecture = $Arch }
        if ($FileArch) { $arguments.FileInfo = [pscustomobject]@{ Architecture = $FileArch } }
        $r = Get-UninstallRegistryKey @arguments
        $r.Path | Should -Be $Path
        $r.Hive | Should -Be $Hive
        $r.Note | Should -BeLike $Note
    }

    It 'returns nothing for <Case>' -ForEach $script:NoKeyCases {
        $arguments = @{ InstallerType = $Type }
        if ($Msi) { $arguments.MsiProperties = $Msi }
        if ($Pkg) { $arguments.PackageMetadata = [pscustomobject]$Pkg }
        Get-UninstallRegistryKey @arguments | Should -BeNullOrEmpty
    }

    It 'takes the architecture of the file when the template is not given' {
        (Get-UninstallRegistryKey -InstallerType 'MSI' -MsiProperties @{ ProductCode = '{PC}' } -FileInfo ([pscustomobject]@{ Architecture = 'x86' })).Path | Should -BeLike '*WOW6432Node*'
    }
}

Describe 'The detection hint of ConvertTo-DeploymentJson' {
    It 'is right for <Type> (<Hint>)' -ForEach $script:HintCases {
        $fi = [pscustomobject]@{ FileName = 'setup.exe'; ProductName = 'Acme Tool'; Architecture = 'x64' }
        $arguments = @{ FileInfo = $fi; InstallerType = $Type }
        if ($Pkg) { $arguments.PackageMetadata = [pscustomobject]$Pkg }
        $json = ConvertTo-DeploymentJson @arguments
        ($json | ConvertFrom-Json).Detection.Hint | Should -BeLike $Hint
    }
}
