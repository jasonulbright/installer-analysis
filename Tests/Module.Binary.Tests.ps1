#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Readers of binary headers and of MSIX manifests, with well-formed, truncated and hostile input.

BeforeDiscovery {
    $script:MachineCases = @(
        @{ Machine = 0x014C; Expected = 'x86' }
        @{ Machine = 0x8664; Expected = 'x64' }
        @{ Machine = 0xAA64; Expected = 'ARM64' }
        @{ Machine = 0x01C0; Expected = 'ARM' }
        @{ Machine = 0x0200; Expected = 'Unknown (0x0200)' }
    )
}

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    Import-AppModule
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-binary-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    # An MZ header whose offset field at 0x3C points to a PE header with the given machine type.
    function script:New-PeBytes {
        param([uint16]$Machine = 0x8664, [int]$PeOffset = 0x80, [uint32]$Signature = 0x00004550, [int]$Length = 0x200)
        $bytes = New-Object byte[] $Length
        $bytes[0] = 0x4D; $bytes[1] = 0x5A
        [BitConverter]::GetBytes($PeOffset).CopyTo($bytes, 0x3C)
        if ($PeOffset -ge 0 -and $PeOffset + 6 -le $Length) {
            [BitConverter]::GetBytes($Signature).CopyTo($bytes, $PeOffset)
            [BitConverter]::GetBytes($Machine).CopyTo($bytes, $PeOffset + 4)
        }
        return , $bytes
    }
    function script:Write-TestFile {
        param([string]$Name, [byte[]]$Bytes)
        $p = Join-Path $script:Work $Name
        [System.IO.File]::WriteAllBytes($p, $Bytes)
        return $p
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Get-PeArchitecture' {
    It 'names the machine type 0x<Machine> as <Expected>' -ForEach $script:MachineCases {
        $p = Write-TestFile -Name ('pe-' + $Machine + '.exe') -Bytes (New-PeBytes -Machine $Machine)
        Get-PeArchitecture -Path $p | Should -Be $Expected
    }

    It 'says Not a PE for a file without the MZ signature' {
        Get-PeArchitecture -Path (Write-TestFile -Name 'text.exe' -Bytes ([System.Text.Encoding]::ASCII.GetBytes('hello world'))) | Should -Be 'Not a PE'
    }

    It 'says Invalid PE when the PE signature is wrong' {
        Get-PeArchitecture -Path (Write-TestFile -Name 'badsig.exe' -Bytes (New-PeBytes -Signature 0x12345678)) | Should -Be 'Invalid PE'
    }

    It 'says Error for <Case>' -ForEach @(
        @{ Case = 'an empty file'; Bytes = [byte[]]@() }
        @{ Case = 'a file that holds only the MZ signature'; Bytes = [byte[]](0x4D, 0x5A) }
        @{ Case = 'a PE offset beyond the end of the file'; Bytes = $null; Offset = 0x7FFFFFF0 }
        @{ Case = 'a negative PE offset'; Bytes = $null; Offset = -16 }
    ) {
        $path = Join-Path $script:Work ('err-' + [guid]::NewGuid().ToString('N') + '.exe')
        if ($Offset) { [System.IO.File]::WriteAllBytes($path, (New-PeBytes -PeOffset $Offset)) }
        elseif (@($Bytes).Count -eq 0) { [System.IO.File]::WriteAllBytes($path, (New-Object byte[] 0)) }
        else { [System.IO.File]::WriteAllBytes($path, $Bytes) }
        Get-PeArchitecture -Path $path | Should -Be 'Error'
    }

    It 'says Error for a file that does not exist' {
        Get-PeArchitecture -Path (Join-Path $script:Work 'missing.exe') | Should -Be 'Error'
    }

    It 'reads the architecture of a real Windows program' {
        Get-PeArchitecture -Path (Join-Path $env:SystemRoot 'System32\notepad.exe') | Should -BeIn 'x64', 'x86', 'ARM64'
    }
}

Describe 'ConvertFrom-MsixPackageManifest' {
    It 'reads identity, properties and architecture' {
        $xml = '<?xml version="1.0"?><Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Acme.App" Publisher="CN=Acme" Version="1.2.3.4" ProcessorArchitecture="arm64" ResourceId="en-us"/><Properties><DisplayName>Acme App</DisplayName><PublisherDisplayName>Acme Inc</PublisherDisplayName><Description>Desc</Description><Logo>logo.png</Logo><Other>x</Other></Properties></Package>'
        $m = ConvertFrom-MsixPackageManifest -XmlText $xml
        $m.InstallerType | Should -Be 'Msix'
        $m.DisplayName | Should -Be 'Acme App'
        $m.Publisher | Should -Be 'Acme Inc'
        $m.DisplayVersion | Should -Be '1.2.3.4'
        $m.Architecture | Should -Be 'arm64'
        $m.Identity.ResourceId | Should -Be 'en-us'
        $m.PropertiesDescription | Should -Be 'Desc'
        $m.PropertiesLogo | Should -Be 'logo.png'
    }

    It 'falls back to the identity name, publisher and the Neutral architecture' {
        $xml = '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Acme.App" Publisher="CN=Acme" Version="1.0.0.0"/></Package>'
        $m = ConvertFrom-MsixPackageManifest -XmlText $xml
        $m.DisplayName | Should -Be 'Acme.App'
        $m.Publisher | Should -Be 'CN=Acme'
        $m.Architecture | Should -Be 'Neutral'
    }

    It 'reads a manifest without a namespace and one with a byte order mark' {
        (ConvertFrom-MsixPackageManifest -XmlText '<Package><Identity Name="NoNs" Publisher="CN=X" Version="1.0.0.0"/><Properties><DisplayName>No Ns</DisplayName></Properties></Package>').DisplayName | Should -Be 'No Ns'
        (ConvertFrom-MsixPackageManifest -XmlText ([string][char]0xFEFF + '<Package><Identity Name="Bom" Publisher="CN=X" Version="1"/></Package>')).DisplayName | Should -Be 'Bom'
    }

    It 'reads a package without an Identity element' {
        $m = ConvertFrom-MsixPackageManifest -XmlText '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"/>'
        $m.Architecture | Should -Be 'Neutral'
        @($m.Identity.Keys).Count | Should -Be 0
    }

    It 'returns nothing for <Case>' -ForEach @(
        @{ Case = 'text that is not XML'; Xml = '<Package' }
        @{ Case = 'XML with another root'; Xml = '<Other/>' }
    ) {
        ConvertFrom-MsixPackageManifest -XmlText $Xml | Should -BeNullOrEmpty
    }

    It 'does not expand an external entity in the manifest' {
        $secret = Join-Path $script:Work 'secret.txt'
        [System.IO.File]::WriteAllText($secret, 'TOP-SECRET-CONTENT')
        $uri = ([System.Uri]$secret).AbsoluteUri
        $xml = "<?xml version=`"1.0`"?><!DOCTYPE Package [<!ENTITY xxe SYSTEM `"$uri`">]><Package><Identity Name=`"&xxe;`" Publisher=`"CN=X`" Version=`"1`"/><Properties><DisplayName>&xxe;</DisplayName></Properties></Package>"
        $m = ConvertFrom-MsixPackageManifest -XmlText $xml
        if ($m) { ($m | ConvertTo-Json -Depth 5) | Should -Not -BeLike '*TOP-SECRET-CONTENT*' }
    }
}

Describe 'ConvertFrom-MsixBundleManifest' {
    It 'reads the identity and every bundled package' {
        $xml = '<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Acme.Bundle" Publisher="CN=Acme" Version="9.0.0.0"/><Packages><Package Type="application" Version="9.0.0.0" Architecture="x64" FileName="a.x64.msix"/><Package Type="application" Version="9.0.0.0" Architecture="arm64" FileName="a.arm64.msix"/><Package Type="resource" Version="9.0.0.0" ResourceId="en" FileName="a.en.msix"/></Packages></Bundle>'
        $m = ConvertFrom-MsixBundleManifest -XmlText $xml
        $m.InstallerType | Should -Be 'MsixBundle'
        $m.DisplayName | Should -Be 'Acme.Bundle'
        $m.Architecture | Should -Be 'arm64, x64'
        @($m.BundledPackages).Count | Should -Be 3
        ($m.BundledPackages | Where-Object ResourceId -eq 'en').FileName | Should -Be 'a.en.msix'
    }

    It 'reads a bundle without namespace and says Bundle when no package names an architecture' {
        $m = ConvertFrom-MsixBundleManifest -XmlText ([string][char]0xFEFF + '<Bundle><Identity Name="N" Publisher="P" Version="1"/><Packages><Package Type="resource" FileName="r.msix"/></Packages></Bundle>')
        $m.Architecture | Should -Be 'Bundle'
        @($m.BundledPackages).Count | Should -Be 1
    }

    It 'reads a bundle without packages and without identity' {
        $m = ConvertFrom-MsixBundleManifest -XmlText '<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"/>'
        @($m.BundledPackages).Count | Should -Be 0
        @($m.Identity.Keys).Count | Should -Be 0
    }

    It 'returns nothing for <Case>' -ForEach @(
        @{ Case = 'text that is not XML'; Xml = 'no xml' }
        @{ Case = 'XML with another root'; Xml = '<Other/>' }
    ) {
        ConvertFrom-MsixBundleManifest -XmlText $Xml | Should -BeNullOrEmpty
    }
}

Describe 'Get-MsixManifest' {
    It 'returns nothing for a zip with neither manifest' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $p = Join-Path $script:Work 'empty.msix'
        $a = [System.IO.Compression.ZipFile]::Open($p, 'Create'); $e = $a.CreateEntry('readme.txt'); $s = $e.Open(); $s.WriteByte(65); $s.Dispose(); $a.Dispose()
        Get-MsixManifest -Path $p | Should -BeNullOrEmpty
    }

    It 'returns nothing for a file that is not a zip' {
        Get-MsixManifest -Path (Write-TestFile -Name 'notzip.msix' -Bytes ([byte[]](1, 2, 3, 4, 5))) | Should -BeNullOrEmpty
    }
}
