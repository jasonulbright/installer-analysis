#Requires -Modules Pester
# Checks that RELEASING.md asks for by hand: one version in three places, a manifest that
# matches the module, and files that PowerShell 5.1 reads correctly.

BeforeDiscovery {
    $root = Split-Path -Parent $PSScriptRoot
    $script:ScriptFiles = @(
        Get-ChildItem -LiteralPath $root -Filter 'start-*.ps1' -File
        Get-ChildItem -LiteralPath (Join-Path $root 'Module') -File -Recurse | Where-Object { $_.Extension -in '.psm1', '.psd1', '.ps1' }
        Get-ChildItem -LiteralPath (Join-Path $root 'Tests') -Filter '*.ps1' -File -Recurse
        Get-Item -LiteralPath (Join-Path $root 'Invoke-Checks.ps1')
    ) | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
}

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    $script:Manifest = Import-PowerShellDataFile -Path (Join-Path $script:AppRoot 'Module\InstallerAnalysisCommon.psd1')
    $script:ShellText = Get-Content -LiteralPath (Join-Path $script:AppRoot 'start-installeranalysis.ps1') -Encoding UTF8 -TotalCount 60
    $script:Changelog = Get-Content -LiteralPath (Join-Path $script:AppRoot 'CHANGELOG.md') -Encoding UTF8
}

Describe 'Version' {
    It 'has the form YYYY.MM.DD.BBBB with a zero padded build number' {
        $script:Manifest.ModuleVersion | Should -Match '^\d{4}\.\d{2}\.\d{2}\.\d{4}$'
    }

    It 'is the same in the manifest, the script header and the top CHANGELOG heading' {
        $header = ($script:ShellText | Where-Object { $_ -match '^\s*Version\s*:\s*(\S+)\s*$' } | Select-Object -First 1) -replace '^\s*Version\s*:\s*', ''
        $heading = ($script:Changelog | Where-Object { $_ -match '^## \[(\d[^\]]+)\]' } | Select-Object -First 1) -replace '^## \[([^\]]+)\].*$', '$1'
        $header.Trim() | Should -Be $script:Manifest.ModuleVersion
        $heading | Should -Be $script:Manifest.ModuleVersion
    }

    It 'dates the top CHANGELOG entry' {
        ($script:Changelog | Where-Object { $_ -match '^## \[\d' } | Select-Object -First 1) | Should -Match '^## \[[^\]]+\] - \d{4}-\d{2}-\d{2}$'
    }

    It 'lists the changelog headings newest first' {
        $builds = @($script:Changelog | Where-Object { $_ -match '^## \[(\d{4}\.\d{2}\.\d{2}\.\d{4})\]' } | ForEach-Object { [int]($_ -replace '^## \[\d{4}\.\d{2}\.\d{2}\.(\d{4})\].*$', '$1') })
        $builds.Count | Should -BeGreaterThan 3
        for ($i = 1; $i -lt $builds.Count; $i++) { $builds[$i - 1] | Should -BeGreaterThan $builds[$i] }
    }
}

Describe 'Module manifest' {
    It 'loads as a manifest' {
        { Test-ModuleManifest -Path (Join-Path $script:AppRoot 'Module\InstallerAnalysisCommon.psd1') -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exports every public function of the module file and nothing else' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:AppRoot 'Module\InstallerAnalysisCommon.psm1'), [ref]$null, [ref]$null)
        $public = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
                Where-Object { $_.Name -notlike 'script:*' } | ForEach-Object Name | Sort-Object -Unique)
        $exported = @($script:Manifest.FunctionsToExport | Sort-Object -Unique)
        @($public | Where-Object { $exported -notcontains $_ }) | Should -BeNullOrEmpty -Because 'a public function is missing from FunctionsToExport'
        @($exported | Where-Object { $public -notcontains $_ }) | Should -BeNullOrEmpty -Because 'FunctionsToExport names a function that does not exist'
    }

    It 'names each exported function once' {
        @($script:Manifest.FunctionsToExport | Group-Object | Where-Object Count -gt 1) | Should -BeNullOrEmpty
    }
}

Describe 'Source files' {
    It 'parse without errors: <Name>' -ForEach $script:ScriptFiles {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        @($errors) | Should -BeNullOrEmpty
    }

    It 'have a byte order mark when they hold non-ASCII text: <Name>' -ForEach $script:ScriptFiles {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
        $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count -gt 0
        if ($nonAscii) { $hasBom | Should -BeTrue }
    }
}
