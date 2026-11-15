#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Headless guard for the images of the README: each one is a guide image or a byte copy of one, listed in
# tools\guide-capture\readme-images.json. The test opens no window. It reads files and compares bytes.

BeforeDiscovery {
    $root = Split-Path -Parent $PSScriptRoot
    $text = [System.IO.File]::ReadAllText((Join-Path $root 'README.md'))
    $script:ReadmeImages = @([regex]::Matches($text, '!\[[^\]]*\]\(([^)\s]+\.(?:png|gif|jpg))\)') | ForEach-Object { @{ Path = $_.Groups[1].Value } })
    $script:MapEntries = @((Get-Content -LiteralPath (Join-Path $root 'tools\guide-capture\readme-images.json') -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { @{ Target = $_.Name; Source = $_.Value } })
}

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ReadmeImages = @([regex]::Matches([System.IO.File]::ReadAllText((Join-Path $script:Root 'README.md')), '!\[[^\]]*\]\(([^)\s]+\.(?:png|gif|jpg))\)') | ForEach-Object { @{ Path = $_.Groups[1].Value } })
    $script:Map = @{}
    foreach ($p in (Get-Content -LiteralPath (Join-Path $script:Root 'tools\guide-capture\readme-images.json') -Raw | ConvertFrom-Json).PSObject.Properties) { $script:Map[$p.Name] = $p.Value }
}

Describe 'README images' {
    It 'shows at least one image' {
        $script:ReadmeImages.Count | Should -BeGreaterThan 0
    }

    It '<Path> is under docs/images or is listed in readme-images.json' -ForEach $script:ReadmeImages {
        ($Path -like 'docs/images/*' -or $script:Map.ContainsKey($Path)) | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Root ($Path -replace '/', '\')) | Should -BeTrue -Because 'the README image must exist'
    }

    It '<Target> exists, its source <Source> exists, and the two files are identical' -ForEach $script:MapEntries {
        $t = Join-Path $script:Root ($Target -replace '/', '\')
        $s = Join-Path $script:Root ($Source -replace '/', '\')
        Test-Path -LiteralPath $s | Should -BeTrue
        Test-Path -LiteralPath $t | Should -BeTrue
        (Get-FileHash -LiteralPath $t -Algorithm SHA256).Hash | Should -Be (Get-FileHash -LiteralPath $s -Algorithm SHA256).Hash -Because 'run Sync-ReadmeImages.ps1 after a capture'
    }

    It 'lists in readme-images.json only images that the README shows' {
        foreach ($k in $script:Map.Keys) { @($script:ReadmeImages | Where-Object { $_.Path -eq $k }).Count | Should -BeGreaterThan 0 -Because $k }
    }

    It 'keeps the map of the capture script the same as readme-images.json' {
        $path = Join-Path $script:Root 'tools\guide-capture\Invoke-GuideCapture.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $assign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$readmeImages' }, $true)
        $assign | Should -Not -BeNullOrEmpty
        $pairs = @([regex]::Matches($assign.Right.Extent.Text, "'([^']+)'\s*=\s*'([^']+)'") | ForEach-Object { 'screenshots/{0}=docs/images/{1}' -f $_.Groups[1].Value, $_.Groups[2].Value } | Sort-Object)
        $mapped = @($script:Map.Keys | ForEach-Object { '{0}={1}' -f $_, $script:Map[$_] } | Sort-Object)
        $pairs | Should -Be $mapped
    }

    It 'has a Sync-ReadmeImages.ps1 that reads the map' {
        $text = [System.IO.File]::ReadAllText((Join-Path $script:Root 'tools\guide-capture\Sync-ReadmeImages.ps1'))
        $text | Should -Match 'readme-images\.json'
        $text | Should -Match 'RepoRoot'
    }
}