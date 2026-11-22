#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }

<#
.SYNOPSIS
    Guard (Q-112f): Installer Analysis keeps no per-site data. No source file builds a path in the per-site data layout, and the guide says so.
#>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:Sources = @(Get-ChildItem -LiteralPath $script:Root -Recurse -File |
            Where-Object { $_.Extension -in '.ps1', '.psm1' -and $_.FullName -notmatch '\\(Tests|Lib|tools)\\' })
}

Describe 'Per-site data layout' {
    It 'finds the tool sources' {
        $script:Sources.Count | Should -BeGreaterThan 0
    }

    It 'builds no path below AppPackagerData or sites and never resolves a tool site' {
        foreach ($f in $script:Sources) {
            $text = [IO.File]::ReadAllText($f.FullName)
            $text | Should -Not -Match 'AppPackagerData' -Because $f.Name
            $text | Should -Not -Match 'Resolve-SuiteToolSite|Get-SuiteSiteFolder' -Because $f.Name
        }
    }

    It 'says in the guide that no data is kept per site' {
        $page = [IO.File]::ReadAllText((Join-Path $script:Root 'docs\reference\files-and-logs.md'))
        $page | Should -Match '(?m)^## Sites'
        $page | Should -Match 'keeps no data per ConfigMgr site'
    }

    It 'carries the SuiteCommon site functions of the suite release' {
        (Get-Command -Name Resolve-SuiteToolSite -ErrorAction SilentlyContinue) -or (Select-String -LiteralPath (Join-Path $script:Root 'Lib\SuiteCommon\SuiteCommon.psm1') -Pattern 'function Resolve-SuiteToolSite' -Quiet) | Should -BeTrue
    }
}
