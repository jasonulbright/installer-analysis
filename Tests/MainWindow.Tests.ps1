#Requires -Modules Pester

<#
.SYNOPSIS
    Pester 5.x tests for the page header after an analysis (script text only, no window is opened).
#>

BeforeAll {
    $script:strScript = Get-Content -LiteralPath (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'start-installeranalysis.ps1') -Raw
}

Describe 'Page header after an analysis' {
    It 'applies the header of the active view after every analysis, so that the start hint does not stay' {
        $script:strScript | Should -Match '(?s)\$currentViewHasData = switch.*?\r?\n\s*Set-ActiveView -View \$\(if \(\$currentViewHasData\) \{ \$script:ActiveView \} else \{ ''Overview'' \}\)'
    }
}
