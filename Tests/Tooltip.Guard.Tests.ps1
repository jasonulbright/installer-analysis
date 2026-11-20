#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }

<#
.SYNOPSIS
    Pester 5.x source guard for tooltips (no window is opened, no ConfigMgr site is needed).
    Every control in the audited list of MainWindow.xaml has a ToolTip that is not empty, is ASCII, ends in a period
    and is at most 200 characters long. Windows PowerShell 5.1 and PowerShell 7.
#>

BeforeDiscovery {
    $script:AuditedName = @(
        'toggleTheme',
        'btnViewOverview', 'btnViewMsi', 'btnViewPayload', 'btnViewFiles', 'btnViewEmbedded', 'btnViewRegistry', 'btnViewStrings', 'btnOptions',
        'btnBreadcrumbBack',
        'txtFilePath', 'btnBrowse',
        'btnCopySummary', 'btnCopyJson', 'btnExportCsv', 'btnExportHtml', 'btnExtractAll',
        'btnExtractAllInner', 'btnAnalyzeSelectedInner', 'btnOpenInNewWindow',
        'btnFilesUp', 'btnFilesExtractSelected', 'btnFilesExtractFolder', 'txtFilesFilter', 'treeFiles',
        'btnRegistryCopyAll', 'txtRegistryFilter',
        'txtStringsFilter'
    )
    $script:AuditedCase = @($script:AuditedName | ForEach-Object { @{ Name = $_ } })
}

BeforeAll {
    $script:Root = Split-Path -Path $PSScriptRoot -Parent
    $script:KeyNamespace = 'http://schemas.microsoft.com/winfx/2006/xaml'
    [xml]$script:Xaml = Get-Content -LiteralPath (Join-Path $script:Root 'MainWindow.xaml') -Raw
    $script:Node = @{}
    foreach ($n in $script:Xaml.SelectNodes('//*')) {
        $name = $n.GetAttribute('Name', $script:KeyNamespace)
        if ($name) { $script:Node[$name] = $n }
    }
}

Describe 'Tooltips of MainWindow.xaml' {
    It 'finds the control <Name>' -ForEach $script:AuditedCase {
        $script:Node.ContainsKey($Name) | Should -BeTrue
    }

    It 'gives <Name> a complete ToolTip' -ForEach $script:AuditedCase {
        $tip = $script:Node[$Name].GetAttribute('ToolTip')
        $tip | Should -Not -BeNullOrEmpty
        $tip | Should -Match '^[\x20-\x7E]+$' -Because 'the tooltip is ASCII text'
        $tip | Should -Match '[.]$' -Because 'the tooltip is a sentence that ends in a period'
        $tip.Length | Should -BeLessOrEqual 200
    }
}
