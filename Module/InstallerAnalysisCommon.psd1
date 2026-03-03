@{
    RootModule        = 'InstallerAnalysisCommon.psm1'
    ModuleVersion     = '1.0.1'
    GUID              = 'c3d4e5f6-a7b8-9012-cdef-456789012345'
    Author            = 'Jason Ulbright'
    Description       = 'Installer analysis tool - version intelligence, installer type detection, silent switches, payload extraction.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        # Logging
        'Initialize-Logging'
        'Write-Log'

        # File Identification
        'Get-InstallerFileInfo'
        'Get-InstallerType'
        'Get-PeArchitecture'

        # MSI Analysis
        'Get-MsiProperties'
        'Get-MsiSummaryInfo'
        'Test-MsiModuleAvailable'

        # Silent Switches
        'Get-SilentSwitchDatabase'
        'Get-SilentSwitches'

        # Payload Extraction
        'Find-7ZipPath'
        'Get-PayloadContents'
        'Expand-InstallerPayload'

        # String Analysis
        'Get-BinaryStrings'
        'Get-InterestingStrings'

        # Export
        'Export-AnalysisReport'
        'Export-AnalysisHtml'
        'New-AnalysisSummaryText'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
}
