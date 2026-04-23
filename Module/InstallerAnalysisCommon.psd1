@{
    RootModule        = 'InstallerAnalysisCommon.psm1'
    ModuleVersion     = '1.1.0'
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

        # ZIP helpers (used by package-format crackers)
        'Test-IsZipFile'
        'Test-ZipEntryExists'
        'Get-ZipEntryText'
        'Get-ZipRootEntryByPattern'

        # MSI Analysis
        'Get-MsiProperties'
        'Get-MsiSummaryInfo'
        'Test-MsiModuleAvailable'

        # Package-format crackers (v1.1.0)
        'Get-ChocolateyMetadata'
        'Get-IntunewinMetadata'
        'Get-MsixManifest'
        'ConvertFrom-MsixPackageManifest'
        'ConvertFrom-MsixBundleManifest'
        'Get-PsadtMetadata'
        'ConvertFrom-PsadtDeployApplication'
        'Get-ZipEntryPathByPattern'
        'Get-SquirrelMetadata'

        # Deployment Fields
        'Get-DeploymentFields'

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
        'ConvertTo-DeploymentJson'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
}
