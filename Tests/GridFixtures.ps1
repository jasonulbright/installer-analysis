# Realistic rows for the grid data tests. The rows come out of the real module functions, which run on a real
# Windows Installer database (New-TestMsi), a real file for the string scan, and a stand-in for 7z.exe that prints a
# listing in the format of 7-Zip. Then the functions of start-installeranalysis.ps1 that fill each grid (cut from its
# syntax tree, as in the other tests) run against plain objects in place of the window controls and give back the
# rows that they put into the grid. No row is written by hand, so a property name that the code stops producing shows
# in the grid tests.
# Call it where Write-Log of the module is mocked and the module is imported.

function New-GridFixture {
    $root = Split-Path -Parent $PSScriptRoot
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'start-installeranalysis.ps1'), [ref]$null, [ref]$null)
    $wanted = 'ConvertTo-FileBrowserIndex', 'Show-FileBrowserFolder', 'ConvertTo-StringsGridRows', 'Show-MsiPropertiesGrid', 'Show-PayloadGrid',
        'Show-EmbeddedGrid', 'Show-StringsGrid', 'Show-RegistryGrid'
    foreach ($n in $wanted) {
        $def = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
        if (-not $def) { throw "function $n not found in the script" }
        . ([scriptblock]::Create($def.Extent.Text))
    }
    # The fill functions name System.Windows.Visibility (PresentationCore); no window is created.
    Add-Type -AssemblyName PresentationCore, WindowsBase
    function Update-SidebarButtonTheme { }

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-grid-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    try {
        # The window controls that the fill functions touch.
        $gridMsi = [pscustomobject]@{ ItemsSource = $null }
        $gridPayload = [pscustomobject]@{ ItemsSource = $null }
        $gridEmbedded = [pscustomobject]@{ ItemsSource = $null }
        $gridStrings = [pscustomobject]@{ ItemsSource = $null }
        $gridRegistry = [pscustomobject]@{ ItemsSource = $null }
        $gridFiles = [pscustomobject]@{ ItemsSource = $null }
        $btnViewEmbedded = [pscustomobject]@{ Visibility = $null; Content = $null }
        $btnViewRegistry = [pscustomobject]@{ Visibility = $null; Content = $null }
        $btnFilesUp = [pscustomobject]@{ IsEnabled = $false }
        $txtFilesFolder = [pscustomobject]@{ Text = '' }
        $txtRegistryNote = [pscustomobject]@{ Text = '' }

        # An MSI: its properties and its registry rows.
        $msi = Join-Path $work 'viewer.msi'
        $null = New-TestMsi -Path $msi -Property ([ordered]@{ ProductName = 'Contoso Viewer'; ProductVersion = '4.2.0'; Manufacturer = 'Contoso Ltd'; ProductCode = '{8F4B5A3E-1C2D-4E5F-9A6B-7C8D9E0F1A2B}' }) `
            -Component @(@{ Name = 'Comp64'; Attributes = 256 }, @{ Name = 'Comp32'; Attributes = 0 }) `
            -Registry @(
            @{ Id = 'r1'; Root = 2; Key = 'SOFTWARE\Contoso\Viewer'; Name = 'Version'; Value = '4.2.0'; Component = 'Comp64' }
            @{ Id = 'r2'; Root = -1; Key = 'SOFTWARE\Contoso\Viewer'; Name = 'Count'; Value = '#5'; Component = 'Comp32' }
        ) `
            -RemoveRegistry @(@{ Id = 'x1'; Root = 1; Key = 'SOFTWARE\Contoso\Old'; Name = '-'; Component = 'Comp32' })
        $script:LastMsiProperties = Get-MsiProperties -MsiPath $msi
        $script:LastRegistry = Get-InstallerRegistrySettings -Path $msi -InstallerType 'MSI'

        # The file listing of 7-Zip, through the stand-in for 7z.exe.
        $listing = Join-Path $work 'listing.txt'
        Set-Content -LiteralPath $listing -Value @(
            '7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov'
            ''
            '   Date      Time    Attr         Size   Compressed  Name'
            '------------------- ----- ------------ ------------  ------------------------'
            '2026-01-02 03:04:05 ....A      2097152      1048576  bin\viewer.dll'
            '2026-01-02 03:04:05 ....A         2048         1024  readme.txt'
            '2026-01-02 03:04:05 D....            0            0  bin'
            '2026-01-03 04:05:06 ....A     52428800     50000000  chain\inner.msi'
            '2026-01-03 04:05:06 ....A      1048576       900000  chain\data1.cab'
            '------------------- ----- ------------ ------------  ------------------------'
            '2026-01-03 04:05:06              55576576     51950000  5 files'
        )
        $fake = New-FakeSevenZip -Directory (Join-Path $work 'tool')
        $installer = Join-Path $work 'setup.exe'
        [System.IO.File]::WriteAllText($installer, 'not a real archive')
        Set-FakeSevenZipBehavior @{ FAKE7Z_STDOUT = $listing }
        try { $script:LastPayload = @(Get-PayloadContents -Path $installer -SevenZipPath $fake) }
        finally { Set-FakeSevenZipBehavior }
        $script:LastEmbedded = Get-EmbeddedInstallers -Payload $script:LastPayload -Type 'WixBurn'

        # A file with strings of the kinds that the scan looks for.
        $binary = Join-Path $work 'setup-strings.bin'
        [System.IO.File]::WriteAllText($binary, "MZ`0`0https://downloads.contoso.com/viewer/setup.exe`0`0{8F4B5A3E-1C2D-4E5F-9A6B-7C8D9E0F1A2B}`0`0HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\Viewer`0`0C:\Program Files\Contoso\Viewer\viewer.exe`0`0Version 4.2.0.1234`0`0")
        $script:LastInterestingStrings = ConvertTo-StringsGridRows -Interesting (Get-InterestingStrings -Path $binary)

        $script:FilesIndex = ConvertTo-FileBrowserIndex -Payload $script:LastPayload
        $null = Show-MsiPropertiesGrid
        $null = Show-PayloadGrid
        $null = Show-EmbeddedGrid
        $null = Show-StringsGrid
        $null = Show-RegistryGrid
        $null = Show-FileBrowserFolder -Folder ''
        @{
            gridMsi      = @($gridMsi.ItemsSource)
            gridPayload  = @($gridPayload.ItemsSource)
            gridEmbedded = @($gridEmbedded.ItemsSource)
            gridStrings  = @($gridStrings.ItemsSource)
            gridRegistry = @($gridRegistry.ItemsSource)
            gridFiles    = @($gridFiles.ItemsSource)
        }
    }
    finally {
        Set-FakeSevenZipBehavior
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Columns that a fixture cannot fill on any row, each with the reason. The grid test accepts only these.
function Get-GridEmptyAllowed {
    @{
        # Only NSIS and Inno Setup rows carry flags. The fixture is an MSI, and the MSI tables have no flags column.
        'gridRegistry.Flags' = 'MSI rows have no flags'
    }
}
