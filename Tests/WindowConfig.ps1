# App-specific names for Window.Tests.ps1.
#
# The views of Installer Analysis are panels in one grid. The window shows an
# empty result when it starts, so PopulateScript fills the grids with sample rows
# and shows the sidebar buttons that the script keeps hidden until a file has
# data. The text is then measured with content in it, as a user sees it.
$script:AppConfig = @{
    Title          = 'Installer Analysis'
    Shell          = 'start-installeranalysis.ps1'
    Xaml           = 'MainWindow.xaml'
    OptionsButton  = 'btnOptions'
    LogLabel       = 'lblLogOutput'
    ActiveMode     = 'Border'
    Views          = @(
        @{ Name = 'Overview';          Container = 'txtOverview';   Button = 'btnViewOverview' }
        @{ Name = 'MSI Properties';    Container = 'gridMsi';       Button = 'btnViewMsi' }
        @{ Name = 'Payload';           Container = 'gridPayload';   Button = 'btnViewPayload' }
        @{ Name = 'File Browser';      Container = 'panelFiles';    Button = 'btnViewFiles' }
        @{ Name = 'Inner Installers';  Container = 'panelEmbedded'; Button = 'btnViewEmbedded' }
        @{ Name = 'Registry Settings'; Container = 'panelRegistry'; Button = 'btnViewRegistry' }
        @{ Name = 'Strings';           Container = 'panelStrings';  Button = 'btnViewStrings' }
    )
    # Script text (not a script block): it runs inside the STA runspace.
    PopulateScript = @'
param($w)
foreach ($b in 'btnViewFiles', 'btnViewEmbedded', 'btnViewRegistry') { $w.FindName($b).Visibility = 'Visible' }
$w.FindName('btnViewFiles').Content = 'File Browser (12)'
$w.FindName('btnViewEmbedded').Content = 'Inner Installers (3)'
$w.FindName('btnViewRegistry').Content = 'Registry Settings (8)'
$w.FindName('actionBar').Visibility = 'Visible'
$w.FindName('txtFilePath').Text = 'C:\Installers\Vendor\Product-Setup-12.4.1.0-x64.msi'
$w.FindName('txtOverview').Text = (1..30 | ForEach-Object { 'Line {0}: Product name, version, publisher and silent switch text' -f $_ }) -join "`r`n"
$w.FindName('gridMsi').ItemsSource = @(1..6 | ForEach-Object { [pscustomobject]@{ Property = "ProductProperty$_"; Value = 'Value text for the property' } })
$w.FindName('gridPayload').ItemsSource = @(1..6 | ForEach-Object { [pscustomobject]@{ Name = "bin\file$_.dll"; Size = '1.2 MB'; DateTime = '2026-01-02 03:04' } })
$w.FindName('gridEmbedded').ItemsSource = @(1..3 | ForEach-Object { [pscustomobject]@{ Name = "inner$_.msi"; Kind = 'MSI'; SizeFormatted = '4.5 MB'; Description = 'Inner installer' } })
$w.FindName('gridFiles').ItemsSource = @(1..6 | ForEach-Object { [pscustomobject]@{ Name = "file$_.txt"; Kind = 'File'; Size = '3 KB'; DateTime = '2026-01-02 03:04' } })
$w.FindName('gridRegistry').ItemsSource = @(1..6 | ForEach-Object { [pscustomobject]@{ Root = 'HKLM'; Key = 'SOFTWARE\Vendor\Product'; Name = "Setting$_"; Type = 'REG_SZ'; Value = 'value'; Action = 'Set'; Flags = ''; View = '64-bit'; Section = 'Registry'; Source = 'Installer' } })
$w.FindName('gridStrings').ItemsSource = @(1..6 | ForEach-Object { [pscustomobject]@{ Category = 'URLs'; Value = "https://example.test/path/$_" } })
$w.FindName('txtStatus').Text = 'Analyzed: Product 12.4.1  [MSI]'
$w.FindName('txtLog').Text = '23:59:59  Analyzed type=MSI'
'@
}
