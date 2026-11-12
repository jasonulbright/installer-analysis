# Sample installers: copies of files that every lab computer has. The capture only reads them.
$samples = Join-Path $appDir 'ui\samples'
New-Item -ItemType Directory $samples -Force | Out-Null
$msi = Get-ChildItem C:\Windows\Installer -Filter *.msi -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 200KB -and $_.Length -lt 3MB } | Select-Object -First 1
if ($msi) { Copy-Item $msi.FullName (Join-Path $samples 'sample-package.msi') }
if (Test-Path 'C:\Windows\ccmsetup\ccmsetup.exe') { Copy-Item 'C:\Windows\ccmsetup\ccmsetup.exe' (Join-Path $samples 'sample-setup.exe') }
$inno = Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' -Recurse -Filter unins000.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if ($inno) { Copy-Item $inno.FullName (Join-Path $samples 'sample-uninstaller.exe') }
Log ('samples: ' + ((Get-ChildItem $samples | ForEach-Object { $_.Name + ' ' + $_.Length }) -join '; '))
$win = Start-App 'start-installeranalysis.ps1' 'Installer Analysis'
Size-Win $win 1440 900
$win = Find-Top 'Installer Analysis' 10
function Rows($grid) { @((Get-El $win $grid).FindAll('Descendants', (New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)))) }
function Analyze([string]$file) {
  Invoke-El (Get-El $win 'btnBrowse'); File-Dialog $file $null
  Start-Sleep -Seconds 3
  $null = Wait-Until { -not (Find-Role $win 'Text' 'Working...') } 5
  Start-Sleep -Seconds 12
}
Section 'first run' {
  Shot $win 'start-first-run'; Dump-Tree $win 'start-first-run'
  Invoke-El (Get-El $win 'btnOptions'); Start-Sleep -Seconds 2
  $d = Find-Last 'Options' 10; Shot $d 'options'; Dump-Tree $d 'options'
  Focus-Win $d; Send-Keys '{ESC}'; Start-Sleep -Seconds 1
}
Section 'analyze msi' {
  Analyze (Join-Path $samples 'sample-package.msi')
  Shot $win 'overview-msi'
  foreach ($v in @(@('Msi', 'view-msi'), @('Payload', 'view-payload'), @('Registry', 'view-registry'), @('Strings', 'view-strings'))) {
    Invoke-El (Get-El $win ('btnView' + $v[0])); Start-Sleep -Seconds 3; Shot $win $v[1]
  }
  # The Files and Embedded buttons show only when the payload lists. Never invoke a hidden button.
  foreach ($n in 'Files', 'Embedded') { $b = Get-El $win ('btnView' + $n) -Quiet; Log ('btnView' + $n + ' shown: ' + ($b -and -not $b.Current.IsOffscreen)) }
}
Section 'analyze exe' {
  Analyze (Join-Path $samples 'sample-setup.exe')
  Invoke-El (Get-El $win 'btnViewOverview'); Start-Sleep -Seconds 2; Shot $win 'overview-exe'
}
Section 'analyze inno' {
  Analyze (Join-Path $samples 'sample-uninstaller.exe')
  Invoke-El (Get-El $win 'btnViewOverview'); Start-Sleep -Seconds 2; Shot $win 'overview-inno'
}
Section 'exports' {
  Invoke-El (Get-El $win 'btnCopySummary'); Start-Sleep -Seconds 1; Shot $win 'copy-summary'
  Invoke-El (Get-El $win 'btnCopyJson'); Start-Sleep -Seconds 1; Shot $win 'copy-json'
  Invoke-El (Get-El $win 'btnExportCsv'); File-Dialog $null $null; Start-Sleep -Seconds 2; Shot $win 'exported-csv'
  Invoke-El (Get-El $win 'btnExportHtml'); File-Dialog $null $null; Start-Sleep -Seconds 2
}
Section 'tab order' { Invoke-El (Get-El $win 'btnViewOverview'); Focus-Win $win; Click-El (Get-El $win 'btnViewOverview'); 1..16 | ForEach-Object { Send-Keys '{TAB}'; $f = [System.Windows.Automation.AutomationElement]::FocusedElement; Log ('tab -> ' + $f.Current.AutomationId + ' / ' + $f.Current.Name) } }
Section 'light' {
  Toggle-El (Get-El $win 'toggleTheme'); Start-Sleep -Seconds 1
  foreach ($v in @(@('Overview', 'light-overview'), @('Msi', 'light-msi'))) { Invoke-El (Get-El $win ('btnView' + $v[0])); Start-Sleep -Seconds 2; Shot $win $v[1] }
  Invoke-El (Get-El $win 'btnOptions'); $d = Find-Last 'Options' 10; Shot $d 'light-options'; Focus-Win $d; Send-Keys '{ESC}'; Start-Sleep -Seconds 1
  Toggle-El (Get-El $win 'toggleTheme')
}
Section 'persist' { Invoke-El (Get-El $win 'btnViewFiles'); Start-Sleep -Milliseconds 600; Invoke-El (Get-El $win 'Close'); Start-Sleep -Seconds 8; $win = Start-App 'start-installeranalysis.ps1' 'Installer Analysis'; Shot $win 'start-reopen' }
Section 'files' {
  New-Item -ItemType Directory "$OutDir\files" -Force | Out-Null
  Get-ChildItem $appDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike '*\Lib\*' -and $_.FullName -notlike '*\Module\*' -and $_.Extension -in '.json', '.log', '.csv', '.html', '.txt' } | ForEach-Object { Log ('file: ' + $_.FullName.Substring($appDir.Length) + ' ' + $_.Length); Copy-Item $_.FullName ("$OutDir\files\" + $_.Name) -Force }
}
Stop-App 'start-installeranalysis.ps1'
