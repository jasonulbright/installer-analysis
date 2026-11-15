<#
.SYNOPSIS
    Copies the captured guide images over the images that the README shows.

.DESCRIPTION
    readme-images.json maps each README image to the file of docs\images that shows the same view.
    Run the guide capture first, then this script. The script fails when a source image is missing.

.PARAMETER RepoRoot
    The repository folder. The default is the repository that holds this script.

.EXAMPLE
    .\tools\guide-capture\Sync-ReadmeImages.ps1
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
$ErrorActionPreference = 'Stop'
$map = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'readme-images.json') -Raw | ConvertFrom-Json
foreach ($property in $map.PSObject.Properties) {
    $target = Join-Path $RepoRoot ($property.Name -replace '/', '\')
    $source = Join-Path $RepoRoot ($property.Value -replace '/', '\')
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "The source image does not exist: $($property.Value)" }
    Copy-Item -LiteralPath $source -Destination $target -Force
    Write-Verbose ('{0} <- {1}' -f $property.Name, $property.Value)
}