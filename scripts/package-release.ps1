param(
  [string]$Directory = ".\release\ProxyDuck",
  [string]$OutputDirectory = ".\release",
  [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$source = (Resolve-Path -LiteralPath $Directory).Path
$releaseRoot = [System.IO.Path]::GetFullPath((Join-Path $root "release"))
$releasePrefix = $releaseRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $source.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Package source must be inside the workspace release directory: $source"
}

if ([string]::IsNullOrWhiteSpace($Version)) {
  $Version = (Get-Content -LiteralPath (Join-Path $root "package.json") -Raw | ConvertFrom-Json).version
}
if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
  throw "Invalid package version: $Version"
}

$output = [System.IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
if ($output -ne $releaseRoot -and -not $output.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Package output must be inside the workspace release directory: $output"
}
New-Item -ItemType Directory -Path $output -Force | Out-Null

& (Join-Path $PSScriptRoot "smoke-release.ps1") -Directory $source
if ($LASTEXITCODE -ne 0) { throw "release smoke test failed" }

$archive = Join-Path $output "ProxyDuck-$Version-portable.zip"
if (Test-Path -LiteralPath $archive) {
  Remove-Item -LiteralPath $archive -Force
}
Compress-Archive -LiteralPath $source -DestinationPath $archive -CompressionLevel Optimal

$artifacts = @($archive)
$installerDirectory = Join-Path $releaseRoot "installer"
if (Test-Path -LiteralPath $installerDirectory -PathType Container) {
  $artifacts += Get-ChildItem -LiteralPath $installerDirectory -Filter "ProxyDuck-$Version-setup.exe" -File | Select-Object -ExpandProperty FullName
}
$hashManifest = Join-Path $output "SHA256SUMS.txt"
$hashes = $artifacts | ForEach-Object {
  $hash = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
  "$hash  $([System.IO.Path]::GetFileName($_))"
}
$hashes | Set-Content -LiteralPath $hashManifest -Encoding ascii

Write-Host "[ProxyDuck] Package: $archive"
Write-Host "[ProxyDuck] Hashes:  $hashManifest"
