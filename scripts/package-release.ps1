param(
  [string]$Directory = ".\release\ProxyDuck",
  [string]$OutputDirectory = ".\release",
  [string]$Version = "",
  [switch]$RequireInstaller,
  [switch]$RequireSignature,
  [switch]$RequireCleanSource
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

$outputInput = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $root $OutputDirectory }
$output = [System.IO.Path]::GetFullPath($outputInput)
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
$installer = Join-Path $installerDirectory "ProxyDuck-$Version-setup.exe"
$buildManifestPath = Join-Path $source ".release-build.json"
$installerMarker = "$installer.build.json"
$installerIsCurrent = $false
if ((Test-Path -LiteralPath $installer -PathType Leaf) -and
    (Test-Path -LiteralPath $installerMarker -PathType Leaf) -and
    (Test-Path -LiteralPath $buildManifestPath -PathType Leaf)) {
  $buildManifest = Get-Content -LiteralPath $buildManifestPath -Raw | ConvertFrom-Json
  $installerManifest = Get-Content -LiteralPath $installerMarker -Raw | ConvertFrom-Json
  $installerIsCurrent = $installerManifest.schemaVersion -eq 1 -and
    $installerManifest.version -eq $Version -and
    $installerManifest.buildId -eq $buildManifest.buildId -and
    $installerManifest.installer -eq (Split-Path -Leaf $installer)
}
if ($installerIsCurrent) {
  $artifacts += $installer
} elseif ($RequireInstaller) {
  throw "A current installer proof is required. Run ISCC and create $installerMarker from $buildManifestPath before packaging."
} elseif (Test-Path -LiteralPath $installer -PathType Leaf) {
  Write-Warning "Skipping installer without a matching current-build proof: $installer"
}

if ($RequireSignature) {
  $signatureTargets = @(Get-ChildItem -LiteralPath $source -Filter *.exe -File)
  if ($installerIsCurrent) {
    $signatureTargets += Get-Item -LiteralPath $installer
  }
  if (-not $signatureTargets) {
    throw "No executable artifacts were found for signature verification"
  }
  foreach ($target in $signatureTargets) {
    $signature = Get-AuthenticodeSignature -LiteralPath $target.FullName
    if ($signature.Status -ne "Valid") {
      throw "A valid Authenticode signature is required for $($target.FullName); got $($signature.Status)"
    }
  }
}

$hashManifest = Join-Path $output "SHA256SUMS.txt"
$hashes = $artifacts | ForEach-Object {
  $hash = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
  $relative = $_.Substring($output.Length).TrimStart('\', '/').Replace('\', '/')
  "$hash  $relative"
}
$hashes | Set-Content -LiteralPath $hashManifest -Encoding ascii

& (Join-Path $PSScriptRoot "generate-release-manifest.ps1") `
  -Directory $Directory `
  -OutputDirectory $OutputDirectory `
  -Version $Version `
  -RequireInstaller:$RequireInstaller `
  -RequireSignature:$RequireSignature `
  -RequireCleanSource:$RequireCleanSource
$manifestHash = (Get-FileHash -LiteralPath (Join-Path $output "release-manifest.json") -Algorithm SHA256).Hash.ToLowerInvariant()
Add-Content -LiteralPath $hashManifest -Value "$manifestHash  release-manifest.json"

& (Join-Path $PSScriptRoot "verify-release-manifest.ps1") `
  -ManifestPath "release\release-manifest.json" `
  -RequireSignature:$RequireSignature `
  -RequireCleanSource:$RequireCleanSource

Write-Host "[ProxyDuck] Package: $archive"
Write-Host "[ProxyDuck] Hashes:  $hashManifest"
