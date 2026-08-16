param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$thirdPartyRoot = [System.IO.Path]::GetFullPath((Join-Path $root "third_party"))
$thirdPartyPrefix = $thirdPartyRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
$manifestPath = Join-Path $thirdPartyRoot "default-runtimes.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

if ($manifest.schemaVersion -ne 1 -or $manifest.architecture -ne "x64") {
  throw "Unsupported default runtime manifest: $manifestPath"
}

function Assert-ThirdPartyPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  $fullPath = [System.IO.Path]::GetFullPath($Path)
  if (-not $fullPath.StartsWith($thirdPartyPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to write outside the third_party cache: $fullPath"
  }
  return $fullPath
}

function Get-LowerSha256 {
  param([Parameter(Mandatory = $true)][string]$Path)

  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-VerifiedDownload {
  param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][string]$Destination,
    [Parameter(Mandatory = $true)][string]$Sha256,
    [long]$ExpectedSize = 0
  )

  $destinationFull = Assert-ThirdPartyPath $Destination
  $destinationDirectory = Split-Path -Parent $destinationFull
  New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null

  if ((-not $Force) -and (Test-Path -LiteralPath $destinationFull -PathType Leaf)) {
    $existingSize = (Get-Item -LiteralPath $destinationFull).Length
    $existingHash = Get-LowerSha256 $destinationFull
    if (($ExpectedSize -le 0 -or $existingSize -eq $ExpectedSize) -and $existingHash -eq $Sha256.ToLowerInvariant()) {
      Write-Host "[ProxyDuck] Reusing verified cache: $destinationFull"
      return $destinationFull
    }
  }

  $temporary = Assert-ThirdPartyPath "$destinationFull.download"
  if (Test-Path -LiteralPath $temporary) {
    Remove-Item -LiteralPath $temporary -Force
  }

  Write-Host "[ProxyDuck] Downloading pinned runtime asset: $Url"
  try {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $temporary
    $downloadedSize = (Get-Item -LiteralPath $temporary).Length
    if ($ExpectedSize -gt 0 -and $downloadedSize -ne $ExpectedSize) {
      throw "Downloaded file size mismatch for $Url (expected $ExpectedSize, got $downloadedSize)"
    }
    $downloadedHash = Get-LowerSha256 $temporary
    if ($downloadedHash -ne $Sha256.ToLowerInvariant()) {
      throw "Downloaded file hash mismatch for $Url (expected $Sha256, got $downloadedHash)"
    }
    Move-Item -LiteralPath $temporary -Destination $destinationFull -Force
  } finally {
    if (Test-Path -LiteralPath $temporary) {
      Remove-Item -LiteralPath $temporary -Force
    }
  }

  return $destinationFull
}

$proxifyreRoot = Assert-ThirdPartyPath (Join-Path $thirdPartyRoot "proxifyre")
$proxifyreArchive = Join-Path $proxifyreRoot "proxifyre.zip"
Get-VerifiedDownload `
  -Url ([string]$manifest.proxifyre.assetUrl) `
  -Destination $proxifyreArchive `
  -Sha256 ([string]$manifest.proxifyre.sha256) `
  -ExpectedSize ([long]$manifest.proxifyre.assetSize) | Out-Null

$proxifyrePackage = Assert-ThirdPartyPath (Join-Path $proxifyreRoot "pkg")
$proxifyreMarker = Join-Path $proxifyrePackage ".asset-sha256"
$markerMatches = (Test-Path -LiteralPath $proxifyreMarker -PathType Leaf) -and
  ((Get-Content -LiteralPath $proxifyreMarker -Raw).Trim() -eq ([string]$manifest.proxifyre.sha256))
$requiredProxifyreFiles = @("ProxiFyre.exe", "socksify.dll")
$packageComplete = $markerMatches
foreach ($requiredFile in $requiredProxifyreFiles) {
  if (-not (Test-Path -LiteralPath (Join-Path $proxifyrePackage $requiredFile) -PathType Leaf)) {
    $packageComplete = $false
  }
}

if ($Force -or -not $packageComplete) {
  $staging = Assert-ThirdPartyPath (Join-Path $proxifyreRoot ("pkg-staging-" + [guid]::NewGuid().ToString("N")))
  New-Item -ItemType Directory -Path $staging -Force | Out-Null
  try {
    Expand-Archive -LiteralPath $proxifyreArchive -DestinationPath $staging -Force
    foreach ($requiredFile in $requiredProxifyreFiles) {
      if (-not (Test-Path -LiteralPath (Join-Path $staging $requiredFile) -PathType Leaf)) {
        throw "Pinned ProxiFyre archive is missing $requiredFile"
      }
    }
    if (Test-Path -LiteralPath $proxifyrePackage) {
      $packageFull = Assert-ThirdPartyPath $proxifyrePackage
      Remove-Item -LiteralPath $packageFull -Recurse -Force
    }
    Move-Item -LiteralPath $staging -Destination $proxifyrePackage
    ([string]$manifest.proxifyre.sha256) | Set-Content -LiteralPath $proxifyreMarker -Encoding ascii
  } finally {
    if (Test-Path -LiteralPath $staging) {
      $stagingFull = Assert-ThirdPartyPath $staging
      Remove-Item -LiteralPath $stagingFull -Recurse -Force
    }
  }
  Write-Host "[ProxyDuck] Extracted verified ProxiFyre $($manifest.proxifyre.version) x64 runtime."
}

$winpkfilterRoot = Assert-ThirdPartyPath (Join-Path $thirdPartyRoot "winpkfilter")
$winpkfilterMsi = Join-Path $winpkfilterRoot ([string]$manifest.winpkfilter.assetFile)
Get-VerifiedDownload `
  -Url ([string]$manifest.winpkfilter.assetUrl) `
  -Destination $winpkfilterMsi `
  -Sha256 ([string]$manifest.winpkfilter.sha256) `
  -ExpectedSize ([long]$manifest.winpkfilter.assetSize) | Out-Null

$licensesRoot = Assert-ThirdPartyPath (Join-Path $thirdPartyRoot "licenses")
foreach ($license in @($manifest.licenses)) {
  Get-VerifiedDownload `
    -Url ([string]$license.url) `
    -Destination (Join-Path $licensesRoot ([string]$license.file)) `
    -Sha256 ([string]$license.sha256) | Out-Null
}

Write-Host "[ProxyDuck] Default runtime cache is ready:"
Write-Host "  ProxiFyre:    $proxifyrePackage"
Write-Host "  WinpkFilter:  $winpkfilterMsi"
Write-Host "  Licenses:     $licensesRoot"
