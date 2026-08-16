param(
  [string]$Bind = "127.0.0.1:46666",
  # Kept for compatibility with older build commands. ProxiFyre is now bundled by default.
  [switch]$BundleProxifyre,
  [string]$ProxifyreDir = $(if ($env:PROXYDUCK_PROXIFYRE_DIR) { $env:PROXYDUCK_PROXIFYRE_DIR } elseif ($env:PROXYDOCK_PROXIFYRE_DIR) { $env:PROXYDOCK_PROXIFYRE_DIR } else { $env:SMARTFLOW_PROXIFYRE_DIR }),
  [string]$WinpkFilterMsi = $(if ($env:PROXYDUCK_WINPKFILTER_MSI) { $env:PROXYDUCK_WINPKFILTER_MSI } else { $env:PROXYDOCK_WINPKFILTER_MSI }),
  [switch]$BundleSingBox,
  [string]$SingBoxPath = $(if ($env:PROXYDUCK_SING_BOX_PATH) { $env:PROXYDUCK_SING_BOX_PATH } else { $env:PROXYDOCK_SING_BOX_PATH })
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$runtimeManifestPath = Join-Path $root "third_party\default-runtimes.json"
$runtimeManifest = Get-Content -LiteralPath $runtimeManifestPath -Raw | ConvertFrom-Json

if ($runtimeManifest.schemaVersion -ne 1 -or $runtimeManifest.architecture -ne "x64") {
  throw "Unsupported default runtime manifest: $runtimeManifestPath"
}

if ($BundleProxifyre) {
  Write-Host "[ProxyDuck] -BundleProxifyre is no longer required; ProxiFyre is included by default."
}

& (Join-Path $PSScriptRoot "fetch-default-runtimes.ps1")

Write-Host "[ProxyDuck] Building release binaries..."
cargo build --release -p proxyduck-core -p proxyduck-cli -p proxyduck-ui
if ($LASTEXITCODE -ne 0) {
  throw "cargo build failed"
}

$releaseDir = Join-Path $root "release\ProxyDuck"
$releaseDirFull = [System.IO.Path]::GetFullPath($releaseDir)
$expectedReleaseRoot = [System.IO.Path]::GetFullPath((Join-Path $root "release")) + [System.IO.Path]::DirectorySeparatorChar
if (-not $releaseDirFull.StartsWith($expectedReleaseRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "Refusing to clean release directory outside the workspace release root: $releaseDirFull"
}
if (Test-Path $releaseDir) {
  Get-ChildItem -Path $releaseDir -Force | Remove-Item -Recurse -Force
} else {
  New-Item -ItemType Directory -Force $releaseDir | Out-Null
}

Copy-Item (Join-Path $root "target\release\proxyduck-core.exe") (Join-Path $releaseDir "proxyduck-core.exe") -Force
Copy-Item (Join-Path $root "target\release\proxyduck-cli.exe") (Join-Path $releaseDir "proxyduck-cli.exe") -Force
Copy-Item (Join-Path $root "target\release\proxyduck-ui.exe") (Join-Path $releaseDir "ProxyDuck.exe") -Force
Copy-Item (Join-Path $root "smartflow-core\config.example.json5") (Join-Path $releaseDir "config.example.json5") -Force
Copy-Item (Join-Path $root "README.md") (Join-Path $releaseDir "README.md") -Force
Copy-Item (Join-Path $root "CHANGELOG.md") (Join-Path $releaseDir "CHANGELOG.md") -Force
Copy-Item (Join-Path $root "LICENSE") (Join-Path $releaseDir "LICENSE") -Force
Copy-Item (Join-Path $root "THIRD_PARTY_NOTICES.md") (Join-Path $releaseDir "THIRD_PARTY_NOTICES.md") -Force
Copy-Item (Join-Path $root "THIRD_PARTY_SOURCES.md") (Join-Path $releaseDir "THIRD_PARTY_SOURCES.md") -Force
Copy-Item $runtimeManifestPath (Join-Path $releaseDir "DEFAULT-RUNTIMES.json") -Force

$proxifyreCandidate = $ProxifyreDir
if ([string]::IsNullOrWhiteSpace($proxifyreCandidate)) {
  $proxifyreCandidate = Join-Path $root "third_party\proxifyre\pkg"
}
if (-not (Test-Path -LiteralPath $proxifyreCandidate -PathType Container)) {
  throw "Default ProxiFyre runtime was not found at: $proxifyreCandidate"
}
foreach ($requiredFile in @("ProxiFyre.exe", "socksify.dll")) {
  if (-not (Test-Path -LiteralPath (Join-Path $proxifyreCandidate $requiredFile) -PathType Leaf)) {
    throw "Default ProxiFyre runtime is incomplete; missing $requiredFile in $proxifyreCandidate"
  }
}

$releaseProxifyre = Join-Path $releaseDir "proxifyre"
New-Item -ItemType Directory -Force $releaseProxifyre | Out-Null

Get-ChildItem -LiteralPath (Resolve-Path $proxifyreCandidate) -File | Where-Object {
  $_.Name -notin @("app-config.json", ".asset-sha256")
} | ForEach-Object {
  Copy-Item $_.FullName (Join-Path $releaseProxifyre $_.Name) -Force
}

$upstreamReadme = Join-Path $root "third_party\proxifyre\README_upstream.md"
if (Test-Path -LiteralPath $upstreamReadme -PathType Leaf) {
  Copy-Item $upstreamReadme (Join-Path $releaseProxifyre "README_upstream.md") -Force
}

Write-Host "[ProxyDuck] Bundled ProxiFyre $($runtimeManifest.proxifyre.version) x64 runtime."

$winpkFilterCandidate = $WinpkFilterMsi
if ([string]::IsNullOrWhiteSpace($winpkFilterCandidate)) {
  $winpkFilterCandidate = Join-Path $root ("third_party\winpkfilter\" + [string]$runtimeManifest.winpkfilter.assetFile)
}
if (-not (Test-Path -LiteralPath $winpkFilterCandidate -PathType Leaf)) {
  throw "Default WinpkFilter installer was not found at: $winpkFilterCandidate"
}
$actualWinpkFilterHash = (Get-FileHash -LiteralPath $winpkFilterCandidate -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedWinpkFilterHash = ([string]$runtimeManifest.winpkfilter.sha256).ToLowerInvariant()
if ($actualWinpkFilterHash -ne $expectedWinpkFilterHash) {
  throw "WinpkFilter MSI hash mismatch (expected $expectedWinpkFilterHash, got $actualWinpkFilterHash)"
}

$releaseDrivers = Join-Path $releaseDir "drivers"
New-Item -ItemType Directory -Force $releaseDrivers | Out-Null
Copy-Item -LiteralPath $winpkFilterCandidate -Destination (Join-Path $releaseDrivers ([string]$runtimeManifest.winpkfilter.assetFile)) -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "install-winpkfilter.ps1") -Destination (Join-Path $releaseDrivers "Install-WinpkFilter.ps1") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "Install-WinpkFilter.cmd") -Destination (Join-Path $releaseDrivers "Install-WinpkFilter.cmd") -Force
Write-Host "[ProxyDuck] Bundled WinpkFilter $($runtimeManifest.winpkfilter.version) x64 installer."

$releaseLicenses = Join-Path $releaseDir "licenses"
New-Item -ItemType Directory -Force $releaseLicenses | Out-Null
foreach ($license in @($runtimeManifest.licenses)) {
  $licenseSource = Join-Path $root ("third_party\licenses\" + [string]$license.file)
  if (-not (Test-Path -LiteralPath $licenseSource -PathType Leaf)) {
    throw "Default runtime license was not found: $licenseSource"
  }
  $actualLicenseHash = (Get-FileHash -LiteralPath $licenseSource -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualLicenseHash -ne ([string]$license.sha256).ToLowerInvariant()) {
    throw "License hash mismatch: $licenseSource"
  }
  Copy-Item -LiteralPath $licenseSource -Destination (Join-Path $releaseLicenses ([string]$license.file)) -Force
}

if ($BundleSingBox) {
  $candidate = $SingBoxPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $root "third_party\sing-box\sing-box.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "BundleSingBox was requested but sing-box.exe was not found at: $candidate"
  }
  Copy-Item -LiteralPath (Resolve-Path $candidate) -Destination (Join-Path $releaseDir "sing-box.exe") -Force
  Write-Host "[ProxyDuck] Bundled optional sing-box runtime."
} else {
  Write-Host "[ProxyDuck] Skipped optional sing-box runtime."
  Write-Host "[ProxyDuck] Set PROXYDUCK_SING_BOX_PATH at runtime or rebuild with -BundleSingBox after reviewing its license."
}

$lockedRuntimeFiles = Get-ChildItem -LiteralPath $releaseDir -Recurse -File | Where-Object {
  $relative = $_.FullName.Substring($releaseDirFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar).Length).TrimStart([System.IO.Path]::DirectorySeparatorChar)
  $relative.StartsWith("proxifyre$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase) -or
    $relative.StartsWith("drivers$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase) -or
    $relative.StartsWith("licenses$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase) -or
    $relative.Equals("DEFAULT-RUNTIMES.json", [System.StringComparison]::OrdinalIgnoreCase) -or
    $relative.Equals("THIRD_PARTY_SOURCES.md", [System.StringComparison]::OrdinalIgnoreCase) -or
    $relative.Equals("sing-box.exe", [System.StringComparison]::OrdinalIgnoreCase)
} | Sort-Object FullName | ForEach-Object {
  [ordered]@{
    path = $_.FullName.Substring($releaseDirFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar).Length).TrimStart([System.IO.Path]::DirectorySeparatorChar).Replace('\', '/')
    size = $_.Length
    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}
$runtimeLock = [ordered]@{
  schemaVersion = 1
  generatedAt = [DateTime]::UtcNow.ToString("o")
  files = @($lockedRuntimeFiles)
}
$runtimeLock | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $releaseDir "RUNTIME-LOCK.json") -Encoding UTF8

Write-Host "[ProxyDuck] Build output: $releaseDir"
Write-Host "[ProxyDuck] Run app:  .\ProxyDuck.exe"
Write-Host "[ProxyDuck] Run core: .\proxyduck-core.exe --bind $Bind"
Write-Host "[ProxyDuck] Run cli:  .\proxyduck-cli.exe status"
