param(
  [string]$Directory = ".\release\ProxyDuck",
  # Retained for compatibility. The default data plane is now always required.
  [switch]$RequireDataPlane,
  [switch]$RequireSingBox
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$releaseDirectory = (Resolve-Path $Directory).Path

if (-not $releaseDirectory.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Release directory must be inside the workspace: $releaseDirectory"
}

if ($RequireSingBox -and -not (Test-Path -LiteralPath (Join-Path $releaseDirectory "sing-box.exe") -PathType Leaf)) {
  throw "Missing required optional data-plane file: sing-box.exe"
}

$requiredFiles = @(
  "ProxyDuck.exe",
  "proxyduck-core.exe",
  "proxyduck-cli.exe",
  "config.example.json5",
  "README.md",
  "CHANGELOG.md",
  "LICENSE",
  "THIRD_PARTY_NOTICES.md",
  "THIRD_PARTY_SOURCES.md",
  "DEFAULT-RUNTIMES.json",
  "RUNTIME-LOCK.json"
)

foreach ($relativePath in $requiredFiles) {
  $path = Join-Path $releaseDirectory $relativePath
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Missing release file: $path"
  }
  if ((Get-Item -LiteralPath $path).Length -eq 0) {
    throw "Release file is empty: $path"
  }
}

$defaultManifestPath = Join-Path $releaseDirectory "DEFAULT-RUNTIMES.json"
$defaultManifest = Get-Content -LiteralPath $defaultManifestPath -Raw | ConvertFrom-Json
if ($defaultManifest.schemaVersion -ne 1 -or $defaultManifest.architecture -ne "x64") {
  throw "Invalid default runtime manifest: $defaultManifestPath"
}

$defaultRuntimeFiles = @(
  "proxifyre\ProxiFyre.exe",
  "proxifyre\socksify.dll",
  "drivers\Install-WinpkFilter.ps1",
  "drivers\Install-WinpkFilter.cmd",
  ("drivers\" + [string]$defaultManifest.winpkfilter.assetFile)
)
foreach ($license in @($defaultManifest.licenses)) {
  $defaultRuntimeFiles += "licenses\$([string]$license.file)"
}

foreach ($relativePath in $defaultRuntimeFiles) {
  $path = Join-Path $releaseDirectory $relativePath
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Missing required default runtime file: $path"
  }
  if ((Get-Item -LiteralPath $path).Length -eq 0) {
    throw "Default runtime file is empty: $path"
  }
}

$winpkFilterPath = Join-Path $releaseDirectory ("drivers\" + [string]$defaultManifest.winpkfilter.assetFile)
$winpkFilterSize = (Get-Item -LiteralPath $winpkFilterPath).Length
if ($winpkFilterSize -ne [long]$defaultManifest.winpkfilter.assetSize) {
  throw "WinpkFilter MSI size mismatch: $winpkFilterPath"
}
$winpkFilterHash = (Get-FileHash -LiteralPath $winpkFilterPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($winpkFilterHash -ne ([string]$defaultManifest.winpkfilter.sha256).ToLowerInvariant()) {
  throw "WinpkFilter MSI hash mismatch: $winpkFilterPath"
}

foreach ($license in @($defaultManifest.licenses)) {
  $licensePath = Join-Path $releaseDirectory ("licenses\" + [string]$license.file)
  $licenseHash = (Get-FileHash -LiteralPath $licensePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($licenseHash -ne ([string]$license.sha256).ToLowerInvariant()) {
    throw "Default runtime license hash mismatch: $licensePath"
  }
}

$runtimeLockPath = Join-Path $releaseDirectory "RUNTIME-LOCK.json"
$runtimeLock = Get-Content -LiteralPath $runtimeLockPath -Raw | ConvertFrom-Json
if ($runtimeLock.schemaVersion -ne 1 -or $null -eq $runtimeLock.files) {
  throw "Invalid runtime lock manifest: $runtimeLockPath"
}
$releasePrefix = $releaseDirectory.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
foreach ($entry in @($runtimeLock.files)) {
  $candidate = [System.IO.Path]::GetFullPath((Join-Path $releaseDirectory ([string]$entry.path)))
  if (-not $candidate.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Runtime lock contains a path outside the release directory: $($entry.path)"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Runtime lock file is missing: $candidate"
  }
  $actualHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne ([string]$entry.sha256).ToLowerInvariant()) {
    throw "Runtime lock hash mismatch: $candidate"
  }
}

$lockedPaths = @($runtimeLock.files | ForEach-Object { ([string]$_.path).Replace('/', '\') })
foreach ($relativePath in @($defaultRuntimeFiles + @("DEFAULT-RUNTIMES.json", "THIRD_PARTY_SOURCES.md"))) {
  if ($relativePath -notin $lockedPaths) {
    throw "Default runtime file is not protected by RUNTIME-LOCK.json: $relativePath"
  }
}

$coreVersion = & (Join-Path $releaseDirectory "proxyduck-core.exe") --version
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($coreVersion)) {
  throw "proxyduck-core.exe --version failed"
}

$cliVersion = & (Join-Path $releaseDirectory "proxyduck-cli.exe") --version
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($cliVersion)) {
  throw "proxyduck-cli.exe --version failed"
}

Write-Host "[ProxyDuck] Release smoke test passed"
Write-Host "  $coreVersion"
Write-Host "  $cliVersion"
Write-Host "  Default runtimes: ProxiFyre $($defaultManifest.proxifyre.version), WinpkFilter $($defaultManifest.winpkfilter.version)"
Write-Host "  Base files: $($requiredFiles.Count)"
