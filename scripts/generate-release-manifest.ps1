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
$sourceInput = if ([System.IO.Path]::IsPathRooted($Directory)) { $Directory } else { Join-Path $root $Directory }
$outputInput = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $root $OutputDirectory }
$source = (Resolve-Path -LiteralPath $sourceInput).Path
$output = [System.IO.Path]::GetFullPath($outputInput)
$releaseRoot = [System.IO.Path]::GetFullPath((Join-Path $root "release"))
$releasePrefix = $releaseRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

if (-not $source.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Release source must be inside the workspace release directory: $source"
}
if ($output -ne $releaseRoot -and -not $output.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Release manifest output must be inside the workspace release directory: $output"
}

$buildManifestPath = Join-Path $source ".release-build.json"
if (-not (Test-Path -LiteralPath $buildManifestPath -PathType Leaf)) {
  throw "Build manifest was not found: $buildManifestPath"
}
$build = Get-Content -LiteralPath $buildManifestPath -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($Version)) {
  $Version = [string]$build.version
}
if ($Version -ne [string]$build.version) {
  throw "Release version $Version does not match build manifest version $($build.version)"
}

$portable = Join-Path $output "ProxyDuck-$Version-portable.zip"
$installer = Join-Path $output "installer\ProxyDuck-$Version-setup.exe"
$installerMarker = "$installer.build.json"
if (-not (Test-Path -LiteralPath $portable -PathType Leaf)) {
  throw "Portable artifact was not found: $portable"
}

$installerIsCurrent = $false
if ((Test-Path -LiteralPath $installer -PathType Leaf) -and
    (Test-Path -LiteralPath $installerMarker -PathType Leaf)) {
  $installerProof = Get-Content -LiteralPath $installerMarker -Raw | ConvertFrom-Json
  $installerIsCurrent = $installerProof.schemaVersion -eq 1 -and
    $installerProof.version -eq $Version -and
    $installerProof.buildId -eq $build.buildId -and
    $installerProof.installer -eq (Split-Path -Leaf $installer)
}
if ($RequireInstaller -and -not $installerIsCurrent) {
  throw "A current installer proof is required before generating the release manifest"
}

function Get-SignatureStatus {
  param([Parameter(Mandatory = $true)][string]$Path)
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -eq "Valid") { return "Valid" }
  return [string]$signature.Status
}

function New-Artifact {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Kind
  )
  $item = Get-Item -LiteralPath $Path
  $relative = $item.FullName.Substring($output.Length).TrimStart('\', '/').Replace('\', '/')
  $signatureStatus = if ($Kind -eq "executable") { Get-SignatureStatus -Path $item.FullName } else { "NotApplicable" }
  [ordered]@{
    name = $Name
    kind = $Kind
    path = $relative
    size = $item.Length
    sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    signatureStatus = $signatureStatus
  }
}

$artifacts = [System.Collections.Generic.List[object]]::new()
$artifacts.Add((New-Artifact -Path $portable -Name (Split-Path -Leaf $portable) -Kind "portable"))
if ($installerIsCurrent) {
  $artifacts.Add((New-Artifact -Path $installer -Name (Split-Path -Leaf $installer) -Kind "executable"))
}

$executables = @(Get-ChildItem -LiteralPath $source -Filter *.exe -File | Sort-Object Name | ForEach-Object {
  New-Artifact -Path $_.FullName -Name $_.Name -Kind "executable"
})
if (-not $executables) {
  throw "No release executables were found in $source"
}
$executableStatuses = @(
  @($executables | ForEach-Object { $_.signatureStatus }) +
  @($artifacts | Where-Object { $_.kind -eq "executable" } | ForEach-Object { $_.signatureStatus })
)
$allExecutablesSigned = $executableStatuses.Count -gt 0 -and ($executableStatuses | Where-Object { $_ -ne "Valid" }).Count -eq 0
if ($RequireSignature -and -not $allExecutablesSigned) {
  throw "Release manifest requires valid signatures, but one or more executable artifacts are not signed"
}

$runtimeLock = Join-Path $source "RUNTIME-LOCK.json"
$runtimeLockHash = if (Test-Path -LiteralPath $runtimeLock -PathType Leaf) {
  (Get-FileHash -LiteralPath $runtimeLock -Algorithm SHA256).Hash.ToLowerInvariant()
} else {
  $null
}
$commit = (& git -C $root rev-parse --verify HEAD 2>$null)
if ($LASTEXITCODE -ne 0) { $commit = $null } else { $commit = [string]$commit.Trim() }
$status = @(& git -C $root status --porcelain --untracked-files=all 2>$null)
$sourceDirty = $LASTEXITCODE -eq 0 -and $status.Count -gt 0
if ($RequireCleanSource -and $sourceDirty) {
  throw "Release manifest requires a clean source tree"
}

$manifest = [ordered]@{
  schemaVersion = 1
  product = "ProxyDuck"
  version = $Version
  buildId = [string]$build.buildId
  generatedAt = [DateTime]::UtcNow.ToString("o")
  sourceCommit = $commit
  sourceDirty = [bool]$sourceDirty
  runtimeLockSha256 = $runtimeLockHash
  signatures = [ordered]@{
    required = [bool]$RequireSignature
    executableArtifactsValid = [bool]$allExecutablesSigned
  }
  artifacts = @($artifacts)
  executables = @($executables)
}

$manifestPath = Join-Path $output "release-manifest.json"
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "[ProxyDuck] Release manifest: $manifestPath"
