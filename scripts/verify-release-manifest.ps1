param(
  [string]$ManifestPath = ".\release\release-manifest.json",
  [switch]$RequireSignature,
  [switch]$RequireCleanSource
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$manifestInput = if ([System.IO.Path]::IsPathRooted($ManifestPath)) { $ManifestPath } else { Join-Path $root $ManifestPath }
$manifestFile = (Resolve-Path -LiteralPath $manifestInput).Path
$releaseRoot = [System.IO.Path]::GetFullPath((Join-Path $root "release"))
$releasePrefix = $releaseRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
$manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json

if ($manifest.schemaVersion -ne 1 -or $manifest.product -ne "ProxyDuck") {
  throw "Unsupported release manifest: $manifestFile"
}
if ([string]::IsNullOrWhiteSpace([string]$manifest.buildId)) {
  throw "Release manifest buildId is missing"
}
if ($RequireCleanSource -and $manifest.sourceDirty) {
  throw "Release manifest was generated from a dirty source tree"
}
if ($RequireSignature -and -not $manifest.signatures.executableArtifactsValid) {
  throw "Release manifest does not prove valid executable signatures"
}

function Resolve-ManifestArtifact {
  param([Parameter(Mandatory = $true)]$Artifact)

  $relative = [string]$Artifact.path
  if ([string]::IsNullOrWhiteSpace($relative) -or [System.IO.Path]::IsPathRooted($relative)) {
    throw "Release manifest artifact path must be a non-empty relative path: $relative"
  }
  $segments = $relative -split '[\\/]'
  if (($segments | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
    throw "Release manifest artifact path contains an unsafe segment: $relative"
  }
  if ([string]$Artifact.kind -notin @('portable', 'executable')) {
    throw "Release manifest contains an unsupported artifact kind '$($Artifact.kind)' for $relative"
  }
  if ([string]$Artifact.sha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw "Release manifest hash is not a SHA-256 value for $relative"
  }
  if ([int64]$Artifact.size -lt 0) {
    throw "Release manifest artifact size is negative for $relative"
  }
  $candidate = [System.IO.Path]::GetFullPath((Join-Path $releaseRoot $relative))
  if (-not $candidate.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Release manifest points outside the release directory: $relative"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release manifest artifact is missing: $relative"
  }
  $item = Get-Item -LiteralPath $candidate
  if ([int64]$artifact.size -ne $item.Length) {
    throw "Release manifest size mismatch for $relative"
  }
  $actualHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne ([string]$artifact.sha256).ToLowerInvariant()) {
    throw "Release manifest hash mismatch for $relative"
  }
  if ($RequireSignature -and $artifact.kind -eq "executable") {
    $signature = Get-AuthenticodeSignature -LiteralPath $candidate
    if ($signature.Status -ne "Valid") {
      throw "Release executable is not Authenticode-valid: $relative ($($signature.Status))"
    }
  }
  return $candidate
}

$seenPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$manifestArtifacts = @($manifest.artifacts) + @($manifest.executables)
if ($manifestArtifacts.Count -eq 0) {
  throw "Release manifest contains no artifacts"
}
foreach ($artifact in $manifestArtifacts) {
  if ($null -eq $artifact) {
    throw "Release manifest contains a null artifact entry"
  }
  $candidate = Resolve-ManifestArtifact -Artifact $artifact
  if (-not $seenPaths.Add($candidate)) {
    throw "Release manifest contains duplicate artifact path: $($artifact.path)"
  }
}

$source = Join-Path $releaseRoot "ProxyDuck"
$runtimeLock = Join-Path $source "RUNTIME-LOCK.json"
if ($manifest.runtimeLockSha256) {
  if (-not (Test-Path -LiteralPath $runtimeLock -PathType Leaf)) {
    throw "RUNTIME-LOCK.json is missing but the manifest contains a runtime lock hash"
  }
  $actualRuntimeHash = (Get-FileHash -LiteralPath $runtimeLock -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualRuntimeHash -ne ([string]$manifest.runtimeLockSha256).ToLowerInvariant()) {
    throw "RUNTIME-LOCK.json hash does not match the release manifest"
  }
}

Write-Host "[ProxyDuck] Release manifest verified: buildId=$($manifest.buildId)"
