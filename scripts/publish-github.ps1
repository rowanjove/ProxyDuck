param(
  [Parameter(Mandatory = $true)]
  [string]$Repo,

  [ValidateSet("public", "private")]
  [string]$Visibility = "public",

  [string]$Tag = "",

  [string]$AssetPath = "",

  [string]$NotesPath = "CHANGELOG.md",

  [switch]$SkipAsset
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$rootPath = $root.Path
$asset = $null
$notesFile = $null

function Invoke-External {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [string[]]$Arguments = @(),

    [switch]$CaptureOutput
  )

  if ($CaptureOutput) {
    $output = & $FilePath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
      $detail = ($output | Out-String).Trim()
      throw "$FilePath failed with exit code $LASTEXITCODE`n$detail"
    }
    return ($output | Out-String).Trim()
  }

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath failed with exit code $LASTEXITCODE"
  }
}

function Resolve-ReleaseAsset {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseTag,

    [string]$RequestedAssetPath = "",

    [switch]$SkipBinaryAsset
  )

  if ($SkipBinaryAsset) {
    return $null
  }

  if (-not [string]::IsNullOrWhiteSpace($RequestedAssetPath)) {
    $candidate = if ([System.IO.Path]::IsPathRooted($RequestedAssetPath)) {
      $RequestedAssetPath
    } else {
      Join-Path $RootPath $RequestedAssetPath
    }

    if (!(Test-Path -LiteralPath $candidate)) {
      throw "Release asset not found: $candidate"
    }

    return (Resolve-Path -LiteralPath $candidate).Path
  }

  $packageDir = Join-Path $RootPath "release\SmartFlow"
  if (!(Test-Path -LiteralPath $packageDir)) {
    throw "No release asset was provided and default package directory was not found: $packageDir. Run .\scripts\build-release.ps1 first, pass -AssetPath, or use -SkipAsset."
  }

  $archivePath = Join-Path (Join-Path $RootPath "release") "SmartFlow-$ReleaseTag.zip"
  if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
  }

  Write-Host "[SmartFlow] Packaging release asset: $archivePath"
  Compress-Archive -Path $packageDir -DestinationPath $archivePath -CompressionLevel Optimal -Force

  return $archivePath
}

function Resolve-ReleaseNotesFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [string]$RequestedNotesPath = ""
  )

  if ([string]::IsNullOrWhiteSpace($RequestedNotesPath)) {
    return $null
  }

  $candidate = if ([System.IO.Path]::IsPathRooted($RequestedNotesPath)) {
    $RequestedNotesPath
  } else {
    Join-Path $RootPath $RequestedNotesPath
  }

  if (!(Test-Path -LiteralPath $candidate)) {
    Write-Host "[SmartFlow] Release notes file not found, falling back to generated notes: $candidate"
    return $null
  }

  return (Resolve-Path -LiteralPath $candidate).Path
}

function Resolve-ProjectVersion {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath
  )

  $tauriConfig = Join-Path $RootPath "smartflow-ui\src-tauri\tauri.conf.json"
  if (!(Test-Path -LiteralPath $tauriConfig)) {
    throw "Project version source not found: $tauriConfig"
  }

  $config = Get-Content -LiteralPath $tauriConfig -Raw | ConvertFrom-Json
  $version = $config.package.version
  if ([string]::IsNullOrWhiteSpace($version)) {
    throw "Project version is missing from $tauriConfig"
  }

  return $version.Trim()
}

Invoke-External gh @("auth", "status", "-h", "github.com")

$originUrl = ""
if ((& git -C $rootPath remote get-url origin 2>$null)) {
  if ($LASTEXITCODE -eq 0) {
    $originUrl = (& git -C $rootPath remote get-url origin).Trim()
  }
}

if ([string]::IsNullOrWhiteSpace($originUrl)) {
  Write-Host "[SmartFlow] Creating GitHub repo $Repo ($Visibility) and pushing source..."
  Invoke-External gh @(
    "repo",
    "create",
    $Repo,
    "--$Visibility",
    "--source",
    $rootPath,
    "--remote",
    "origin",
    "--push"
  )
} else {
  Write-Host "[SmartFlow] Pushing source to existing origin..."
  Invoke-External git @("-C", $rootPath, "push", "-u", "origin", "HEAD")
}

if ([string]::IsNullOrWhiteSpace($Tag)) {
  $Tag = "v$(Resolve-ProjectVersion -RootPath $rootPath)"
}

$asset = Resolve-ReleaseAsset -RootPath $rootPath -ReleaseTag $Tag -RequestedAssetPath $AssetPath -SkipBinaryAsset:$SkipAsset
$notesFile = Resolve-ReleaseNotesFile -RootPath $rootPath -RequestedNotesPath $NotesPath

$tagExists = Invoke-External git @("-C", $rootPath, "tag", "-l", $Tag) -CaptureOutput
if ([string]::IsNullOrWhiteSpace($tagExists)) {
  Invoke-External git @("-C", $rootPath, "tag", "-a", $Tag, "-m", "SmartFlow release $Tag")
}

Invoke-External git @("-C", $rootPath, "push", "origin", $Tag)

if ($asset) {
  Write-Host "[SmartFlow] Creating GitHub release $Tag with asset: $asset"
  $arguments = @(
    "release",
    "create",
    $Tag,
    $asset,
    "--title",
    "SmartFlow $Tag"
  )
  if ($notesFile) {
    $arguments += @("--notes-file", $notesFile)
  } else {
    $arguments += @("--notes", "Automated release.")
  }
  Invoke-External -FilePath gh -Arguments $arguments
} else {
  Write-Host "[SmartFlow] Creating GitHub release $Tag without a binary asset"
  $arguments = @(
    "release",
    "create",
    $Tag,
    "--title",
    "SmartFlow $Tag"
  )
  if ($notesFile) {
    $arguments += @("--notes-file", $notesFile)
  } else {
    $arguments += @("--notes", "Automated release.")
  }
  Invoke-External -FilePath gh -Arguments $arguments
}

Write-Host "[SmartFlow] Done."
