param(
  [string]$ManifestPath = (Join-Path $PSScriptRoot "..\DEFAULT-RUNTIMES.json"),
  [switch]$Quiet,
  [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"

function Write-Status {
  param([string]$Message)
  if (-not $Quiet) {
    Write-Host $Message
  }
}

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

try {
  if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Default runtime manifest was not found: $ManifestPath"
  }
  $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
  if ($manifest.schemaVersion -ne 1 -or $manifest.architecture -ne "x64") {
    throw "Unsupported default runtime manifest: $ManifestPath"
  }

  $msiPath = Join-Path $PSScriptRoot ([string]$manifest.winpkfilter.assetFile)
  if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw "WinpkFilter installer was not found: $msiPath"
  }
  $actualHash = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $expectedHash = ([string]$manifest.winpkfilter.sha256).ToLowerInvariant()
  if ($actualHash -ne $expectedHash) {
    throw "WinpkFilter installer hash mismatch. Expected $expectedHash, got $actualHash"
  }

  if ($VerifyOnly) {
    Write-Status "WinpkFilter installer verification passed."
    return
  }

  if (-not (Test-IsAdministrator)) {
    Write-Status "Requesting administrator access to install WinpkFilter..."
    $powershell = Join-Path $PSHOME "powershell.exe"
    $arguments = @(
      "-NoProfile",
      "-ExecutionPolicy", "Bypass",
      "-File", ('"' + $PSCommandPath + '"'),
      "-ManifestPath", ('"' + $ManifestPath + '"')
    )
    if ($Quiet) {
      $arguments += "-Quiet"
    }
    $elevated = Start-Process -FilePath $powershell -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    exit $elevated.ExitCode
  }

  Write-Status "Installing WinpkFilter $($manifest.winpkfilter.version)..."
  $msiexec = Join-Path $env:SystemRoot "System32\msiexec.exe"
  $process = Start-Process -FilePath $msiexec -ArgumentList @(
    "/i", ('"' + $msiPath + '"'), "/qn", "/norestart"
  ) -Wait -PassThru

  if ($process.ExitCode -notin @(0, 1641, 3010)) {
    throw "WinpkFilter installation failed with Windows Installer exit code $($process.ExitCode)"
  }
  Write-Status "WinpkFilter is installed. A restart may be required if Windows requested one."
  exit 0
} catch {
  [Console]::Error.WriteLine("[ProxyDuck] $($_.Exception.Message)")
  exit 1
}
