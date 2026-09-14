param(
  [string]$ManifestPath = (Join-Path $PSScriptRoot "..\DEFAULT-RUNTIMES.json"),
  [switch]$Quiet,
  [switch]$VerifyOnly,
  [switch]$Status,
  [switch]$Repair
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

function Get-InstalledWinpkFilter {
  param([string]$ProductCode)
  $roots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )
  Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue |
    Where-Object {
      $_.PSChildName -ieq $ProductCode -or $_.DisplayName -eq "Windows Packet Filter x64"
    } |
    Select-Object -First 1
}

try {
  if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Default runtime manifest was not found: $ManifestPath"
  }
  $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
  if ($manifest.schemaVersion -ne 1 -or $manifest.architecture -ne "x64") {
    throw "Unsupported default runtime manifest: $ManifestPath"
  }
  if ([string]::IsNullOrWhiteSpace([string]$manifest.winpkfilter.productCode)) {
    throw "WinpkFilter product code is missing from the runtime manifest"
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

  if (($Status -and $Repair) -or ($Status -and $VerifyOnly) -or ($Repair -and $VerifyOnly)) {
    throw "-Status, -VerifyOnly, and -Repair are mutually exclusive"
  }

  $installed = Get-InstalledWinpkFilter -ProductCode ([string]$manifest.winpkfilter.productCode)
  if ($Status) {
    $statusPayload = [ordered]@{
      expectedVersion = [string]$manifest.winpkfilter.version
      productCode = [string]$manifest.winpkfilter.productCode
      bundleHashVerified = $true
      installed = $null -ne $installed
      installedVersion = if ($null -ne $installed) { [string]$installed.DisplayVersion } else { $null }
      matchesExpected = $null -ne $installed -and [string]$installed.DisplayVersion -eq [string]$manifest.winpkfilter.version
    }
    if ($Quiet) {
      $statusPayload | ConvertTo-Json -Compress
    } else {
      $statusPayload | ConvertTo-Json -Depth 3
    }
    exit 0
  }

  if ($VerifyOnly) {
    Write-Status "WinpkFilter installer verification passed."
    return
  }

  if ($Repair -and $null -ne $installed -and [string]$installed.DisplayVersion -ne [string]$manifest.winpkfilter.version) {
    throw "Refusing to repair unsupported WinpkFilter version $($installed.DisplayVersion); expected $($manifest.winpkfilter.version)"
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
    if ($Repair) {
      $arguments += "-Repair"
    }
    $elevated = Start-Process -FilePath $powershell -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    exit $elevated.ExitCode
  }

  Write-Status "Installing WinpkFilter $($manifest.winpkfilter.version)..."
  $msiexec = Join-Path $env:SystemRoot "System32\msiexec.exe"
  $installArguments = @("/i", ('"' + $msiPath + '"'), "/qn", "/norestart")
  if ($Repair) {
    $installArguments += @("REINSTALL=ALL", "REINSTALLMODE=vomus")
  }
  $process = Start-Process -FilePath $msiexec -ArgumentList $installArguments -Wait -PassThru

  if ($process.ExitCode -notin @(0, 1641, 3010)) {
    throw "WinpkFilter installation failed with Windows Installer exit code $($process.ExitCode)"
  }
  Write-Status "WinpkFilter is installed. A restart may be required if Windows requested one."
  exit 0
} catch {
  [Console]::Error.WriteLine("[ProxyDuck] $($_.Exception.Message)")
  exit 1
}
