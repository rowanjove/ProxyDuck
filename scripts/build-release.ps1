param(
  [string]$Bind = "127.0.0.1:46666",
  [switch]$BundleProxifyre,
  [string]$ProxifyreDir = $env:SMARTFLOW_PROXIFYRE_DIR
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")

$vcvars = '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"'
$cargoExe = '"%USERPROFILE%\.cargo\bin\cargo.exe"'
$cmd = "$vcvars && $cargoExe build --release -p smartflow-core -p smartflow-cli -p smartflow-ui"

Write-Host "[SmartFlow] Building release binaries..."
cmd /c $cmd
if ($LASTEXITCODE -ne 0) {
  throw "cargo build failed"
}

$releaseDir = Join-Path $root "release\SmartFlow"
if (Test-Path $releaseDir) {
  Get-ChildItem -Path $releaseDir -Force | Remove-Item -Recurse -Force
} else {
  New-Item -ItemType Directory -Force $releaseDir | Out-Null
}

Copy-Item (Join-Path $root "target\release\smartflow-core.exe") (Join-Path $releaseDir "smartflow-core.exe") -Force
Copy-Item (Join-Path $root "target\release\smartflow-cli.exe") (Join-Path $releaseDir "smartflow-cli.exe") -Force
Copy-Item (Join-Path $root "target\release\smartflow-ui.exe") (Join-Path $releaseDir "smartflow-ui.exe") -Force
Copy-Item (Join-Path $root "smartflow-core\config.example.json5") (Join-Path $releaseDir "config.example.json5") -Force
Copy-Item (Join-Path $root "README.md") (Join-Path $releaseDir "README.md") -Force
Copy-Item (Join-Path $root "CHANGELOG.md") (Join-Path $releaseDir "CHANGELOG.md") -Force
Copy-Item (Join-Path $root "LICENSE") (Join-Path $releaseDir "LICENSE") -Force
Copy-Item (Join-Path $root "THIRD_PARTY_NOTICES.md") (Join-Path $releaseDir "THIRD_PARTY_NOTICES.md") -Force

if ($BundleProxifyre) {
  $candidate = $ProxifyreDir
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $root "third_party\proxifyre\pkg"
  }
  if (!(Test-Path $candidate)) {
    throw "BundleProxifyre was requested but no runtime was found at: $candidate"
  }

  $releaseProxifyre = Join-Path $releaseDir "proxifyre"
  New-Item -ItemType Directory -Force $releaseProxifyre | Out-Null

  Get-ChildItem -Path (Resolve-Path $candidate) -File | Where-Object { $_.Name -ne "app-config.json" } | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $releaseProxifyre $_.Name) -Force
  }

  $upstreamReadme = Join-Path $root "third_party\proxifyre\README_upstream.md"
  if (Test-Path $upstreamReadme) {
    Copy-Item $upstreamReadme (Join-Path $releaseProxifyre "README_upstream.md") -Force
  }

  Write-Host "[SmartFlow] Bundled ProxiFyre runtime into: $releaseProxifyre"
} else {
  Write-Host "[SmartFlow] Skipped ProxiFyre bundle by default."
  Write-Host "[SmartFlow] Set SMARTFLOW_PROXIFYRE_DIR at runtime, place proxifyre next to smartflow-core.exe, or rebuild with -BundleProxifyre after reviewing upstream license terms."
}

Write-Host "[SmartFlow] Build output: $releaseDir"
Write-Host "[SmartFlow] Run core: .\smartflow-core.exe --bind $Bind"
Write-Host "[SmartFlow] Run cli:  .\smartflow-cli.exe status"
Write-Host "[SmartFlow] Run ui:   .\smartflow-ui.exe"
