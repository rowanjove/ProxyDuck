param(
  [string]$Bind = "127.0.0.1:46666"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")

$core = Join-Path $root "target\release\proxyduck-core.exe"
$ui = Join-Path $root "target\release\proxyduck-ui.exe"

if (!(Test-Path $core) -or !(Test-Path $ui)) {
  Write-Host "Release binaries not found. Run .\scripts\build-release.ps1 first."
  exit 1
}

Write-Host "Starting proxyduck-core on $Bind"
Start-Process -FilePath $core -ArgumentList "--bind", $Bind -WindowStyle Hidden

Start-Sleep -Seconds 2

Write-Host "Starting ProxyDuck"
Start-Process -FilePath $ui
