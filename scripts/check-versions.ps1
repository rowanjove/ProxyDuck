$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$packageVersion = (Get-Content -LiteralPath (Join-Path $root "package.json") -Raw | ConvertFrom-Json).version
$tauriVersion = (Get-Content -LiteralPath (Join-Path $root "smartflow-ui\src-tauri\tauri.conf.json") -Raw | ConvertFrom-Json).package.version
$manifests = @(
  "proxyduck-common\Cargo.toml",
  "smartflow-core\Cargo.toml",
  "smartflow-cli\Cargo.toml",
  "smartflow-ui\src-tauri\Cargo.toml"
)

$versions = @($packageVersion, $tauriVersion)
foreach ($manifest in $manifests) {
  $content = Get-Content -LiteralPath (Join-Path $root $manifest) -Raw
  $match = [regex]::Match($content, '(?m)^version\s*=\s*"([^"]+)"')
  if (-not $match.Success) { throw "package version missing from $manifest" }
  $versions += $match.Groups[1].Value
}

$different = $versions | Sort-Object -Unique
if ($different.Count -ne 1) {
  throw "version mismatch: $($versions -join ', ')"
}
Write-Host "[ProxyDuck] Version consistency verified: $packageVersion"
