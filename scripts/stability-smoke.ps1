param(
  [double]$DurationHours = 24,
  [int]$PollSeconds = 30,
  [string]$ReleaseDirectory = ".\release\ProxyDuck",
  [int]$Port = 47666
)

$ErrorActionPreference = "Stop"
if ($DurationHours -le 0 -or $DurationHours -gt 168) { throw "DurationHours must be greater than 0 and no more than 168" }
if ($PollSeconds -lt 1 -or $PollSeconds -gt 3600) { throw "PollSeconds must be between 1 and 3600" }
if ($Port -lt 1024 -or $Port -gt 65535) { throw "Port must be between 1024 and 65535" }

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$release = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
$releaseRoot = [System.IO.Path]::GetFullPath((Join-Path $root "release"))
$releasePrefix = $releaseRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $release.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "ReleaseDirectory must be inside the workspace release directory: $release"
}

$core = Join-Path $release "proxyduck-core.exe"
$cli = Join-Path $release "proxyduck-cli.exe"
foreach ($path in @($core, $cli)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing stability-test binary: $path" }
}

$logDirectory = Join-Path $releaseRoot "stability"
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$stamp = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
$logPath = Join-Path $logDirectory "stability-$stamp.jsonl"
$configPath = Join-Path $logDirectory "config-$stamp.json5"
$coreUrl = "http://127.0.0.1:$Port"
$deadline = [DateTime]::UtcNow.AddHours($DurationHours)
$checks = 0
$failures = 0
$process = $null

try {
  $process = Start-Process -FilePath $core -ArgumentList @("--bind", "127.0.0.1:$Port", "--config", $configPath) -WorkingDirectory $release -WindowStyle Hidden -PassThru
  $readyDeadline = [DateTime]::UtcNow.AddSeconds(20)
  do {
    if ($process.HasExited) { throw "core exited during startup with code $($process.ExitCode)" }
    & $cli --core-url $coreUrl --format json status *> $null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Milliseconds 250
  } while ([DateTime]::UtcNow -lt $readyDeadline)
  if ($LASTEXITCODE -ne 0) { throw "core did not become ready within 20 seconds" }

  while ([DateTime]::UtcNow -lt $deadline) {
    $checks += 1
    $statusText = (& $cli --core-url $coreUrl --format json status 2>&1 | Out-String).Trim()
    $healthy = $LASTEXITCODE -eq 0 -and -not $process.HasExited
    if (-not $healthy) { $failures += 1 }
    [ordered]@{
      timestamp = [DateTime]::UtcNow.ToString("o")
      healthy = $healthy
      coreExited = $process.HasExited
      status = $statusText
    } | ConvertTo-Json -Compress | Add-Content -LiteralPath $logPath -Encoding UTF8
    if (-not $healthy) { throw "stability check failed; see $logPath" }
    Start-Sleep -Seconds $PollSeconds
  }
} finally {
  if ($null -ne $process -and -not $process.HasExited) {
    Stop-Process -Id $process.Id -Force
    $process.WaitForExit()
  }
}

Write-Host "[ProxyDuck] Stability smoke passed: $checks checks, $failures failures"
Write-Host "[ProxyDuck] Log: $logPath"
