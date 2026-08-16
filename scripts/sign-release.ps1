param(
  [Parameter(Mandatory = $true)]
  [string]$Directory
)

$ErrorActionPreference = "Stop"
$resolvedDirectory = (Resolve-Path -LiteralPath $Directory).Path
$certificateBase64 = if ($env:PROXYDUCK_SIGNING_PFX_BASE64) { $env:PROXYDUCK_SIGNING_PFX_BASE64 } else { $env:PROXYDOCK_SIGNING_PFX_BASE64 }
$certificatePassword = if ($env:PROXYDUCK_SIGNING_PFX_PASSWORD) { $env:PROXYDUCK_SIGNING_PFX_PASSWORD } else { $env:PROXYDOCK_SIGNING_PFX_PASSWORD }

if ([string]::IsNullOrWhiteSpace($certificateBase64)) {
  Write-Host "[ProxyDuck] Signing certificate is not configured; binaries remain unsigned."
  exit 0
}
if ([string]::IsNullOrWhiteSpace($certificatePassword)) {
  throw "PROXYDUCK_SIGNING_PFX_PASSWORD is required when signing is enabled"
}

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter signtool.exe -Recurse |
  Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
  Sort-Object FullName -Descending |
  Select-Object -First 1
if (-not $signtool) { throw "signtool.exe was not found" }

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("proxyduck-sign-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
$certificatePath = Join-Path $temporaryDirectory "certificate.pfx"
try {
  [IO.File]::WriteAllBytes($certificatePath, [Convert]::FromBase64String($certificateBase64))
  $binaries = Get-ChildItem -LiteralPath $resolvedDirectory -Filter *.exe -File
  if (-not $binaries) { throw "no release binaries found in $resolvedDirectory" }
  foreach ($binary in $binaries) {
    & $signtool.FullName sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f $certificatePath /p $certificatePassword $binary.FullName
    if ($LASTEXITCODE -ne 0) { throw "failed to sign $($binary.FullName)" }
  }
} finally {
  Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
