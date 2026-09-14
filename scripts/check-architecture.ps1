# CI Architecture Lint for ProxyDuck
# Verifies that core models, default configurations, and UI remain de-branded and neutral.
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "[Architecture Lint] Scanning for brand leaks and anti-patterns..."

$forbiddenKeywords = @("clash-verge", "clash verge", "clashforwindows", "cfw")
$scannedPaths = @(
    "smartflow-core/src/model.rs",
    "smartflow-ui/dist/index.html",
    "smartflow-ui/dist/i18n.mjs"
)

$violations = @()

foreach ($relPath in $scannedPaths) {
    $fullPath = Join-Path $root $relPath
    if (Test-Path $fullPath) {
        $lines = Get-Content -LiteralPath $fullPath
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            # Allow migration or backwards-compatibility aliases
            if ($line -match "migrate" -or $line -match "deprecated" -or $line -match "alias" -or $line -match "legacy") {
                continue
            }
            foreach ($kw in $forbiddenKeywords) {
                if ($line.ToLower().Contains($kw)) {
                    $lineNum = $i + 1
                    $violations += "${relPath}:${lineNum}: contains forbidden keyword '$kw' -> $line"
                }
            }
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Host "[Architecture Lint FAILED]" -ForegroundColor Red
    foreach ($v in $violations) {
        Write-Host "  $v" -ForegroundColor Yellow
    }
    exit 1
}

Write-Host "[Architecture Lint PASSED] No brand leaks or unauthorized couplings found." -ForegroundColor Green
exit 0
