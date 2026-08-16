$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Push-Location $root
try {
  & .\scripts\check-versions.ps1
  cargo fmt --all -- --check
  if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed" }
  cargo clippy --workspace --all-targets -- -D warnings
  if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed" }
  cargo test --workspace --all-targets
  if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }
  npm test
  if ($LASTEXITCODE -ne 0) { throw "npm test failed" }
  npm run test:e2e
  if ($LASTEXITCODE -ne 0) { throw "Playwright end-to-end tests failed" }
  npm run check:ui
  if ($LASTEXITCODE -ne 0) { throw "UI syntax check failed" }
} finally {
  Pop-Location
}
