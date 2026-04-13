# Changelog

All notable changes to SmartFlow will be documented in this file.

The project is open source under the MIT License.

## 0.2.0 - 2026-04-13

### Added

- Added `smartflow-cli` for local automation and headless management of the SmartFlow core API.
- Added CLI commands for status, config, runtime toggles, engine mode, logs, process listing, quick bar launch, proxy management, and rule management.
- Added a reusable icon generation script and refreshed the app icon set for the Tauri desktop app.
- Added `LICENSE` and `THIRD_PARTY_NOTICES.md` to release packaging.
- Added unit tests around API helpers, config persistence, model defaults, process matching, and local-origin CORS checks.

### Changed

- Switched the repository and packaged application metadata to MIT licensing.
- Tightened the core API CORS policy to local origins while preserving browser-based local development support.
- Moved executable icon extraction to the core API and kept it hidden-window on Windows.
- Updated release packaging to exclude bundled ProxiFyre by default and generate GitHub release zip assets automatically.
- Expanded the README with build, run, CLI, licensing, and packaging guidance in both English and Chinese.

### Fixed

- Rejected empty quick bar executable paths at the API layer.
- Avoided release regressions where local browser origins were blocked by CORS.
- Restored no-console icon extraction behavior on Windows.
- Defaulted GitHub publishing to attach a release asset instead of creating source-only releases unintentionally.
