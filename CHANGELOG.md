# Changelog

All notable changes to SmartFlow will be documented in this file.

The project is open source under the MIT License.

## 0.3.0 - 2026-04-13

### Added

- Added per-user local API token authentication, with the token stored in the SmartFlow app data directory and auto-loaded by the desktop UI and CLI.
- Added observability endpoints for rule hits, proxy hits, and recent match events, plus a richer dashboard summary in the Tauri UI.
- Added an `AI 开发模板` quick action that can seed common IDE, Node.js, and browser proxy rules in one step.
- Added a `--format json` CLI option while keeping `--json` as a compatibility shortcut.

### Changed

- Quick Bar bind modes now synchronize managed EXE rules so `start_and_bind` and `bind_only` produce an actual runtime binding instead of a launcher-only action.
- Rule matching now follows an explicit priority order: PID > EXE path > app name > wildcard.
- Internal engine wiring now depends on a dedicated data-plane backend trait so alternate backends and test doubles can be slotted in with lower coupling.

### Fixed

- Blocked direct edits and deletes of Quick Bar managed rules from the generic rule endpoints to prevent UI/API drift.
- Stopped duplicate lower-priority rule patterns from shadowing higher-priority bindings in the generated ProxiFyre runtime config.

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
