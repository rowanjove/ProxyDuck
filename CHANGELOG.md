# Changelog

All notable changes to SmartFlow are documented in this file.

SmartFlow is open source under the MIT License.

以下为 SmartFlow 的版本更新记录。

## 0.3.0 - 2026-04-13

### English

#### Highlights

- Added per-user local API token authentication. The token is stored in the SmartFlow app data directory and is loaded automatically by the desktop UI and CLI.
- Added observability endpoints for rule hits, proxy hits, and recent match events, and upgraded the Tauri dashboard summary to surface that data more clearly.
- Added an `AI Dev Template` quick action to seed common IDE, Node.js, and browser proxy rules in one step.
- Added a `--format json` CLI option while keeping `--json` as a compatibility shortcut.

#### Behavior Changes

- Quick Bar bind modes now synchronize managed EXE rules, so `start_and_bind` and `bind_only` produce a real runtime binding instead of acting like launcher-only flows.
- Rule matching now follows an explicit priority order: PID > EXE path > app name > wildcard.
- Internal engine wiring now uses a dedicated data-plane backend trait to reduce coupling and make future backend swaps or test doubles easier.

#### Fixes

- Blocked direct edits and deletes of Quick Bar managed rules from the generic rule endpoints to prevent UI and API drift.
- Prevented lower-priority rule patterns from shadowing higher-priority bindings in generated ProxiFyre runtime config.

### 中文

#### 重点更新

- 新增本地 API Token 鉴权。Token 会写入 SmartFlow 应用数据目录，并由桌面 UI 和 CLI 自动读取。
- 新增规则命中、代理命中、最近命中事件等可观测性接口，同时增强了 Tauri 仪表盘的统计展示。
- 新增 `AI 开发模板` 快捷入口，可一键导入常见 IDE、Node.js 与浏览器代理规则。
- CLI 新增 `--format json` 参数，并继续兼容 `--json`。

#### 行为调整

- Quick Bar 的绑定模式现在会同步托管 EXE 规则，`start_and_bind` 和 `bind_only` 会真正产生运行时绑定，而不再只是启动流程。
- 规则匹配优先级现在明确为：PID > EXE 路径 > 应用名 > 通配。
- 内部引擎接线新增独立的数据平面 backend trait，降低后续替换后端或做测试替身时的耦合度。

#### 修复

- 禁止通过通用规则接口直接编辑或删除 Quick Bar 托管规则，避免 UI 与 API 状态漂移。
- 修复低优先级规则模式覆盖高优先级绑定的问题，生成 ProxiFyre 运行时配置时会按优先级收敛。

## 0.2.0 - 2026-04-13

### English

#### Highlights

- Added `smartflow-cli` for local automation and headless management of the SmartFlow core API.
- Added CLI commands for status, config, runtime toggles, engine mode, logs, process listing, quick bar launch, proxy management, and rule management.
- Added a reusable icon generation script and refreshed the app icon set for the Tauri desktop app.
- Added `LICENSE` and `THIRD_PARTY_NOTICES.md` to release packaging.
- Added unit tests covering API helpers, config persistence, model defaults, process matching, and local-origin CORS checks.

#### Behavior Changes

- Switched repository and packaged application metadata to MIT licensing.
- Tightened the core API CORS policy to local origins while keeping browser-based local development usable.
- Moved executable icon extraction into the core API and kept the Windows implementation hidden-window.
- Updated release packaging to exclude bundled ProxiFyre by default and support release zip generation.
- Expanded the README with build, run, CLI, licensing, and packaging guidance in both English and Chinese.

#### Fixes

- Rejected empty quick bar executable paths at the API layer.
- Avoided regressions where valid local browser origins were blocked by CORS.
- Restored no-console executable icon extraction behavior on Windows.
- Fixed the release publishing flow so it would not unintentionally fall back to source-only releases when a packaged asset was expected.

### 中文

#### 重点更新

- 新增 `smartflow-cli`，用于本地自动化脚本和无界面环境下管理 SmartFlow core API。
- 新增 CLI 命令，覆盖状态查看、配置读取、运行时开关、引擎模式、日志、进程列表、Quick Bar 启动、代理管理和规则管理。
- 新增可复用的图标生成脚本，并刷新了 Tauri 桌面端图标资源。
- 在发布内容中补充 `LICENSE` 和 `THIRD_PARTY_NOTICES.md`。
- 新增一批单元测试，覆盖 API 辅助逻辑、配置持久化、模型默认值、进程匹配和本地 CORS 校验。

#### 行为调整

- 仓库和打包应用的许可证信息统一切换为 MIT。
- Core API 的 CORS 策略收紧到本地来源，同时保留本地浏览器开发场景可用。
- 可执行文件图标提取逻辑迁移到 core API，Windows 下继续保持隐藏窗口执行。
- 发布打包默认不再捆绑 ProxiFyre，并支持生成 release zip。
- README 扩展为中英双语，补充构建、运行、CLI、许可证和打包说明。

#### 修复

- 在 API 层阻止空的 Quick Bar 可执行路径写入。
- 修复本地浏览器来源被 CORS 误拦截的回归问题。
- 恢复 Windows 下无控制台弹窗的图标提取行为。
- 修复发布流程在预期应附带打包资产时，意外退化为仅源码发布的问题。
