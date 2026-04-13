# SmartFlow

SmartFlow is a lightweight per-process traffic control tool for Windows. It works with proxy tools like Clash, sing-box, and V2Ray, so traffic policy can follow specific applications instead of relying only on domain/IP matching.

It is designed for modern applications that may bypass system proxy settings via custom network stacks, built-in DNS, HTTP/2, or QUIC. Typical scenarios include AI IDEs, language servers, developer toolchains, and automation scripts.

SmartFlow provides a tray UI (`smartflow-ui`) and local core service (`smartflow-core`) to help you bind proxy behavior to target processes such as `cursor.exe`, `node.exe`, and language server processes.

SmartFlow is open source under the MIT License.

## Current Data Plane

- Runtime traffic enforcement backend: **ProxiFyre** (SOCKS5, TCP+UDP per-process)
- SmartFlow core generates/updates `app-config.json` automatically and controls ProxiFyre lifecycle.
- Runtime hardening policies are applied through Windows Firewall rules:
  - DNS direct block (`TCP/UDP 53`)
  - IPv6 direct block (`::/0`)
  - DoH provider IP block (`TCP 443`, known DoH endpoints)

## Key Features

- Proxy profiles (default: Clash Verge `127.0.0.1:7897`)
- Rule management (app name/path/PID matching)
- Quick Bar launch and bind with managed EXE rules
- AI IDE preset import for VS Code, Cursor, Windsurf, Node.js, Chrome, and Edge
- Engine mode switch (`win_divert`, `wfp`, `api_hook`) with shared backend lifecycle
- Real-time process view, rule hit stats, and logs
- Tray resident UI

## Build Prerequisites (Win10)

- Rust toolchain (MSVC)
- Visual Studio Build Tools 2022 + C++ toolset + Windows 10/11 SDK
- Node.js + npm (frontend asset helper)

## Build

```powershell
.\scripts\build-release.ps1
```

If you need to bundle a local ProxiFyre runtime after reviewing its upstream
license terms:

```powershell
.\scripts\build-release.ps1 -BundleProxifyre
```

Output:

- `release\SmartFlow\smartflow-core.exe`
- `release\SmartFlow\smartflow-cli.exe`
- `release\SmartFlow\smartflow-ui.exe`
- `release\SmartFlow\CHANGELOG.md`
- `release\SmartFlow\LICENSE`
- `release\SmartFlow\THIRD_PARTY_NOTICES.md`
- `release\SmartFlow\proxifyre\*` (optional, only when `-BundleProxifyre` is used)

## Run

```powershell
.\release\SmartFlow\smartflow-core.exe --bind 127.0.0.1:46666
.\release\SmartFlow\smartflow-cli.exe status
.\release\SmartFlow\smartflow-ui.exe
```

Notes:

- Run as **Administrator** for full enforcement/firewall rule operations.
- Runtime hardening firewall rules are applied only when at least one SOCKS5 endpoint is reachable.
- New default config starts with `runtime.enabled = false` for safer first launch.
- Core HTTP requests require `X-SmartFlow-Token`; SmartFlow writes the token to `%APPDATA%\SmartFlow\token` and the bundled UI/CLI load it automatically.
- The source repo and default release output do **not** bundle ProxiFyre binaries.
- If local builds fail with missing `kernel32.lib` / `stddef.h`, install the Windows SDK component for Visual Studio Build Tools.
- `smartflow-core` searches ProxiFyre in this order:
  1. `SMARTFLOW_PROXIFYRE_DIR`
  2. `<core_dir>\proxifyre`
  3. `<core_dir>`
  4. `<cwd>\third_party\proxifyre\pkg`
  5. `C:\tools\ProxiFyre`

## Core API

Base URL: `http://127.0.0.1:46666`

- `GET /health`
- `GET/PUT /config`
- `GET /processes`
- `GET/POST /rules`
- `PUT/DELETE /rules/{id}`
- `GET/POST /quickbar`
- `PUT/DELETE /quickbar/{id}`
- `POST /quickbar/{id}/launch`
- `GET/POST /proxies`
- `PUT/DELETE /proxies/{id}`
- `POST /engine/mode`
- `POST /runtime`
- `GET /stats`
- `GET /stats/rules`
- `GET /stats/proxies`
- `GET /stats/hits`
- `GET /logs`
- `POST /templates/ai-dev`

## CLI

`smartflow-cli` talks to the local core HTTP API and is useful for scripts,
PowerShell workflows, and headless machines.

Use `--format json` (or the legacy `--json`) for structured automation output.

Examples:

```powershell
.\release\SmartFlow\smartflow-cli.exe status
.\release\SmartFlow\smartflow-cli.exe runtime on
.\release\SmartFlow\smartflow-cli.exe mode set win-divert
.\release\SmartFlow\smartflow-cli.exe proxies list
.\release\SmartFlow\smartflow-cli.exe proxies add --id clash-local --name "Clash Local" --kind socks5 --endpoint 127.0.0.1:7897
.\release\SmartFlow\smartflow-cli.exe proxies update clash-local --endpoint 127.0.0.1:7898 --enabled on
.\release\SmartFlow\smartflow-cli.exe rules list
.\release\SmartFlow\smartflow-cli.exe rules add --name "Node via Clash" --proxy clash-socks --app node.exe
.\release\SmartFlow\smartflow-cli.exe rules remove "Node via Clash"
.\release\SmartFlow\smartflow-cli.exe quickbar launch cursor
.\release\SmartFlow\smartflow-cli.exe processes list --filter node --limit 20
.\release\SmartFlow\smartflow-cli.exe logs --tail 50
```

Set `SMARTFLOW_CORE_URL` if your core is not using the default
`http://127.0.0.1:46666`.

## License

- SmartFlow source code is licensed under [MIT](./LICENSE).
- Third-party runtimes keep their own licenses. See [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).
- Release history is tracked in [CHANGELOG.md](./CHANGELOG.md).

---

## 中文版

SmartFlow 是一款面向 Windows 的轻量化进程级流量管理工具，包含托盘界面（`smartflow-ui`）和本地核心服务（`smartflow-core`）。它可与 Clash、sing-box、V2Ray 等代理工具协同，让策略按进程生效，而不是仅依赖域名/IP 规则匹配。

该项目主要面向 AI IDE、语言服务器、开发工具链等场景，解决应用使用自定义网络栈、内置 DNS、HTTP/2、QUIC 时可能绕过系统代理的问题。SmartFlow 的定位是应用程序与代理工具之间的流量控制层。

SmartFlow 以 MIT License 开源。

### 当前数据平面

- 运行时流量接管后端：**ProxiFyre**（SOCKS5，支持 TCP+UDP 按进程代理）
- SmartFlow Core 会自动生成/更新 `app-config.json`，并管理 ProxiFyre 生命周期
- 运行时加固策略通过 Windows 防火墙规则生效：
  - 阻断直连 DNS（`TCP/UDP 53`）
  - 阻断直连 IPv6（`::/0`）
  - 阻断常见 DoH 提供商 IP（`TCP 443`）

### 主要功能

- 代理配置管理（默认：Clash Verge `127.0.0.1:7897`）
- 规则管理（支持进程名/路径/PID 匹配）
- Quick Bar 一键启动并绑定代理，并同步托管 EXE 规则
- 一键导入 AI IDE 预设（VS Code、Cursor、Windsurf、Node、Chrome、Edge）
- 引擎模式切换（`win_divert`、`wfp`、`api_hook`），共享后端生命周期
- 实时进程视图、规则命中统计、日志查看
- 托盘常驻 UI

### 构建依赖（Win10）

- Rust 工具链（MSVC）
- Visual Studio Build Tools 2022 + C++ toolset + Windows 10/11 SDK
- Node.js + npm（前端资源辅助）

### 构建

```powershell
.\scripts\build-release.ps1
```

如果你已经审查过 ProxiFyre 的上游许可证，并且确实需要把本地运行时一起打包：

```powershell
.\scripts\build-release.ps1 -BundleProxifyre
```

输出目录：

- `release\SmartFlow\smartflow-core.exe`
- `release\SmartFlow\smartflow-cli.exe`
- `release\SmartFlow\smartflow-ui.exe`
- `release\SmartFlow\CHANGELOG.md`
- `release\SmartFlow\LICENSE`
- `release\SmartFlow\THIRD_PARTY_NOTICES.md`
- `release\SmartFlow\proxifyre\*`（可选，仅在传入 `-BundleProxifyre` 时生成）

### 运行

```powershell
.\release\SmartFlow\smartflow-core.exe --bind 127.0.0.1:46666
.\release\SmartFlow\smartflow-cli.exe status
.\release\SmartFlow\smartflow-ui.exe
```

说明：

- 建议使用 **管理员权限** 运行，以获得完整接管/防火墙规则能力。
- 仅当至少一个 SOCKS5 端点可达时，运行时加固防火墙规则才会应用。
- 新默认配置中 `runtime.enabled = false`，用于首次启动安全兜底。
- Core HTTP 请求需要携带 `X-SmartFlow-Token`；SmartFlow 会把 token 写入 `%APPDATA%\SmartFlow\token`，打包后的 UI/CLI 会自动读取。
- 源码仓库和默认 release 输出都**不会**直接捆绑 ProxiFyre 二进制。
- 如果本地构建报 `kernel32.lib` 或 `stddef.h` 缺失，请在 Visual Studio Build Tools 中安装 Windows SDK 组件。
- `smartflow-core` 会按以下顺序查找 ProxiFyre：
  1. `SMARTFLOW_PROXIFYRE_DIR`
  2. `<core_dir>\proxifyre`
  3. `<core_dir>`
  4. `<cwd>\third_party\proxifyre\pkg`
  5. `C:\tools\ProxiFyre`

### Core API

基础地址：`http://127.0.0.1:46666`

- `GET /health`
- `GET/PUT /config`
- `GET /processes`
- `GET/POST /rules`
- `PUT/DELETE /rules/{id}`
- `GET/POST /quickbar`
- `PUT/DELETE /quickbar/{id}`
- `POST /quickbar/{id}/launch`
- `GET/POST /proxies`
- `PUT/DELETE /proxies/{id}`
- `POST /engine/mode`
- `POST /runtime`
- `GET /stats`
- `GET /stats/rules`
- `GET /stats/proxies`
- `GET /stats/hits`
- `GET /logs`
- `POST /templates/ai-dev`

### CLI

`smartflow-cli` 直接连接本地 core HTTP API，适合脚本、PowerShell 自动化和无界面环境。

结构化输出可使用 `--format json`（兼容保留 `--json`）。

示例：

```powershell
.\release\SmartFlow\smartflow-cli.exe status
.\release\SmartFlow\smartflow-cli.exe runtime on
.\release\SmartFlow\smartflow-cli.exe mode set win-divert
.\release\SmartFlow\smartflow-cli.exe proxies list
.\release\SmartFlow\smartflow-cli.exe proxies add --id clash-local --name "Clash Local" --kind socks5 --endpoint 127.0.0.1:7897
.\release\SmartFlow\smartflow-cli.exe proxies update clash-local --endpoint 127.0.0.1:7898 --enabled on
.\release\SmartFlow\smartflow-cli.exe rules list
.\release\SmartFlow\smartflow-cli.exe rules add --name "Node 走 Clash" --proxy clash-socks --app node.exe
.\release\SmartFlow\smartflow-cli.exe rules remove "Node 走 Clash"
.\release\SmartFlow\smartflow-cli.exe quickbar launch cursor
.\release\SmartFlow\smartflow-cli.exe processes list --filter node --limit 20
.\release\SmartFlow\smartflow-cli.exe logs --tail 50
```

如果 core 不在默认地址 `http://127.0.0.1:46666`，可通过 `SMARTFLOW_CORE_URL` 指定。

### 许可证

- SmartFlow 源码采用 [MIT](./LICENSE)。
- 第三方运行时保留各自许可证，详见 [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)。
- 更新记录见 [CHANGELOG.md](./CHANGELOG.md)。
