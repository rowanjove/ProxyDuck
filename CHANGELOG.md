# Changelog

ProxyDuck starts a new product version line at **1.0.0**. Earlier ProxyDock and SmartFlow builds are treated as legacy products and are supported only through compatibility migration.

## 1.1.0 - 2026-09-14

### 中文

- **Windows 服务化与 IPC 权限隔离**：新增 `proxyduck-service.exe` 作为常驻后台服务宿主，通过 Named Pipe 及专用 Windows ACL（当前安装用户 SID + SYSTEM + Administrators）提供安全调用通道；桌面端与 CLI 日常使用受限权限通信，无需持续请求管理员提权。
- **网络急救 (Doctor)**：集成 10 层系统网络与代理健康诊断系统，支持物理网卡、默认网关、路由表、DNS 解析、NCSI 探测、Winsock LSP 目录、Hosts 屏蔽及死代理端口的全面体检；支持一键安全修复并在操作前自动创建网络环境快照，支持秒级快照回滚。
- **配置工作台与策略模拟器 (Studio)**：提供规则策略模拟器（Policy Simulator），输入进程名、目标域名与端口即可实时分析规则命中链与匹配优先级；内置死规则、阴影遮蔽规则（Shadowed Rules）与冗余规则静态分析检测。
- **端点安全导入**：支持从 Clash `proxies` 和 sing-box `outbounds` 本地配置文件导入代理端点；支持导入前只读预览（解析节点数、协议兼容性警告与跳过项），不支持类型自动停用，严格保护代理凭据不回显。
- **配置方案快照 (Profiles V1)**：支持多场景配置方案的保存、复制、差异比对（Diff）、重命名与快速激活；方案间独立隔离规则、路由引擎与快捷启动设置，密码凭证由系统统一安全管理。
- **规则工作台强化**：支持按业务场景分组与标签分类管理；支持批量选中启停；内置日常浏览器、AI 编程开发工具、主流游戏平台及远程会议软件等预设模版。
- **端点可观测性与健康监控**：SOCKS5 端点连续主动健康探测，记录并维护最近 30 次有界延迟样本走势；提供进程生命周期事件时序追踪（Timeline）与活跃连接统计。
- **文案重构与界面优化**：全面优化中英文界面与文档文案，去除修饰性表述，采用准确清晰的技术术语；更新全套 1.1.0 高清界面截图。

### English

- **Windows Service Host & Named Pipe IPC**: Added `proxyduck-service.exe` as a dedicated LocalSystem service host with Named Pipe transport and strict Windows ACLs (installing user SID, SYSTEM, and Administrators); desktop and CLI operate under standard privileges without continuous elevation prompts.
- **Network Doctor**: Introduced a 10-layer network and proxy diagnostic engine covering network adapters, gateways, routes, DNS resolution, NCSI probes, Winsock LSP catalog, Hosts file, and dead proxy ports; includes one-click safe remediation with automatic pre-repair environment snapshots and instant rollback.
- **Config Studio & Policy Simulator**: Added an interactive policy simulator to evaluate rule match chains and priority by process name, destination domain, and port; incorporates static rule analysis for dead, shadowed, and redundant rules.
- **Proxy Endpoint Import**: Added local import support for Clash `proxies` and sing-box `outbounds` configurations with preview-first safety checks; incompatible protocols are automatically marked disabled and secrets remain redacted.
- **Profiles V1**: Added snapshot-based profile management supporting cloning, visual diffing, renaming, and one-click activation across development, office, and entertainment configurations.
- **Rule Workbench Improvements**: Added rule grouping, tags, batch enable/disable operations, and built-in templates for browsers, AI development environments, gaming platforms, and conferencing applications.
- **Observability & Health Supervisor**: Enhanced SOCKS5 continuous capability probing with bounded history (last 30 latency samples) for trend analysis; added process timeline tracking and active connection metrics.
- **Documentation & UI Polish**: Thoroughly refreshed Chinese and English documentation and UI copy for technical clarity and precision; generated high-resolution screenshots for 1.1.0.

## 1.0.0 - 2026-08-16

### 中文

- 产品正式更名为 ProxyDuck；统一更新桌面标题、数据目录、Cargo 包、二进制、API 请求头、环境变量、Windows 安装器和发布物名称。
- 使用全新的“鸭子 + 网络路由”图标，并重新生成 Windows PNG、ICO 与前端品牌资源。
- 新版本号从 1.0.0 开始，同时保留 ProxyDock 与 SmartFlow 的配置、令牌、环境变量和 API 请求头迁移兼容。
- 提供按进程的 SOCKS5 TCP/UDP 路由、旧 DNS 防护兼容标记、代理鉴权和分层连通性探测。
- 提供确定性规则优先级、精确路径/进程名匹配、通配模式、规则冲突检测与试运行。
- PID 路由规则现在必须绑定 creation time；缺少身份时编译器 fail-closed，watcher 不把 `(PID, None)` 当稳定身份，避免 PID 复用误命中。
- 提供 ProxiFyre（旧版 WinDivert 标签兼容）与可选 sing-box TUN 数据平面、故障恢复和真实运行状态。
- 提供防泄漏策略、防火墙事务回滚、配置原子保存、备份恢复和 DPAPI 令牌保护。
- 提供中文/英文桌面界面、托盘、首次运行检查、配置导入导出和诊断信息。
- 修复数据平面启动失败会连带退出核心服务的问题；桌面端现在请求必要的管理员权限，并将核心启动日志保存在本机数据目录。
- 默认发行包内置经固定版本与 SHA-256 校验的 ProxiFyre 2.4.0 x64 和 WinpkFilter 3.6.2.1 x64；安装器自动安装驱动，sing-box 等其他引擎保持用户按需安装。
- 新增 `proxyduck-service.exe` Windows Service host：安装时保存安装用户 SID、迁移首份配置到 `%ProgramData%\ProxyDuck`、配置服务失败自动恢复，并以 Named Pipe + Windows ACL 作为桌面端/CLI 的服务通道；未安装服务时保留 HTTP sidecar 回退。
- Named Pipe 与 HTTP 共用版本化 request/response DTO、deadline、长度帧、typed error 和受限诊断 ZIP 传输。
- 配置文件升级到 Schema 5，新增 Profiles V1：可保存、复制、比较、激活和删除规则/引擎/快捷启动/运行策略快照；代理凭据不复制，仍由 SecretStore 管理。
- Strict/Compatibility 模式现在返回结构化编译诊断；已知引擎能力缺口在 Compatibility 下明确降级，身份和结构错误继续 fail-closed。
- 规则工作台新增分组、标签、批量启停，以及 AI 开发、浏览器、游戏平台和会议模板；模板规则会保留来源标签，批量变更使用原子配置事务。
- 支持从 Clash `proxies` 和 sing-box `outbounds` 本地 JSON 导入代理端点；桌面端和 CLI 先预览再确认，当前引擎不支持的类型会保持停用，不抓取远程订阅。
- 代理健康状态增加最近 30 次延迟样本，诊断与 API 可据此展示趋势；失败状态继续保留认证、协议和离线原因分层。
- 提供 Core API、CLI、Windows CI、Playwright E2E、便携包、SHA-256 清单和可选安装器签名。

### English

- Renamed the product to ProxyDuck across desktop identity, data directories, Cargo packages, binaries, API headers, environment variables, the Windows installer, and release artifacts.
- Added a completely redesigned duck-and-network-routing icon and regenerated the Windows PNG, ICO, and frontend brand assets.
- Started a new product version line at 1.0.0 while retaining migration compatibility with ProxyDock and SmartFlow configuration, tokens, environment variables, and API headers.
- Included per-process SOCKS5 TCP/UDP routing, legacy DNS-protection compatibility flags, authentication, and layered capability probes.
- Included deterministic rule priority, exact path/process-name matching, glob patterns, conflict detection, and dry runs.
- PID routing rules now require creation time; missing identity fails closed and watcher de-duplication never treats `(PID, None)` as stable, preventing PID-reuse matches.
- Included the ProxiFyre data plane (with compatibility for the legacy WinDivert label) and optional sing-box TUN data planes with recovery and truthful runtime state.
- Included leak-protection policies, transactional firewall rollback, atomic configuration persistence, backup recovery, and DPAPI token protection.
- Included Chinese and English desktop interfaces, tray integration, first-run checks, configuration portability, and diagnostics.
- Fixed data-plane startup failures terminating the control service; the desktop app now requests required administrator access and preserves core startup logs in the local data directory.
- Bundled pinned and SHA-256-verified ProxiFyre 2.4.0 x64 and WinpkFilter 3.6.2.1 x64 by default; the installer installs the driver automatically while sing-box and other engines remain user-managed.
- Added `proxyduck-service.exe` as a LocalSystem Windows Service host with installer-user SID propagation, first-config migration to `%ProgramData%\ProxyDuck`, failure recovery, and Named Pipe + Windows ACL transport for the desktop and CLI; HTTP remains an explicit portable/developer fallback.
- Unified Named Pipe and HTTP around a versioned request/response DTO with deadlines, bounded frames, typed errors, and controlled diagnostic ZIP transfer.
- Upgraded the config format to Schema 5 with Profiles V1 for saving, cloning, diffing, activating, and deleting rule/engine/Quick Launch/runtime snapshots; proxy credentials remain in the SecretStore and are never duplicated.
- Strict and Compatibility modes now expose structured compile diagnostics; known engine capability gaps degrade explicitly in Compatibility while identity and structural errors remain fail-closed.
- Added rule groups, tags, atomic batch enable/disable, and AI development, browser, gaming, and meeting templates; template origin is preserved as metadata.
- Added local Clash `proxies` and sing-box `outbounds` endpoint import with preview-first desktop and CLI flows; unsupported types remain disabled and remote subscriptions are never fetched.
- Proxy health now retains the latest 30 bounded latency samples for trend display while preserving authentication, protocol, and offline failure classes.
- Included the Core API, CLI, Windows CI, Playwright E2E, portable packaging, SHA-256 manifests, and optional installer signing.
