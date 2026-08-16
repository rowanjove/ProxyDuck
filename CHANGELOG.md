# Changelog

ProxyDuck starts a new product version line at **1.0.0**. Earlier ProxyDock and SmartFlow builds are treated as legacy products and are supported only through compatibility migration.

## 1.0.0 - 2026-08-16

### 中文

- 产品正式更名为 ProxyDuck；统一更新桌面标题、数据目录、Cargo 包、二进制、API 请求头、环境变量、Windows 安装器和发布物名称。
- 使用全新的“鸭子 + 网络路由”图标，并重新生成 Windows PNG、ICO 与前端品牌资源。
- 新版本号从 1.0.0 开始，同时保留 ProxyDock 与 SmartFlow 的配置、令牌、环境变量和 API 请求头迁移兼容。
- 提供按进程的 SOCKS5 TCP、UDP 与 DNS 路由、代理鉴权和实际连通性探测。
- 提供确定性规则优先级、精确路径/进程名匹配、通配模式、规则冲突检测与试运行。
- 提供 ProxiFyre/WinDivert 与可选 sing-box TUN 数据平面、故障恢复和真实运行状态。
- 提供防泄漏策略、防火墙事务回滚、配置原子保存、备份恢复和 DPAPI 令牌保护。
- 提供中文/英文桌面界面、托盘、首次运行检查、配置导入导出和诊断信息。
- 修复数据平面启动失败会连带退出核心服务的问题；桌面端现在请求必要的管理员权限，并将核心启动日志保存在本机数据目录。
- 默认发行包内置经固定版本与 SHA-256 校验的 ProxiFyre 2.4.0 x64 和 WinpkFilter 3.6.2.1 x64；安装器自动安装驱动，sing-box 等其他引擎保持用户按需安装。
- 提供 Core API、CLI、Windows CI、Playwright E2E、便携包、SHA-256 清单和可选安装器签名。

### English

- Renamed the product to ProxyDuck across desktop identity, data directories, Cargo packages, binaries, API headers, environment variables, the Windows installer, and release artifacts.
- Added a completely redesigned duck-and-network-routing icon and regenerated the Windows PNG, ICO, and frontend brand assets.
- Started a new product version line at 1.0.0 while retaining migration compatibility with ProxyDock and SmartFlow configuration, tokens, environment variables, and API headers.
- Included per-process SOCKS5 TCP, UDP, and DNS routing with authentication and real capability probes.
- Included deterministic rule priority, exact path/process-name matching, glob patterns, conflict detection, and dry runs.
- Included ProxiFyre/WinDivert and optional sing-box TUN data planes with recovery and truthful runtime state.
- Included leak-protection policies, transactional firewall rollback, atomic configuration persistence, backup recovery, and DPAPI token protection.
- Included Chinese and English desktop interfaces, tray integration, first-run checks, configuration portability, and diagnostics.
- Fixed data-plane startup failures terminating the control service; the desktop app now requests required administrator access and preserves core startup logs in the local data directory.
- Bundled pinned and SHA-256-verified ProxiFyre 2.4.0 x64 and WinpkFilter 3.6.2.1 x64 by default; the installer installs the driver automatically while sing-box and other engines remain user-managed.
- Included the Core API, CLI, Windows CI, Playwright E2E, portable packaging, SHA-256 manifests, and optional installer signing.
