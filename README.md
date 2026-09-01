# ProxyDuck — Windows 按应用代理分流

[简体中文](README.md) | [English](README.en.md)

ProxyDuck 将指定 Windows 应用的 TCP、UDP 和 DNS 流量转发到本地 SOCKS5 代理。它提供桌面界面和 CLI，用于配置进程规则、检查代理连通性、查看路由状态与最近命中。

你需要先准备 Clash、sing-box、V2Ray 或其他程序提供的本地 SOCKS5 端口。**ProxyDuck 不提供代理节点，也不替代代理服务。**

[下载 v1.0.0](https://github.com/rowanjove/ProxyDuck/releases/tag/v1.0.0) · [更新记录](CHANGELOG.md) · [报告问题](https://github.com/rowanjove/ProxyDuck/issues)

![ProxyDuck 概览：路由开关、规则与最近活动](docs/images/proxyduck-overview.png)

## 安装与首次配置

需要 Windows 10/11 x64、WebView2 Runtime，以及可用的本地 SOCKS5 代理。安装驱动与接管流量需要管理员权限。

1. 从 [Releases](https://github.com/rowanjove/ProxyDuck/releases) 下载：
   - `ProxyDuck-1.0.0-setup.exe`：安装版，自动部署 WinpkFilter 驱动。
   - `ProxyDuck-1.0.0-portable.zip`：免安装版，首次使用运行 `drivers/Install-WinpkFilter.cmd`。
2. 启动自己的代理程序，确认其 SOCKS5 端口，例如 `127.0.0.1:7897`。
3. 在“代理”中添加端点并测试连通性。
4. 在“规则”中选择应用、目标代理和接管协议。
5. 返回“概览”开启路由，检查数据平面状态和实际命中。

当前 ProxyDuck 二进制未配置商业代码签名，可能触发 SmartScreen。随包第三方运行时来自固定版本的上游发布资产，并由 SHA-256 校验。卸载 ProxyDuck 不会自动移除可能被其他应用共用的 WinpkFilter 驱动。

## 规则与状态

- 按进程名、完整路径、PID 或通配符匹配应用。
- 按规则顺序确定优先级，支持冲突检查、复制、排序与进程试运行。
- 分别配置 TCP、UDP 与 DNS 接管。
- 分别查看核心、数据平面、代理连通性及防泄漏状态；代理端口连通不代表所有应用流量都已被接管。
- 支持单实例、托盘、中英文界面和浅色／深色主题。

![ProxyDuck 按应用分流规则界面](docs/images/proxyduck-rules.png)

截图使用本机回环代理地址和隔离演示配置，不含真实用户数据。

## 数据平面与限制

| 组件 | 默认状态 | 作用 |
| --- | --- | --- |
| ProxiFyre 2.4.0 x64 | 内置 | 将目标进程 TCP／UDP 转发到 SOCKS5 |
| WinpkFilter 3.6.2.1 x64 | 内置 | ProxiFyre 所需的数据包过滤驱动 |
| sing-box TUN | 用户自行安装 | 可选数据平面 |
| 原生 WFP | 尚未提供 | 需要独立签名驱动 |
| API Hook | 实验阶段 | 不作为已交付能力 |

运行时的版本、下载源与哈希见 [default-runtimes.json](third_party/default-runtimes.json)。构建过程生成 `RUNTIME-LOCK.json`，用于校验发行包运行时文件。

桌面端和 CLI 通过本地 API 调用 Core，Core 负责进程发现、规则编译和驱动数据平面；数据平面再将流量送往 SOCKS5 端点。不同引擎的限制不能用界面规则配置代替实际验证。

## 命令行

在解压目录中运行：

```powershell
.\proxyduck-cli.exe status
.\proxyduck-cli.exe runtime on
.\proxyduck-cli.exe runtime off
.\proxyduck-cli.exe mode set win-divert
.\proxyduck-cli.exe proxies list
.\proxyduck-cli.exe rules list
.\proxyduck-cli.exe processes list --filter code --limit 20
.\proxyduck-cli.exe logs --tail 50
```

`mode set win-divert` 是当前切换默认 ProxiFyre 数据平面的 CLI 标识。CLI 默认连接 `http://127.0.0.1:46666`，可用 `--core-url` 指定其他本地地址。

## 本地数据与安全

Core API 仅监听本机并使用随机令牌鉴权；Windows 令牌通过当前用户 DPAPI 保护。应用数据目录包含 `config.json5`、`token`、`core.log` 和 `crash.log`。配置及日志可能涉及代理或进程信息，反馈问题前应检查并脱敏。

常用环境变量：

- `PROXYDUCK_CORE_URL`：Core API 地址。
- `PROXYDUCK_PROXIFYRE_DIR`：自定义 ProxiFyre 目录。
- `PROXYDUCK_SING_BOX_PATH`：用户安装的 sing-box 路径。
- `PROXYDUCK_ICON_DIR`：进程图标缓存目录。

首次运行会迁移 ProxyDock 和旧 SmartFlow 配置，不删除旧目录。

## 从源码构建

需要 Rust stable、Node.js 20+、Visual Studio 2022 C++ Build Tools 和 Windows 10/11 x64。

```powershell
git clone https://github.com/rowanjove/ProxyDuck.git
cd ProxyDuck
npm ci
npx playwright install chromium
./scripts/verify-release.ps1
./scripts/build-release.ps1
./scripts/package-release.ps1
```

构建会下载并校验固定版本的 ProxiFyre、WinpkFilter 和许可文本；运行时缓存不提交到 Git。sing-box 默认不下载。自定义捆绑包可使用：

```powershell
./scripts/build-release.ps1 -BundleSingBox -SingBoxPath "C:/path/to/sing-box.exe"
```

## 沿革、贡献与许可

ProxyDuck 前身为 SmartFlow，公开版本从 1.0.0 重新编号。旧仓库为私有历史存档；部分 `smartflow-*` 源码目录保留，以兼容现有脚本。

[路线图](ROADMAP.md) · [贡献指南](CONTRIBUTING.md) · [安全反馈](SECURITY.md)

自有源码采用 [MIT License](LICENSE)。MIT 不覆盖随包的 ProxiFyre 或其他第三方运行时；再分发前阅读 [第三方许可](THIRD_PARTY_NOTICES.md) 和 [对应源码](THIRD_PARTY_SOURCES.md)。
