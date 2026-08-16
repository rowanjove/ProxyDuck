# 安全策略

ProxyDuck 会接触进程信息、本地代理配置、Windows 防火墙与网络驱动，因此安全问题会被优先处理。

## 支持范围

| 版本 | 安全更新 |
| --- | --- |
| 1.0.x | 支持 |
| SmartFlow / ProxyDock 旧版本 | 不支持，请迁移到 ProxyDuck |

## 已知的继承依赖提醒

ProxyDuck 1.0.0 基于 Tauri 1。GitHub 当前会报告两项无法在 Tauri 1 约束内单独升级的间接依赖提醒：

- [`glib::VariantStrIter` 迭代器实现不健全（GHSA-wrw7-89jp-8q8g）](https://github.com/advisories/GHSA-wrw7-89jp-8q8g)：来自 Tauri 1 的 Linux GTK 依赖分支；ProxyDuck 1.0.0 仅发布 Windows 版本，不会打包这条 Linux 运行时依赖。
- [`rand` 在特定自定义日志器组合下存在不健全行为（GHSA-cq8v-f236-94qc）](https://github.com/advisories/GHSA-cq8v-f236-94qc)：Tauri 1 的旧 HTML / 宏依赖仍约束 `rand 0.7.3`；可独立更新的 `rand 0.8` 已升至修复版本 `0.8.6`。

Dependabot 已确认这两个旧版本无法在现有依赖约束内更新。项目不会隐藏或忽略提醒；完整退出路径是路线图第 21 项的 Tauri 2 迁移。在此之前，1.0.x 仅发布 Windows 产物，并持续对可独立修复的直接与间接依赖进行更新。

## 私下报告漏洞

请使用 GitHub 仓库的 **Security → Report a vulnerability** 私密报告入口，不要创建公开 Issue。

报告中建议包含：

- 受影响版本和 Windows 版本
- 问题类型与实际影响
- 最小复现步骤或概念验证
- 你已经尝试过的缓解方式

请先移除代理用户名、密码、令牌、个人目录、真实公网地址和无关日志。维护者的目标是在 72 小时内确认收到报告，并在复现后说明处理计划。

## 威胁边界

- Core 默认只监听 `127.0.0.1`，API 请求必须携带本地随机令牌。
- Windows 上的令牌使用当前用户 DPAPI 保护。
- ProxyDuck 不提供远程控制面、账户系统或默认云同步。
- ProxiFyre、WinpkFilter 与用户安装的其他引擎属于独立第三方组件，适用各自的安全公告和许可证。
