# 参与 ProxyDuck

谢谢你愿意让这只小鸭游得更稳一点。ProxyDuck 欢迎代码、测试、文档、设计和真实使用反馈。

## 开始之前

- 小型修复可以直接提交 Pull Request。
- 新引擎、配置格式变更、驱动相关工作或大范围界面调整，请先开 Issue 对齐方案。
- 安全问题不要提交公开 Issue，请按照 [`SECURITY.md`](SECURITY.md) 私下报告。

## 本地开发

要求：Windows 10/11 x64、Rust stable、Node.js 20+、Visual Studio 2022 C++ Build Tools。

```powershell
npm install
npx playwright install chromium
.\scripts\verify-release.ps1
```

完整检查包括：

- Rust 格式检查、Clippy 与工作区测试
- Node 单元测试
- Playwright 端到端测试
- 前端 JavaScript 语法检查

## 目录说明

- `smartflow-core/`：Core、API、规则编译、进程监视与数据平面
- `smartflow-ui/`：Tauri 桌面端和前端资源
- `smartflow-cli/`：命令行客户端
- `proxyduck-common/`：桌面端、Core 与 CLI 共用的本地鉴权和数据目录逻辑
- `scripts/`：验证、构建、签名、打包和发布脚本
- `installer/`：Windows 安装器定义

部分目录保留旧 SmartFlow 名称是为了维护 Git 历史与外部脚本兼容；新增产品标识请统一使用 `ProxyDuck`。

## 提交要求

1. 只提交与本次改动有关的文件。
2. 行为变化应带测试；用户可见变化应更新 README 或 CHANGELOG。
3. 不要提交代理凭据、真实用户路径、日志、令牌、证书或构建产物。
4. 不要直接提交第三方运行时二进制。更新默认运行时时，需要同步修改版本锁、SHA-256、许可证和源码链接。
5. 提交信息简短明确，例如 `fix: keep core online after data-plane failure`。

## Pull Request 清单

- 说明改了什么、为什么改以及对用户的影响
- 写出验证命令和结果
- 界面变化附截图
- 配置或 API 变化说明兼容策略
- 第三方依赖变化说明许可证与再分发影响

维护者可能会要求把过大的 PR 拆开。这不是增加门槛，而是让每次变化都更容易理解、验证和回退。
