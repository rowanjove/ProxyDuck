# ProxyDuck Service / IPC ADR

状态：协议契约、Windows Service host、Named Pipe 传输、服务安装脚本和 Tauri 桌面调用链已落地；真实 Windows VM/安装器烟测仍待环境门禁。

当前实现位置：`proxyduck-common::ipc`。

已落地的契约门禁：

- 固定 `version`、唯一 `requestId`、HTTP-compatible `method/path`；
- 每个请求必须带有 1–120000ms deadline；
- 统一 4 字节大端长度帧，单帧上限 1MiB，拒绝截断和尾随数据；
- response 使用 typed error code、status、retryable 和可选 details；
- 协议层拒绝非绝对路径、控制字符、超长 ID、未知版本和非法状态组合。

`proxyduck-service.exe` 已作为独立 host 接管 Core bootstrap：安装时把安装用户 SID 作为受限启动参数传入，服务以 LocalSystem 运行并启用 `--ipc-pipe`；Tauri UI 和 CLI 检测到已安装服务后不会再拉起第二个 Core，而通过 Named Pipe 调用同一套 API。客户端在生产模式下还会把 Pipe 服务端 PID 与 SCM 中登记的二进制路径比对；开发 Core Pipe 需显式设置 `PROXYDUCK_ALLOW_DEV_PIPE=1`。localhost HTTP 仍保留给未安装服务的开发/portable 回退模式。标准用户、管理员、SID 变化和服务重启仍需在 Windows VM 中验收。

适配器还执行 API path allow-list；`engine/mode`、生命周期、Quick Bar 启动和诊断 ZIP 等高权限动作要求管理员/SYSTEM token。非 Windows 构建拒绝 `--no-http --ipc-pipe` 组合，不启动不可管理的 headless 进程。

## 决策

ProxyDuck 1.3 将由 Windows Service 持有 Core、引擎、驱动、防火墙和健康检查生命周期；桌面 UI 只作为标准用户控制端。主 IPC 使用本机 Named Pipe，localhost HTTP 仅保留给显式开启的开发者模式，默认不作为桌面主通道。

服务账户初始采用 `LocalSystem`，但所有业务请求都读取 Named Pipe 客户端的实际 access token/SID。安装用户 SID、Administrators 和 SYSTEM 是默认允许的安全主体；其他交互用户默认拒绝。服务不会因为调用方能够连接 pipe 就授予修改驱动、防火墙或配置的权限。

## 威胁模型

- 低权限本机进程尝试读取代理凭据、配置或诊断包。
- 其他登录用户尝试控制当前用户的路由、引擎或 Quick Bar。
- UI 被替换、退出或崩溃，但 Service 仍继续持有数据面。
- Service 重启、升级或卸载过程中产生半应用的 EnginePlan、临时明文配置或残留防火墙规则。
- 恶意请求伪造 API 字段，诱导 Service 将 Strict 策略降级为 Direct。

不把“客户端知道 pipe 名称”“请求携带 token”视为权限证明；权限必须由 Windows token/SID 和服务端状态机共同决定。

## Pipe 协议边界

每个请求包含（当前冻结的 wire DTO）：

```json
{
  "version": 1,
  "requestId": "uuid",
  "method": "GET | POST | PUT | DELETE",
  "path": "/runtime/status",
  "deadlineMs": 5000,
  "body": {}
}
```

`method/path` 是现有 Core HTTP API 的稳定映射；Service 层可以在其 operation registry 中把更高层 operation 映射到这些路径，但不能另定义一套 wire 字段。响应包含 `version`、`requestId`、HTTP-compatible `status`，成功时可选 `body`，失败时必须有 typed error：

```json
{
  "version": 1,
  "requestId": "uuid",
  "status": 403,
  "error": { "code": "forbidden", "message": "...", "retryable": false }
}
```

服务端约束：

- 单请求有上限和取消语义；超过 deadline 不继续执行引擎/驱动动作。当前适配器对连接读写和 Axum dispatch 执行 deadline；Service 事务动作仍须在 Service host 中支持可取消边界。
- `applyConfig` 采用 validate → compile → apply → verify → persist 的事务顺序；失败回滚到 last-known-good plan。
- Strict 下任何能力不支持、健康不满足或校验失败都只能进入 degraded/stopped，不能扩大为 Direct。
- 二进制诊断 ZIP 仅在单帧上限内通过 base64 字段返回；超过上限明确返回错误，不能把任意路径交给客户端读取。
- 日志、错误和响应沿用结构化事件 ID，禁止返回密码、secret ref 解密值和完整用户路径。

## Secret 迁移

当前 1.1 使用 Current User DPAPI。`proxyduck-service --install` 在注册 LocalSystem 服务前运行一次性迁移：在安装用户会话中解密现有引用，并把相同 secret ref 以 machine-scope DPAPI 写入 `%PROGRAMDATA%\ProxyDuck\secrets`，共享配置随后只保留 ref。任一已有引用无法解密时安装失败，不会启用一个静默丢失认证的服务。服务运行期新写入的凭据也使用同一 machine-scope store。迁移完成后不记录明文或迁移日志；真实升级、SID 变化和 ACL 仍需 VM 验证。

多用户机器上，配置和 secret 的所有者必须显式记录。卸载默认不自动删除用户数据，提供单独的“删除配置和密钥”确认路径。

## 生命周期与回退

Service 的启动、睡眠恢复、网络变化、升级和卸载都进入同一 reconcile/apply 状态机。UI 退出不会停止 Service；Service 停止前必须先撤销自身创建的临时引擎配置和防火墙规则，并保留失败原因。

1.3 实现前必须在隔离 Windows VM 验证：pipe ACL、SID 变化、服务升级回滚、进程树回收、坏配置恢复、驱动/防火墙失败回滚和临时文件清理。本 ADR 不代表这些运行时门禁已经通过。
