# 架构

ClawdJumpServer 是给 AI agent（以及人）使用的堡垒机。所有组件都主动向服务端拨出，服务端是唯一需要对外开放端口的组件。

```
 agent (cjs / cjs daemon / cjs mcp)            device (cjs-device)
        │  WS 或 HTTP 长轮询，外层 TLS              │  同左
        │  内层 Noise IK（钉住服务端公钥）          │
        ▼                                          ▼
 ┌──────────────────────────── cjs-server ────────────────────────────┐
 │ transport ─ gateway（认证/注册/租约复核）─ relay（决策/审计/中继）    │
 │ REST API（/api/v1）  Web 控制台（/）  审计库  业务库  录像目录        │
 └─────────────────────────────────────────────────────────────────────┘
```

## 组件

| crate | 产物 | 作用 |
|---|---|---|
| `cjs-proto` | 库 | 协议类型、错误码、请求校验（`validate_request`） |
| `cjs-mux` | 库 | yamux 多路复用 + 每条流上的长度前缀 postcard 消息 |
| `cjs-transport` | 库 | 可续传、端到端加密的会话层（WS / HTTP），客户端 profile 与注册流程 |
| `cjs-authz` | 库 | 授权模型、PDP（默认拒绝）、网络规则与 SSRF 防护、能力令牌 |
| `cjs-audit` | 库 | 哈希链审计日志、签名检查点、asciicast 录像 |
| `cjs-fsjail` | 库 | 基于 cap-std 的项目目录监狱 |
| `cjs-sandbox` | 库 + helper | Landlock / sandbox-exec / AppContainer |
| `cjs-server` | `cjs-server` | 网关、中继、出口、REST API、Web 控制台 |
| `cjs-device` | `cjs-device` | 设备守护进程 |
| `cjs-agent` | `cjs` | agent CLI、本地守护进程、MCP 服务 |
| `cjs-ctl` | `cjsctl` | 管理 CLI（REST 客户端） |
| `cjs-tests` | 测试 | 端到端测试与 4A 合规测试 |

## 一条流的生命周期（以终端为例）

1. agent 在 mux 上开流，发送 `OpenRequest::Pty{device, cols, rows, term, ...}`。
2. 服务端：`validate_request` → 重新加载 agent 与负责人并检查状态 → PDP 决策并原子占用并发名额 → 写 `authz.decision` 审计（失败则拒绝）。
3. 服务端在设备连接上开流，签发能力令牌：绑定设备 id、设备连接 id、**该 yamux 流 id**、动作、网络目标、项目根、会话 id，TTL 60 秒。
4. 设备独立校验令牌（签名、设备、连接、流、动作、目标、有效期、防重放），通过项目监狱确定工作目录，在沙箱里启动 shell（环境变量为白名单 + 会话变量）。
5. 服务端创建录像文件（失败即拒绝），登记流，写 `session.start` 审计（失败即拒绝），回复 agent。
6. 中继：服务端逐条解码 `PtyIn` / `PtyOut` 并重新编码，检查尺寸与消息语法，写入录像（增量 SHA-256，单个录像有大小上限）；录像写失败或达到上限立即终止会话。
7. 租约检查器每 5 秒（以及每次管理操作后）对每条流重新决策；授权被撤销、账号被禁用、全权限到期时终止会话并通知 agent。
8. 结束时写 `session.end`：字节数、退出码、时长、录像文件名、大小与 SHA-256。

其他流类型相同，只是第 6 步不同：

| 类型 | 中继方式 | 审计摘要 |
|---|---|---|
| exec | 解码 `ExecIn` / `ExecOut` | stdin/stdout/stderr 字节数与 SHA-256、退出码、信号、是否超时 |
| file_get / file_put / file_list | 解码 `FileMsg`，强制各自的消息顺序；上传不得超过声明大小，下载不得超过设备在 `Meta` 中声明的大小 | 路径、字节数、传输范围 SHA-256、整文件 SHA-256 |
| forward_local / egress | 双向字节拷贝 | 字节数、实际连接地址 |
| forward_remote | 控制流 + 每个接入连接一条 `ForwardRConn` 流 | 每个连接单独审计 |

## 信任边界

- **外层 TLS 不承担机密性**：中间人（包括会重签 TLS 的企业代理）只能丢包，不能读或注入，因为会话内容由钉住服务端公钥的 Noise IK 保护；Noise 之外的控制数据（确认、关闭、续传、HTTP 批次）用握手派生的密钥做 MAC，伪造的只会导致断线续传。续传凭据是持有证明，从不以明文出现在请求里（HTTP 头只有一次性 MAC）。
- **服务端中继不被设备信任**：设备只信任能力令牌签名，令牌与具体连接和具体流绑定，伪造、扩权、改目标、重放都会被设备拒绝（合规用例 A8）。
- **设备不被 agent 信任**：agent 只会拨打它自己登记过的远程转发目标；交互终端会丢弃 OSC 52（写剪贴板）序列。
- **agent 本地守护进程**：socket 位于 0700 目录，另有每次启动随机生成的令牌（0600 文件，常量时间比较）。

## 存储

- `cjs.db`：账号、agent、设备、组、注册令牌（只存 SHA-256）、授权、全权限审批、Web 会话（只存 SHA-256）。
- `audit.db`：审计事件与签名检查点，`synchronous=FULL`。
- `recordings/<session>.cast`：asciicast v2 录像（默认每个最多 512 MiB），其 SHA-256 记在 `session.end` 审计事件里。
- `noise.key` / `capability.key` / `audit.key`：0600（每次写入都强制设置）。审计公钥应在带外钉住（启动日志打印其指纹），用于离线校验导出的审计日志。
