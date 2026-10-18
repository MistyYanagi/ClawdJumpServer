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
- **agent 本地守护进程**：socket 位于 0700 目录（Windows 为命名管道），另有每次启动随机生成的令牌（`daemon.token`，0600，守护进程退出时删除）。双方用它做挑战-应答，守护进程先证明，令牌从不上线，连到冒名 socket / 管道的客户端不会泄露任何东西。
- **agent 本地代理**：`cjs proxy` 默认要求随机生成的凭据（SOCKS5 用户名/口令、HTTP `Proxy-Authorization`），本机其他进程不能借用 agent 身份；`--no-auth` 需显式指定。
- **`.cjs.toml` 不被盲目信任**：向上查找止于 git 仓库根或主目录，忽略属于他人或组/其他用户可写的文件。

## 设备上的隔离

每条 shell / exec 流都在两层隔离之下（全权限获批时两层都解除）：

**项目监狱（`cjs-fsjail`）**：文件读写、列目录、工作目录都在授权的项目根之下用 cap-std 解析，拒绝 `..`、越界符号链接、UNC/设备路径、备用数据流和保留设备名。FIFO 等特殊文件直接拒绝（不会阻塞），有多个硬链接的文件也拒绝（防止借硬链接改写项目外的文件）；上传时先检查再截断。

**操作系统沙箱（`cjs-sandbox`）**：设备把自己作为 helper 重新执行（`cjs-device __cjs_sandbox ...`），策略为：

| | 规则 |
|---|---|
| 读 / 执行 | 整个系统可读，**设备配置目录除外**（身份密钥、profile、其他会话的临时目录）；不授予指向它的链接 |
| 写 | 只有项目根和本会话私有临时目录（`TMPDIR`），不能创建块/字符设备节点；`/dev/pts` 下只有本会话自己的 pty 可写 |
| 网络 | 不能 TCP bind/connect（出网走服务端出口：`cjs proxy`、转发）；路径名 Unix socket 只能在可写目录内连接 |
| 进程 | `no_new_privs`、`RLIMIT_NOFILE` 上限；不能向沙箱外进程发信号、不能连沙箱外的抽象 socket |
| 生命周期 | helper 是 child subreaper，命令结束或会话被终止时杀掉所有后代（`setsid`、两次 fork 的后台任务也逃不掉）；设备先发 SIGTERM，3 秒后 SIGKILL；中继中止 exec 时向设备发 `ExecIn::Kill` |

平台实现：Linux 为 Landlock（读写执行、ABI 4+ 的 TCP、ABI 6+ 的信号/抽象 socket 隔离、ABI 9 的 Unix socket 限制；旧内核部分执行，内核不支持 Landlock 时拒绝运行）；macOS 为 `sandbox-exec` 生成的 SBPL（同样隐藏配置目录、禁止 IP 网络）；Windows 为 AppContainer（无网络能力、无用户配置文件访问，只给可写目录授权）+ Job Object（helper 退出即杀整棵进程树）。沙箱不可用时报 `sandbox_unavailable`，不会退化为不隔离。设备每次启动把配置目录重新收紧为 0700/0600。环境变量为白名单，加载器类变量（`LD_*`、`DYLD_*`、`GLIBC_TUNABLES`、`MALLOC_*`）一律拒绝。

**网络目标的二次校验**：本地转发与经设备出口时，服务端把匹配的规则签进能力令牌（`net_rules`），设备在 DNS 解析后复核地址，IP 先规范化（IPv4 映射/兼容/SIIT 地址、旧式数字 IPv4 写法）。出口：私网、环回、链路本地、元数据等敏感地址需要以 IP 明确列出的规则（`ip_allowed`）。本地转发（目标已由授权的 `forward_targets` 限定）：命中 deny 规则的地址拒绝，云元数据地址必须有以 IP 明确列出它的规则（`forward_ip_allowed`）。服务端自己的出口同样在解析后校验，并只连接已校验的地址。

## 存储

- `cjs.db`：账号、agent、设备、组、注册令牌（只存 SHA-256）、授权、全权限审批、Web 会话（只存 SHA-256）。
- `audit.db`：审计事件与签名检查点，`synchronous=FULL`。
- `recordings/<session>.cast`：asciicast v2 录像（默认每个最多 512 MiB），其 SHA-256 记在 `session.end` 审计事件里。
- `noise.key` / `capability.key` / `audit.key`：0600（每次写入都强制设置）。审计公钥应在带外钉住（启动日志打印其指纹），用于离线校验导出的审计日志。
