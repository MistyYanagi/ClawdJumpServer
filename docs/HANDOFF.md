# ClawdJumpServer 开发状态

计划中的全部里程碑已完成，随后做了一轮安全评审修复（见第 3 节）。`cjs-tests` 有 6 组端到端测试（pty、streams、plan_e2e、hardening、sandbox_e2e、conformance_4a 的 16 个 4A 合规用例），CI 在 Linux / macOS 上分别用 WebSocket 与 HTTP 长轮询各跑一遍；`cargo clippy --workspace --all-targets -- -D warnings` 无警告；Windows 上跑单元测试与 release 构建。

## 1. 进度

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 骨架 + `cjs-proto` | ✅ | 协议类型、错误码、请求校验 |
| M1 `cjs-mux` + `cjs-transport` | ✅ | yamux；Noise IK；WS / HTTP 长轮询；断线续传；传输 v2（控制消息认证） |
| M2 服务端核心 | ✅ | 网关（认证、注册、租约复核、握手限速）、中继、出口、RPC |
| `cjs-audit` / `cjs-authz` / `cjs-fsjail` / `cjs-sandbox` | ✅ | 见 docs/architecture.md |
| 设备端 `cjs-device` | ✅ | 能力令牌独立校验、沙箱 PTY/exec、监狱文件、转发、出口、服务安装 |
| agent `cjs` | ✅ | CLI（含 `cp -r`）、本地守护进程、SOCKS5/HTTP 代理、MCP 服务、`.cjs.toml`，见 docs/agent.md |
| REST API + `cjsctl` | ✅ | Cookie + CSRF、三权分立、两人角色审批、OpenAPI 3.1 |
| Web 控制台 | ✅ | 纯 JavaScript，内嵌在服务端二进制 |
| 部署 | ✅ | `Dockerfile`、systemd / launchd / 计划任务，见 docs/deployment.md |
| 测试、CI、文档 | ✅ | `.github/workflows/ci.yml`（Linux/macOS/Windows），`deny.toml`，`docs/` |

## 2. 与原计划不同的决定

- **多路复用用 yamux，没有自写 mux。** 可靠性放在下面一层：序号、累计确认、ACK 前保留分段、重连后重发都在 `cjs-transport/src/core.rs`；yamux 只负责流与流控（每连接 128 条流、连接接收缓冲上限 48 MiB）。
- **没有 15 分钟会话令牌。** 取而代之的是：长连接上每条流每 5 秒（以及每次管理操作后）重新决策一次（租约检查），撤销即断；设备侧每条流一个 60 秒有效的 Ed25519 能力令牌，绑定设备、连接、yamux 流 id、动作、目标以及请求本身的哈希（中继改不了命令和路径）。
- **“项目”不是独立实体。** 项目就是授权里的 `project_roots`，没有项目表、项目成员或项目级 API。
- **Web 控制台用纯 JavaScript，没有用 Leptos/WASM。** 不需要 wasm 工具链，CSP 可以是 `script-src 'self'`，供应链更小；服务端数据一律用 `textContent` 渲染。（`Cargo.toml` 里 `exclude = ["crates/cjs-web"]` 的注释是遗留。）
- **OpenAPI 文档由路由表生成**（`api::ROUTES`），没有引入 utoipa。
- **出口与本地转发都做 DNS 后地址校验**：服务端把匹配的规则签进令牌（`Capability.net_rules`），设备解析后复核。
- **加载器类环境变量直接拒绝**（`LD_*`、`DYLD_*`、`GLIBC_TUNABLES`、`MALLOC_*`），服务端和设备都校验。
- **Windows 自启动用计划任务**（`cjs-device install-service --apply` → `schtasks /SC ONLOGON`），不实现 SCM 协议。

## 3. 安全评审修复（a497500..c16b501）

- **账号 / 认证（docs/4a.md A3–A6）**：经 API 授予任何角色都变成待审批的角色变更（`role_changes` 表、`/api/v1/role-changes`、Web Approvals、`cjsctl role-changes`），须由申请人与被授予者之外的 secadmin 批准；有角色用户的凭据只能在本机 `cjs-server reset-user` 重置；新增 `user-add` / `user-role` 用于引导；最后一名 secadmin / auditor 不能被禁用或降级。登录状态原子化：TOTP 时间步用条件 UPDATE 认领，登录次数在校验前预占，按列更新代替整行写。防枚举：未知/禁用/过期/锁定统一 `invalid credentials` 且都跑一次 argon2。`__Host-` Cookie；密钥文件每次加载都强制 0600。
- **传输 v2（docs/protocol.md）**：Ack、Close、Resume/Resumed、HTTP 批次全部 MAC（握手哈希派生密钥）；续传改为持有证明（计数器 + 时间戳 + MAC），不再有持票人续传密钥；未认证的控制消息只断链路。握手前按来源地址令牌桶限速，重放缓存有界，握手放到阻塞线程；`X-Forwarded-For` 取最右侧；网关拒绝按地址聚合审计。
- **授权**：`max_sessions` 的决策与名额占用在同一把锁下原子完成。
- **审计**：校验覆盖索引列（ts/kind/actor/target/outcome/session/highlight）；导出文件可用钉住的公钥离线校验（`cjsctl audit verify --file --pubkey`）；`audit-verify` / `info` 不再悄悄生成密钥；启动日志打印审计公钥指纹。录像增量哈希、单会话上限（默认 512 MiB，达到即以 `limit_exceeded` 终止）；`FileGet` 不得超过 `Meta` 声明的大小。
- **沙箱**：Landlock 也限制读，设备配置目录不可见；不能创建设备节点；非全权限时禁止 TCP；helper 成为 subreaper，结束时杀掉所有后代，撤销会真正停止命令（SIGTERM→SIGKILL、`ExecIn::Kill`）；macOS 同样隐藏配置目录并禁 IP 网络。
- **监狱**：拒绝 FIFO 等特殊文件（不阻塞）和多硬链接文件，检查后才截断。
- **网络规则**：IP 规范化（IPv4 映射/兼容/SIIT、旧式数字写法），更多特殊网段视为敏感；本地转发的规则签进令牌，设备解析后复核（deny 规则、元数据地址需 IP 规则）。
- **agent**：`cjs proxy` 默认要求生成的凭据（`--no-auth` 可关闭，`--env-file` 写 0600 文件供 `. FILE`），并支持普通 HTTP 转发代理与 export 行；守护进程 IPC 改为双向挑战-应答，令牌不上线、退出时删除；OSC 52 过滤按数值比较并识别 C1 序列，exec 输出到终端也过滤；下载超出声明大小即停；`.cjs.toml` 查找止于 git 根/主目录并忽略他人所有或组/其他可写的文件；新增 `cjs cp -r`；MCP 新增 `cjs_forward_start/list/stop`。

## 4. 代码地图

```
crates/cjs-transport core.rs（分段、确认、重发、续传） mac.rs（控制消息 MAC） handshake.rs link.rs server.rs client.rs profile.rs
crates/cjs-server    state.rs（共享状态、在线注册表、决策封装） gateway.rs（认证、连接、租约检查、令牌签发）
                     relay.rs（逐条解码的中继、录像、远程转发） egress.rs（服务端出口与 SSRF）
                     api.rs（REST） accounts.rs db.rs web.rs keys.rs main.rs web/（控制台）
crates/cjs-device    lib.rs（连接循环、令牌校验、分发、环境白名单、沙箱策略） pty.rs exec.rs files.rs net.rs service.rs
crates/cjs-sandbox   linux.rs（Landlock + subreaper） macos.rs（SBPL） windows.rs（AppContainer + Job）
crates/cjs-agent     conn.rs local.rs（守护进程与 Opener） ops.rs（含 cp -r） proxy.rs term.rs（OSC 52 过滤） mcp.rs project.rs
crates/cjs-ctl       main.rs
crates/cjs-tests     lib.rs（夹具） tests/{pty,streams,plan_e2e,hardening,sandbox_e2e,conformance_4a}.rs
```

## 5. 踩过的坑

- 终端会回显输入：测试里等待的标记必须由 shell 计算出来（例如 `$((40+2))`），否则会匹配到回显。
- 某些 pty（如 `script`）报告终端尺寸 0x0，客户端需回退到 80x24。
- 设备端上传后的校验和要用新的只读句柄计算，写句柄是只写的。
- 一次性密钥（初始口令、注册令牌）在 Web 控制台重新渲染后必须保留（`state.flash`）。
- 用 `pgrep -f` 杀进程时模式会匹配到执行它的 shell 本身。
- `Cargo.lock` 里的依赖需要 Rust 1.88（`rust-version` 已改为 1.88；Dockerfile 用 1.88）。
- 多个 git worktree 不能共用一个 `CARGO_TARGET_DIR`：工作区内 crate 的产物名与路径无关，会互相覆盖，编出另一份源码。
- exec 流被正常关闭只表示 stdin 结束；要结束命令必须发 `ExecIn::Kill`（中继中止会话时会发），否则撤销后进程仍在设备上运行。
- 沙箱 helper 不能直接 `exec` 命令：它要作为 subreaper 留下来，会话结束时杀掉整棵进程树（`setsid`、二次 fork 的后台任务）。

## 6. 已知限制与后续

- macOS sandbox-exec 与 Windows AppContainer 只在 CI 上验证过，需要在真实机器上手工验证。
- Windows 没有端到端测试：`crates/cjs-tests` 整体是 `cfg(unix)`。
- 审计头部哈希需要定期推送到外部存档（WORM 或第三方时间戳），否则连同检查点一起截断无法自检发现。
- 录像包含键入的输入（包括在终端里输入的口令）；可考虑可选不记录输入事件。
- sysadmin 经 API 创建用户时会拿到其初始口令和 TOTP 密钥。
- 没有全局内存预算：握手限速、yamux 缓冲等都是按来源地址 / 按连接计算。
- CI 里加一个 MSRV（1.88）任务。
- 文件上传直接写目标文件（续传依赖这一点），中途失败会留下不完整的文件。
- 授权时间窗用固定 UTC 偏移，不跟随夏令时。
- Web 控制台里用户角色编辑和组成员增删仍用浏览器自带的 `prompt()`。
