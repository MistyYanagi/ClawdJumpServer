# ClawdJumpServer 交接文档

分支：`claude/sleepy-hawking-y3rtzk`（基于 `claude/clawdjumpserver-implementation-a2fg2k` 的 M0 提交继续）
最后一个可用提交：`15efbed`。工作区干净，`cargo test --workspace` 共 53 个测试全部通过，`cargo clippy --workspace --all-targets -- -D warnings` 无警告。
尚未合并到 `main`，也没有开 PR。

## 1. 进度总览

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 骨架 + `cjs-proto` | ✅ | 协议类型、错误码、能力令牌结构 |
| M1 `cjs-mux` + `cjs-transport` | ✅ | yamux 多路复用；Noise IK；WS / HTTP 长轮询；断线续传 |
| M2 服务端核心 | 🟡 部分完成 | `db.rs`、`accounts.rs`、`error.rs` 已完成；gateway 尚未写 |
| `cjs-audit` | ✅ | 哈希链、签名检查点、asciicast 录像 |
| `cjs-authz` | ✅ | 授权规则、PDP、出口与 SSRF 规则、能力令牌、双人审批 |
| `cjs-fsjail` | ✅ | 基于 cap-std 的项目目录监狱 |
| `cjs-sandbox` | ✅（Linux 实测） | Landlock 已实测生效；macOS 与 Windows 只通过交叉编译检查 |
| M3–M9 其余部分 | ❌ | 见第 4 节 |

## 2. 关键设计决策（已落地）

- **多路复用库选 `yamux` 0.14.1**（libp2p 的 rust-yamux）：下载约 3000 万次，2026-09 仍有发布，带 per-stream 窗口自动调节，历史安全公告已修复。没有选 `h2`（HTTP 语义多余），也没有选 `tokio-yamux` 和 `async-smux`（用户量小很多）。M0 里自研的 `Frame` 协议已删除。
- **传输分层**：WS 或 HTTP → `WireMsg::Seg{seq,data}` → Noise 消息（nonce = seq，使用 `snow::StatelessTransportState`）→ 字节流（`SessionIo`）→ yamux → 每个流上的 postcard 消息（4 字节大端长度前缀，单条最大 1 MiB）。
  - 段在收到 ACK 之前一直保留，重连后原样重发，不会丢数据也不会重复。
  - 续传密钥由 Noise 握手哈希派生，从不明文下发。中间人即使解开 TLS，最多只能丢弃流量（DoS），无法读取或注入内容。
  - 服务端检查握手时间戳偏差（±120s）和 (key, nonce) 重放。
- **流协议**：开流方先发送 `OpenRequest`（Agent → 服务端）或 `DeviceOpen{cap, req}`（服务端 → 设备），对端回复 `OpenReply::Ok{id, session}` 或 `OpenReply::Err`。`ForwardR` 的 `id` 同时作为监听器 id，设备回连时放在 `ForwardRConn{listener}` 里。
- **身份**：客户端的 Noise X25519 静态公钥就是身份（计划里写的是 Ed25519，实际用 Noise 静态密钥代替）。首次连接在 `Hello.enroll` 中携带一次性令牌；令牌格式为 `cjs1.<服务端公钥hex>.<secret>`，库里只存 secret 的 sha256。
- **能力令牌**：Ed25519 签名，TTL 60s，绑定设备 id、设备连接 id、动作、网络目标和项目根。设备端 `CapVerifier` 会再次校验，并做 id 防重放。
- **审计**：每条事件存储的是被哈希的那份原始 JSON；`hash_n = BLAKE3(hash_{n-1} || body)`；每 100 条（以及手动调用时）用 Ed25519 签名一次检查点；`append` 失败时调用方必须拒绝操作（fail-closed）。`inject_failure()` 用于合规测试。
- **沙箱**：
  - Linux：设备以 `<exe> __cjs_sandbox --write DIR.. -- CMD` 重新执行自身，施加 Landlock（只限制写，放开 `IoctlDev`），设置 `no_new_privs` 并禁用 core dump，然后 exec。内核不支持 Landlock 时拒绝运行。
  - macOS：用 `sandbox-exec` 加载生成的 SBPL 配置。
  - Windows：AppContainer（无任何 capability）+ Job Object `KILL_ON_JOB_CLOSE`。
  - `cjs-sandbox` 是唯一允许 `unsafe` 的 crate，且仅用于 Windows FFI。
- **服务端存储**：rusqlite（bundled），用 `PRAGMA user_version` 做迁移，所有访问经过 `Mutex<Connection>`。审计库与业务库分为两个 SQLite 文件。

## 3. 代码地图

```
crates/cjs-proto      协议类型（WireMsg、OpenRequest/OpenReply、Capability、各流的消息）
crates/cjs-mux        yamux 驱动任务 + MuxHandle::open / 入站接收器；read_msg / write_msg 帧工具
crates/cjs-transport  core.rs（seq/ack/重发/Noise） io.rs（SessionIo） link.rs（WS 泵）
                      server.rs（axum 路由：/v1/t/ws、/v1/t/open、/v1/t/{sid}/tx、/v1/t/{sid}/rx）
                      client.rs（connect、自动降级、重连） tls.rs（根证书、HTTPS_PROXY CONNECT） keys.rs
crates/cjs-audit      lib.rs（AuditLog、verify、export） recording.rs（asciicast v2）
crates/cjs-authz      model.rs（Role、Grant、FullAccess） net.rs（NetRule、SSRF） pdp.rs（decide） capability.rs
crates/cjs-fsjail     Jail::{new, resolve, open_read, open_write, list, cwd}
crates/cjs-sandbox    lib.rs（wrap、helper_main、probe） linux.rs  macos.rs  windows.rs  bin/cjs-sandbox-helper.rs
crates/cjs-server     db.rs（全部表与 CRUD） accounts.rs（argon2id、TOTP、锁定、login） error.rs（ApiError）
crates/cjs-agent / cjs-device / cjs-ctl / cjs-tests   仍是 M0 的占位文件
```

## 4. 剩余工作（建议顺序）

1. **服务端 gateway**：实现 `cjs_transport::Authenticator`（按公钥查 agent/device，处理注册令牌，检查账号状态和负责人状态，审计成功与失败）；接入循环为每个连接启动 yamux（Server 模式）并登记在线连接；定期复核租约，账号被禁用时立即断开会话（`SessionHandle::close`）。
2. **服务端 relay**：读取 `OpenRequest` → `cjs_authz::decide` → 写审计（失败即拒绝）→ 签发能力令牌 → 向设备开流并发送 `DeviceOpen` → 按 StreamKind 中继：PTY 录像、exec 摘要、文件的大小与 sha256、TCP 字节计数 → 写会话结束审计。另外还要处理 `ForwardR` 监听器注册表、`Rpc`（WhoAmI、ListDevices），以及服务端出口（DNS 在服务端解析，之后用 `net::ip_allowed` 二次校验）。
3. **服务端 `main.rs`**：`init`（生成三把密钥和首个管理员，打印密码和 otpauth）和 `run`（axum + axum-server rustls，监听单一端口）。`cjs-server` 的 `[[bin]]` 已从 Cargo.toml 中移除，补上 `main.rs` 时要一并加回去。
4. **`cjs-device`**：连接与重连，校验能力令牌，用 portable-pty 跑 PTY，exec，用 fsjail 做文件读写，ForwardL/R，出口节点；`main` 开头要处理 `__cjs_sandbox` 参数；安装为服务（systemd、launchd、Windows Service）。
5. **`cjs-agent`（bin `cjs`）**：守护进程监听 Unix socket 或命名管道，本地连接直接按流协议拼接到 mux 流上；子命令 shell、exec `--json`、cp、ls、forward -L/-R、proxy（SOCKS5 + HTTP CONNECT）、mcp、devices；读取 `.cjs.toml`。
6. **REST API + `cjsctl`**：Cookie 会话配合 CSRF、SameSite=Strict 和 CSP；按三种角色做接口鉴权；OpenAPI 文档。
7. **`cjs-web`**：Leptos CSR，通过 rust-embed 打进服务端二进制。本机已装好 `trunk` 和 `wasm32-unknown-unknown`。
8. **测试**：`tests/conformance_4a.rs` 覆盖计划中的 11 条合规用例；e2e 测试用 WS 和 HTTP 各跑一遍。
9. **收尾**：`deny.toml`、`.github/workflows/ci.yml`（三平台矩阵）、`docs/`（架构、协议、4A 规范、部署），然后开 PR 合并到 `main`。

## 5. 踩过的坑

- **WS 泵死锁**：读循环和写循环必须并发运行（`link.rs` 中用 `select!` 同时跑 reader 和 writer）。如果单线程先发一批段再去读，双方的 TCP 缓冲区都会被写满，导致死锁。
- **`watch` 的 Sender 被提前 drop**：客户端的 `superseded` 通道如果 Sender 被丢弃，`changed()` 会立即返回 Err，链路会被误判为被接管，陷入不停重连。`ws_keeper` 里必须持有 `_never_tx`。
- **Nagle 算法**：服务端要设置 `TCP_NODELAY`，否则 ACK 这类小帧会和延迟确认叠加，出现约 40ms 的卡顿。axum 0.8 的写法是 `axum::serve(ListenerExt::tap_io(l, |t| { let _ = t.set_nodelay(true); }), app)`。
- **totp-rs 5**：带 issuer 和 account 的 `TOTP::new` 以及 `get_url` 需要开启 `otpauth` feature（已加入工作区依赖）。
- **landlock 0.4**：`LandlockStatus::current()` 是私有的。可用性探测的做法是在一次性线程里真正施加一个规则集（Landlock 和 `no_new_privs` 都只作用于当前线程）。
- **跨平台检查**：已安装 `x86_64-pc-windows-gnu` 和 `x86_64-apple-darwin` 的 std，可以用 `cargo clippy --target <t> -p cjs-sandbox` 检查编译。
- **测试输出**：跑测试时不要把输出接到 `grep`，否则测试卡住时什么都看不到。应当加 `timeout` 并逐个测试运行。

## 6. 常用命令

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all            # rustfmt.toml: max_width = 110
cargo test -p cjs-sandbox --test enforce -- --nocapture   # Landlock 实测
cargo clippy -p cjs-sandbox --target x86_64-pc-windows-gnu -- -D warnings
```

## 7. 已知限制

- Windows AppContainer 与 macOS sandbox-exec 的实际行为尚未在对应系统上验证。
- 经由设备出口时，SSRF 只校验名称规则；设备端解析出的内网 IP 不会被二次校验。
- 审计日志若连同全部检查点一起被截断，自身无法发现，需要把头部哈希定期导出到外部存档。
