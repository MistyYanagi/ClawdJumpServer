# ClawdJumpServer 开发状态

计划中的全部里程碑已完成并合并到 `main`。`cargo test --workspace` 全部通过（含 9 个端到端测试与 11 个 4A 合规测试，WS 与 HTTP 两种传输各跑一遍），`cargo clippy --workspace --all-targets -- -D warnings` 无警告，`cjs-agent` 与 `cjs-device` 已交叉编译检查 Windows 目标。

## 1. 进度

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 骨架 + `cjs-proto` | ✅ | 协议类型、错误码、请求校验 |
| M1 `cjs-mux` + `cjs-transport` | ✅ | yamux；Noise IK；WS / HTTP 长轮询；断线续传；客户端 profile 与注册 |
| M2 服务端核心 | ✅ | 网关（认证、注册、租约复核）、中继、出口、RPC |
| `cjs-audit` / `cjs-authz` / `cjs-fsjail` / `cjs-sandbox` | ✅ | 见 docs/architecture.md |
| 设备端 `cjs-device` | ✅ | 能力令牌独立校验、沙箱 PTY/exec、监狱文件、转发、出口、服务安装 |
| agent `cjs` | ✅ | CLI、本地守护进程、SOCKS5/HTTP 代理、MCP 服务、`.cjs.toml` |
| REST API + `cjsctl` | ✅ | Cookie + CSRF、三权分立、OpenAPI 3.1 |
| Web 控制台 | ✅ | 纯 JavaScript（见第 2 节），内嵌在服务端二进制 |
| 测试 | ✅ | `cjs-tests`：pty / streams / conformance_4a |
| CI、文档 | ✅ | `.github/workflows/ci.yml`（Linux/macOS/Windows），`deny.toml`，`docs/` |

## 2. 与原计划不同的决定

- **Web 控制台用纯 JavaScript，没有用 Leptos/WASM。** 不需要 wasm 工具链和 trunk，CSP 可以做到 `script-src 'self'`（不需要 `wasm-unsafe-eval`），供应链更小。所有服务端数据用 `textContent` 渲染。
- **OpenAPI 文档由路由表生成**（`api::ROUTES`），没有引入 utoipa。
- **能力令牌绑定到 yamux 流 id**（`Capability.stream`），设备校验，防止令牌被挪用到其他流。
- **经设备出口也做 DNS 后地址校验**：服务端把匹配的出口规则签进令牌（`Capability.net_rules`），设备解析后用 `ip_allowed` 复核。原交接文档里的这条已知限制已解决。
- **加载器类环境变量直接拒绝**（`LD_*`、`DYLD_*`、`GLIBC_TUNABLES`、`MALLOC_*`）：它们可能在沙箱生效之前就在 helper 进程里执行代码。服务端和设备都校验。
- **Windows 服务**用计划任务（`schtasks /SC ONLOGON`）实现开机自启，不实现 SCM 协议。

## 3. 代码地图（新增部分）

```
crates/cjs-server  state.rs（共享状态、在线注册表、决策封装） gateway.rs（认证、连接、租约检查、令牌签发）
                   relay.rs（逐条解码的中继、录像、远程转发） egress.rs（服务端出口与 SSRF）
                   api.rs（REST） web.rs（静态文件、安全响应头） keys.rs  main.rs  web/（控制台）
crates/cjs-device  lib.rs（连接循环、令牌校验、分发、环境白名单） pty.rs exec.rs files.rs net.rs service.rs
crates/cjs-agent   conn.rs（直连、远程转发回连） local.rs（守护进程与 Opener） ops.rs proxy.rs term.rs mcp.rs project.rs
crates/cjs-ctl     main.rs
crates/cjs-tests   lib.rs（测试夹具） tests/{pty,streams,conformance_4a}.rs
```

## 4. 踩过的坑（新增）

- 终端会回显输入：测试里等待的标记必须由 shell 计算出来（例如 `$((40+2))`），否则会匹配到回显。
- 某些 pty（如 `script`）报告终端尺寸 0x0，客户端需回退到 80x24。
- 设备端上传后的校验和要用新的只读句柄计算，写句柄是只写的。
- 一次性密钥（初始口令、注册令牌）在 Web 控制台重新渲染后必须保留（`state.flash`）。
- 用 `pgrep -f` 杀进程时模式会匹配到执行它的 shell 本身。

## 5. 后续可做

- 在真实 macOS / Windows 机器上手工验证沙箱行为（CI 只跑测试）。
- 审计头部哈希定期推送到外部存档（WORM 存储或第三方时间戳）。
- 录像中的输入事件可选择不记录。
