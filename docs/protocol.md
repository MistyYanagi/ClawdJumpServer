# 协议

所有结构定义在 `crates/cjs-proto/src/lib.rs`，编码为 postcard。协议版本 `PROTO_VERSION = 2`（v2：传输层控制数据全部认证，续传密钥不再上线，见“传输控制消息认证”）。

## 分层

```
TLS (WebSocket /v1/t/ws | HTTP /v1/t/open, /v1/t/{sid}/tx, /v1/t/{sid}/rx)
  └ WireMsg::Seg{seq, data}       可续传：段在 ACK 前保留，重连后原样重发
     └ Noise 传输消息（nonce = seq，Noise_IK_25519_ChaChaPoly_BLAKE2s）
        └ 字节流（SessionIo）
           └ yamux（每连接最多 128 条流；每条流至少 256 KiB、可自动增长到约 16 MiB 的接收窗口；整个连接接收缓冲上限 48 MiB）
              └ 每条流：4 字节大端长度 + postcard 消息，单条 ≤ 1 MiB
```

## 握手

1. 客户端发送 `WireMsg::Hello{noise}`：Noise IK 第一条消息，载荷为 `Hello{version, role, ts, nonce, enroll?, info}`。
2. 服务端检查版本、时间偏差（±120 秒）、`(公钥, nonce)` 重放，然后由网关认证：按公钥查找 agent / 设备，或用一次性注册令牌注册新公钥。
3. 服务端回复 `WireMsg::Welcome{sid, noise}`，载荷为 `HandshakeReply::Welcome{principal_id, name, connection_id, signing_key, server_time}`。`signing_key` 是能力令牌签名公钥，因为它在钉住服务端的 Noise 会话内送达，所以可信。
4. 双方从握手哈希派生三把 32 字节密钥（`blake3::derive_key`）：续传密钥 `resume`、客户端→服务端控制密钥 `c2s`、服务端→客户端控制密钥 `s2c`。这些密钥从不上线。
5. 服务端在做任何密码学运算之前，按来源地址做令牌桶限速（默认突发 30 次、每秒 5 次；超限：WS 回 `Reject(limit_exceeded)`，HTTP 回 429）。握手重放缓存有上限（65536 条），按时间顺序淘汰。握手在阻塞线程上执行，不占用异步工作线程。

注册令牌格式：`cjs1.<服务端 Noise 公钥 hex>.<secret>`，服务端只存 `sha256(secret)`。

## 传输控制消息认证

Noise 传输消息之外的一切都可能被会重签 TLS 的代理看到或伪造，所以 v2 对它们全部做 MAC（带密钥的 BLAKE3，`mac = keyed_blake3(key, label || 0 || postcard(fields))`）：

| 消息 | 密钥 | 覆盖内容 |
|---|---|---|
| `Ack{n, mac}` | 发送方控制密钥 | `"ack"`, `n` |
| `Close{err, mac}` | 发送方控制密钥 | `"close"`, `err` |
| `Resume{sid, ctr, ts, ack, proof}` | `resume` | `"request"`, `(sid, "resume", ctr, ts, BLAKE3(ack 大端))` |
| `Resumed{ack, mac}` | `s2c` | `"resumed"`, `(ctr, ack)` |
| HTTP 请求头 `x-cjs-auth: <ctr>.<ts>.<hex mac>` | `resume` | `"request"`, `(sid, "tx"/"rx", ctr, ts, BLAKE3(请求体 或 ack 大端))` |
| HTTP 响应 `HttpBatch.mac` | `s2c` | `"http-resp"`, `(kind, 请求 ctr, ack, closed)` |

- **续传凭据是持有证明，不是持票人密钥**：密钥本身从不上线。每类请求（resume / tx / rx）各有一个严格递增的计数器，服务端只接受更大的计数器，`ts` 必须在 ±120 秒内，比较为常量时间。截获的请求无法重放，也无法用来保活或劫持会话。
- **未认证的消息只能断开当前链路**：MAC 不对的 `Close` / `Ack`、无法通过认证的分段、意外的消息，只会让收到方丢弃这条链路并续传，绝不会结束会话或丢弃未确认的数据。只有通过认证的 `Close` 才结束会话并带出真实原因（例如 `disabled`）。
- **未认证的拒绝**：握手阶段的 `Reject` / HTTP 非 200、续传时的 `Reject`、没有有效 MAC 的 HTTP 410，其错误码都不可信。客户端把握手阶段的这类拒绝报告为 `io`（守护进程按暂时性故障重连）；续传阶段的“会话不存在”连续 10 秒都没有认证的回答才认定会话丢失，以 `io` 结束会话（守护进程随后重新握手），在此之前只当作暂时性故障重试。
- 服务端对已关闭但尚未回收的会话（关闭后保留 10 秒）回复认证过的 `Close`，客户端因此能得知真实原因。

## 流

开流方先发送一条消息，对端回复 `OpenReply::Ok{id, session}` 或 `OpenReply::Err(ProtoError)`：

| 方向 | 首条消息 |
|---|---|
| agent → 服务端 | `OpenRequest` |
| 服务端 → 设备 | `DeviceOpen{cap: SignedCapability, req: OpenRequest}`（`device` 字段已清空） |
| 设备 → 服务端 | `OpenRequest::ForwardRConn{listener, peer}`（只允许这一种） |
| 服务端 → agent | `OpenRequest::ForwardRConn{listener, peer}` |

之后各类型的消息：

| 类型 | agent → 设备 | 设备 → agent |
|---|---|---|
| Pty | `PtyIn::Input` / `PtyIn::Resize` | `PtyOut::Output` …，`PtyOut::Exit` |
| Exec | `ExecIn::Stdin` / `StdinEof` / `Kill`；半关闭只等于 StdinEof | `ExecOut::Stdout` / `Stderr` …，`ExecOut::Exit` |
| FileGet | （无） | `Meta`、`Chunk`*、`End{sha256}` |
| FilePut | `Chunk`*、`End` | `Done{size, sha256}` |
| FileList | （无） | `Stat`、`Entries`*、`End` |
| ForwardL / Egress / ForwardRConn | 原始字节 | 原始字节 |
| ForwardR | 控制流，无数据；关闭即结束转发 | 同左 |
| Rpc | — | `RpcResponse` |

`FileGet.offset` 与 `FilePut.offset` 用于断点续传，`End` / `Done` 里的 SHA-256 始终是整个文件的。中继强制消息顺序与大小：`FileGet` 中 `Meta` 必须先于 `Chunk`，`Chunk` 总量不得超过 `Meta.size - offset`；`FilePut` 不得超过声明的 `size - offset`；违反时流以 `protocol` / `bad_request` 错误终止。

## 能力令牌

`Capability{version, id, principal, device, action, roots, full_access, issued_at, expires_at, stream, connection, target, session, net_rules}`，Ed25519 签名覆盖 `b"cjs-cap-v1" || postcard(body)`。设备拒绝：签名错误、设备不符、连接不符、流不符、动作不符、网络目标不符、过期或 TTL 超过 60 秒、无项目根且非全权限、id 重放。`net_rules` 只用于经设备出口，设备据此对解析出的地址做 SSRF 二次校验。

## 错误码

`ErrorCode::as_str()` 是稳定的字符串（JSON 输出里的 `error.code`），`exit_code()` 是 CLI 的稳定退出码（10–27）。例如 `forbidden` = 11，`audit_failure` = 16，`sandbox_unavailable` = 27。

## agent 本地守护进程协议

socket：`<配置目录>/agent.sock`（Windows：`\\.\pipe\cjs-agent-<hash>`）。客户端发送 `LocalHello{version, token}`，然后发送一条 `LocalRequest`：`Open(OpenRequest)`（之后透明拼接）、`ForwardR{req, local_host, local_port}` 或 `Status`。
