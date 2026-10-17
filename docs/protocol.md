# 协议

所有结构定义在 `crates/cjs-proto/src/lib.rs`，编码为 postcard。协议版本 `PROTO_VERSION = 1`。

## 分层

```
TLS (WebSocket /v1/t/ws | HTTP /v1/t/open, /v1/t/{sid}/tx, /v1/t/{sid}/rx)
  └ WireMsg::Seg{seq, data}       可续传：段在 ACK 前保留，重连后原样重发
     └ Noise 传输消息（nonce = seq，Noise_IK_25519_ChaChaPoly_BLAKE2s）
        └ 字节流（SessionIo）
           └ yamux（每连接最多 512 条流，接收窗口总上限 256 MiB）
              └ 每条流：4 字节大端长度 + postcard 消息，单条 ≤ 1 MiB
```

## 握手

1. 客户端发送 `WireMsg::Hello{noise}`：Noise IK 第一条消息，载荷为 `Hello{version, role, ts, nonce, enroll?, info}`。
2. 服务端检查版本、时间偏差（±120 秒）、`(公钥, nonce)` 重放，然后由网关认证：按公钥查找 agent / 设备，或用一次性注册令牌注册新公钥。
3. 服务端回复 `WireMsg::Welcome{sid, noise}`，载荷为 `HandshakeReply::Welcome{principal_id, name, connection_id, signing_key, server_time}`。`signing_key` 是能力令牌签名公钥，因为它在钉住服务端的 Noise 会话内送达，所以可信。
4. 续传密钥由双方从握手哈希派生，从不下发；断线后客户端发送 `Resume{sid, secret, ack}`。

注册令牌格式：`cjs1.<服务端 Noise 公钥 hex>.<secret>`，服务端只存 `sha256(secret)`。

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

`FileGet.offset` 与 `FilePut.offset` 用于断点续传，`End` / `Done` 里的 SHA-256 始终是整个文件的。

## 能力令牌

`Capability{version, id, principal, device, action, roots, full_access, issued_at, expires_at, stream, connection, target, session, net_rules}`，Ed25519 签名覆盖 `b"cjs-cap-v1" || postcard(body)`。设备拒绝：签名错误、设备不符、连接不符、流不符、动作不符、网络目标不符、过期或 TTL 超过 60 秒、无项目根且非全权限、id 重放。`net_rules` 只用于经设备出口，设备据此对解析出的地址做 SSRF 二次校验。

## 错误码

`ErrorCode::as_str()` 是稳定的字符串（JSON 输出里的 `error.code`），`exit_code()` 是 CLI 的稳定退出码（10–27）。例如 `forbidden` = 11，`audit_failure` = 16，`sandbox_unavailable` = 27。

## agent 本地守护进程协议

socket：`<配置目录>/agent.sock`（Windows：`\\.\pipe\cjs-agent-<hash>`）。客户端发送 `LocalHello{version, token}`，然后发送一条 `LocalRequest`：`Open(OpenRequest)`（之后透明拼接）、`ForwardR{req, local_host, local_port}` 或 `Status`。
