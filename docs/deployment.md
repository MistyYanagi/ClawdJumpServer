# 部署

## 构建

```sh
cargo build --release --bin cjs-server --bin cjs-device --bin cjs --bin cjsctl
```

需要 Rust 1.85+。Web 控制台是纯静态文件，编译时打包进 `cjs-server`，不需要额外工具链。

## 服务端

```sh
cjs-server --data /var/lib/cjs-server init --admin admin --hostname jump.example.com
cjs-server --data /var/lib/cjs-server run --listen 0.0.0.0:8443
```

`init` 生成三把密钥（Noise、能力令牌、审计）、自签 TLS 证书（`tls/cert.pem`）和首个管理员（sysadmin + secadmin），并打印其口令与 TOTP 密钥（用认证器 App 导入 otpauth 链接）。请尽快：

1. 创建一名 auditor 和第二名 secadmin（双人规则需要）；
2. 用 `cjsctl passwd` 修改初始口令。

TLS：默认使用 `tls/cert.pem` 与 `tls/key.pem`，也可以用 `--tls-cert/--tls-key` 指定正式证书。放在 TLS 终结的反向代理之后时使用 `--no-tls --trust-forwarded-for`（反向代理需要支持 WebSocket；不支持时客户端自动降级到 HTTP 长轮询）。

只需要开放一个端口：`/v1/t/*` 是 agent / 设备传输，`/api/v1/*` 是 REST API（OpenAPI：`/api/v1/openapi.json`），`/` 是 Web 控制台。

其他命令：`cjs-server token --kind device --name box1`（离线签发令牌）、`cjs-server audit-verify`、`cjs-server info`。

systemd 示例：

```ini
[Service]
User=cjs
ExecStart=/usr/local/bin/cjs-server --data /var/lib/cjs-server run
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/cjs-server
PrivateTmp=yes
```

备份 `/var/lib/cjs-server` 整个目录（包括密钥）。建议定期把 `cjsctl audit verify` 输出的 `head` 存到外部系统。

## 管理（cjsctl）

```sh
cjsctl login --server https://jump.example.com:8443 --name admin --ca cert.pem
cjsctl users create aud1 --roles auditor
cjsctl token create --kind device --name build-box
cjsctl token create --kind agent --name claude-1 --owner alice
cjsctl grants put build build.json
cjsctl full-access request --agent claude-1 --device build-box --reason "..." --duration 3600
cjsctl audit verify
```

授权示例（`build.json`）：

```json
{
  "subject": {"type": "principal", "id": "claude-1"},
  "target": {"type": "device", "id": "build-box"},
  "actions": ["shell", "exec", "file_read", "file_write", "forward_local"],
  "project_roots": ["/srv/work/project"],
  "forward_targets": [{"host": "127.0.0.1", "ports": ["5432"]}],
  "max_sessions": 8,
  "expires_at": 1798761600
}
```

服务端出口：`"target": {"type": "server"}`，`"actions": ["egress"]`，`"egress": [{"host": "*.github.com", "ports": [443]}]`，`project_roots` 留空。

## 设备

```sh
cjs-device enroll --server https://jump.example.com:8443 --token cjs1.... --ca cert.pem
cjs-device probe              # 检查沙箱
cjs-device install-service --apply --user cjs   # systemd / launchd / 计划任务
```

设备进程以普通用户运行即可；它能让 agent 写入的范围只是授权里的项目根。Linux 需要支持 Landlock 的内核（5.13+），否则 shell 与命令会被拒绝（除非批准了全权限）。

## agent

```sh
cjs enroll --server https://jump.example.com:8443 --token cjs1.... --ca cert.pem
cjs daemon &                  # 可选：复用一条连接
cjs devices
cjs exec -d build-box --json -- make test
cjs shell -d build-box
cjs cp --resume ./big.tar build-box:big.tar
cjs forward -d build-box -L 15432:127.0.0.1:5432
cjs proxy --listen 127.0.0.1:1080      # SOCKS5 + HTTP CONNECT
cjs mcp                                # MCP stdio 服务
```

项目目录里的 `.cjs.toml` 可以设置默认设备和远端工作目录：

```toml
device = "build-box"
cwd = "/srv/work/project"
```

云端 agent 若处于会重签 TLS 的代理之后：客户端信任系统根证书（遵守 `SSL_CERT_FILE`）、Mozilla 根证书和 `--ca`，并遵守 `HTTPS_PROXY` / `NO_PROXY`。会话内容仍由钉住服务端公钥的 Noise 加密。

MCP 客户端配置示例：

```json
{"mcpServers": {"cjs": {"command": "cjs", "args": ["mcp"]}}}
```
