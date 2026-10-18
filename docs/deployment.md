# 部署

## 构建

```sh
cargo build --release --locked --bin cjs-server --bin cjs-device --bin cjs --bin cjsctl
```

工作区声明 `rust-version = 1.85`，但 `Cargo.lock` 中锁定的依赖（`icu_*`、`time`、`sha2 0.11`）需要 **Rust 1.88+**。Web 控制台是纯静态文件，编译时打包进 `cjs-server`，不需要额外工具链。

## 服务端

```sh
cjs-server --data /var/lib/cjs-server init --admin admin --hostname jump.example.com
cjs-server --data /var/lib/cjs-server run --listen 0.0.0.0:8443
```

`--data`（环境变量 `CJS_DATA`，默认 `/var/lib/cjs-server`）对所有子命令有效；`--listen` 也可用 `CJS_LISTEN`。`--hostname` 可重复，用于自签证书的 SAN（默认 `localhost`）。

`init` 生成三把密钥（`noise.key`、`capability.key`、`audit.key`，0600）、自签 TLS 证书（`tls/cert.pem`、`tls/key.pem`，已存在则不覆盖）和首个管理员（sysadmin + secadmin），打印其口令与 TOTP 密钥（用认证器 App 导入 otpauth 链接）。已有用户时 `init` 拒绝执行；`run` 在未初始化或审计链校验失败时拒绝启动。

### 引导管理员

职责分离要求 secadmin 与 auditor 由不同的人担任，而经 API 授予任何角色都需要**另一名** secadmin 批准。只有一个初始管理员时，在服务器本机直接创建（不需要审批，但写审计，actor 为 `system:cli`）：

```sh
cjs-server user-add audit1 --roles auditor        # 打印初始口令与 TOTP 密钥
cjs-server user-add sec2 --roles secadmin
cjs-server user-role admin sysadmin               # 完整替换角色集合（逗号分隔；省略则清空）
cjs-server reset-user sec2                        # 重置口令与 TOTP（任何用户，含管理员）
```

各自登录后用 `cjsctl passwd` 修改初始口令。之后通过 API 授予角色走两人审批：`cjsctl users roles <user> secadmin` 生成待审批变更，另一名 secadmin 用 `cjsctl role-changes list / approve <id>` 批准（Web 控制台 Approvals 页同理）。持有角色的用户只能在本机用 `reset-user` 重置凭据。

### 钉住审计公钥

`run` 启动时在日志中打印 `audit_key`（hex）与 `audit_fingerprint`（`server keys (pin the audit key out of band)`），`cjs-server info` / `cjsctl info` 也会输出审计公钥。把它记录到服务器之外（密码管理器、工单、纸面）。审计员导出后离线校验，不信任文件里自带的公钥：

```sh
cjsctl audit export -o audit.jsonl
cjsctl audit verify --file audit.jsonl --pubkey <hex 或含 hex 的文件>
```

能同时改写 `audit.key` 与 `audit.db` 的人可以重签检查点，所以服务端自检（`cjs-server audit-verify`、启动时校验）不能代替这一步。建议定期把 `cjsctl audit verify` 输出中的 `head` 也存到外部系统，防止整段截断。

### TLS 与端口

默认使用 `<data>/tls/cert.pem` 与 `<data>/tls/key.pem`，也可以用 `--tls-cert/--tls-key` 指定正式证书（PEM，证书链 + 私钥）。放在 TLS 终结的反向代理之后时使用 `--no-tls --trust-forwarded-for`（反向代理需要支持 WebSocket；不支持时客户端自动降级到 HTTP 长轮询）。`--trust-forwarded-for` 取 `X-Forwarded-For` 最右侧的地址，只能在可信代理之后使用。会话内容始终由 Noise 端到端加密，与 TLS 是否终结在代理无关。

只需要开放一个端口：`/v1/t/*` 是 agent / 设备传输，`/api/v1/*` 是 REST API（OpenAPI：`/api/v1/openapi.json`，无需登录），`/` 是 Web 控制台。

其他命令：`cjs-server token --kind device --name box1 [--owner U] [--ttl 秒]`（离线签发注册令牌）、`cjs-server audit-verify`（退出码 2 表示校验失败）、`cjs-server info`（密钥缺失时报错，不会生成新密钥）。

### systemd

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

收到 SIGTERM 时服务端先写一个签名检查点再退出。

## Docker

仓库根目录的 `Dockerfile` 是两阶段构建：`rust:1.88-bookworm` 里执行 `cargo build --release -p cjs-server --locked`，运行镜像为 `debian:bookworm-slim`，以 uid/gid 10001（`cjs`）运行，数据卷 `/var/lib/cjs-server`，暴露 8443，健康检查请求 `/api/v1/openapi.json`（先 HTTPS 后 HTTP）。入口是 `cjs-server`，默认参数 `run`。

```sh
docker build -t cjs-server .

# 初始化（一次）；记下打印的管理员口令与 TOTP 密钥
docker run --rm -v cjs-data:/var/lib/cjs-server cjs-server \
  init --admin admin --hostname jump.example.com

# 运行
docker run -d --name cjs --restart unless-stopped -p 8443:8443 \
  -v cjs-data:/var/lib/cjs-server cjs-server

# 引导其他管理员、查看审计公钥
docker exec cjs cjs-server user-add audit1 --roles auditor
docker exec cjs cjs-server user-add sec2 --roles secadmin
docker logs cjs 2>&1 | grep audit_fingerprint
```

- **数据卷**：命名卷会继承镜像中目录的属主（10001）。用宿主目录绑定挂载时先 `chown -R 10001:10001 /srv/cjs-data`；服务端会把数据目录收紧为 0700。
- **正式证书**：只读挂载证书目录，私钥需对 uid 10001 可读。Let's Encrypt 的 `live/` 是指向 `archive/` 的符号链接，要挂载整个 `/etc/letsencrypt` 或复制出真实文件：

  ```sh
  docker run -d --name cjs -p 443:8443 -v cjs-data:/var/lib/cjs-server \
    -v /etc/cjs-tls:/tls:ro cjs-server \
    run --tls-cert /tls/fullchain.pem --tls-key /tls/privkey.pem
  ```

  证书更新后需要重启容器（证书只在启动时加载）。
- **反向代理之后**：`run --no-tls --trust-forwarded-for`，只把端口发布到代理可达的地址（例如 `-p 127.0.0.1:8443:8443`）。健康检查会自动改用 HTTP。监听端口改动（`CJS_LISTEN`）时需要用 `--health-cmd` 覆盖健康检查。
- 在运行中的容器里执行 `user-add` 等本机命令会与服务端并发写同一个审计库；若偶尔报数据库忙，重试即可（审计写失败时操作被拒绝，不会留下半条记录）。

## 备份与恢复

需要备份整个数据目录：`cjs.db`、`audit.db`（均为 WAL 模式，连同 `-wal` / `-shm` 文件）、`recordings/`、三把密钥和 `tls/`。丢失 `noise.key` 意味着所有 agent 和设备都要重新注册（它们钉住了服务端公钥）；丢失 `audit.key` 后旧审计日志仍可用钉住的公钥离线校验，但服务端无法继续签名该链。

最简单一致的方法是短暂停机（SIGTERM 会先写检查点）：

```sh
docker stop cjs
docker run --rm -v cjs-data:/data:ro -v "$PWD":/backup debian:bookworm-slim \
  tar -C /data -czf /backup/cjs-$(date +%F).tgz .
docker start cjs
```

不停机时，用 `sqlite3 cjs.db ".backup 'cjs.bak'"`（`audit.db` 同理）复制数据库，再复制其余文件。备份包含全部私钥，应加密并限制访问。恢复后启动时会重新校验审计链；另外用钉住的审计公钥对导出做一次离线校验。

## 管理（cjsctl）

```sh
cjsctl login --server https://jump.example.com:8443 --name admin --ca cert.pem
cjsctl users create alice                         # 无角色用户（agent 负责人）
cjsctl users create aud2 --roles auditor          # 生成待审批的角色变更
cjsctl role-changes approve <id>                  # 另一名 secadmin
cjsctl token create --kind device --name build-box
cjsctl token create --kind agent --name claude-1 --owner alice
cjsctl grants put build build.json
cjsctl full-access request --agent claude-1 --device build-box --reason "..." --duration 3600
cjsctl live streams
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

服务端出口：`"target": {"type": "server"}`，`"actions": ["egress"]`，`"egress": [{"host": "*.github.com", "ports": [443]}]`，`project_roots` 留空。私网、环回、链路本地与云元数据地址只有在规则里以 IP 明确列出时才允许。

## 设备

```sh
cjs-device enroll --server https://jump.example.com:8443 --token cjs1.... --ca cert.pem
cjs-device probe              # 检查沙箱
cjs-device run                # 前台运行
cjs-device install-service    # 打印服务定义；加 --apply 写入并启用
```

`--config`（环境变量 `CJS_DEVICE_DIR`）指定配置目录（身份密钥、profile、会话临时目录）；默认：Linux 下 root 为 `/var/lib/cjs-device`，否则为平台配置目录下的 `cjs-device`（`~/.config`、`~/Library/Application Support`、`%APPDATA%`）。设备每次启动把该目录收紧为 0700/0600，沙箱内不可读。服务定义里的路径取自执行 `install-service` 时的 `--config` 和可执行文件位置，所以要用与 `enroll` 相同的 `--config` 执行。

设备进程以普通用户运行即可：agent 只能写授权里的项目根和会话临时目录。Linux 需要支持 Landlock 的内核（5.13+），否则 shell 与命令会被拒绝（除非批准了全权限）。较旧的内核只能部分执行（`probe` 显示 `landlock (partial: older kernel ABI)`）：禁止 TCP 需要 ABI 4（6.7+），信号与抽象 socket 隔离需要 ABI 6（6.12+）。

### Linux（systemd）

```sh
sudo useradd --system --create-home --home-dir /var/lib/cjs-device cjs
sudo -u cjs cjs-device --config /var/lib/cjs-device enroll --server ... --token cjs1.... --ca cert.pem
sudo cjs-device --config /var/lib/cjs-device install-service --apply --user cjs
```

`--apply` 写入 `/etc/systemd/system/cjs-device.service` 并执行 `systemctl daemon-reload` 与 `systemctl enable --now`。单元以 `--user`（默认 `cjs`）运行，带 `NoNewPrivileges`、`PrivateTmp`、`RestrictSUIDSGID`、`UMask=0077` 等。

### macOS（launchd）

```sh
cjs-device enroll --server ... --token cjs1.... --ca cert.pem
cjs-device install-service            # 先查看 plist
cjs-device install-service --apply
```

`--apply` 写入当前用户的 `~/Library/LaunchAgents/com.clawdjumpserver.device.plist`（`RunAtLoad`、`KeepAlive`，stderr 写到 `<配置目录>/device.log`）并执行 `launchctl load -w`。这是用户级 LaunchAgent：设备以当前用户身份、在该用户登录后运行，`--user` 不起作用。停用：`launchctl unload -w ~/Library/LaunchAgents/com.clawdjumpserver.device.plist` 后删除文件。沙箱使用 `sandbox-exec`（系统自带，`cjs-device probe` 可检查）。

### Windows（计划任务）

```powershell
cjs-device enroll --server ... --token cjs1.... --ca cert.pem
cjs-device install-service            # 打印 schtasks 命令
cjs-device install-service --apply
```

`--apply` 执行：

```
schtasks /Create /F /SC ONLOGON /RL LIMITED /TN "ClawdJumpServer Device" /TR "\"<cjs-device.exe>\" run --config \"<配置目录>\""
```

即当前用户登录时以受限权限启动设备（不实现 Windows 服务控制协议，因此用户未登录时设备不在线）。创建 ONLOGON 任务可能需要管理员命令行。立即启动：`schtasks /Run /TN "ClawdJumpServer Device"`；删除：`schtasks /Delete /TN "ClawdJumpServer Device" /F`。命令在 AppContainer 中运行，没有网络。

## agent

agent 的用法（`cjs`、本地代理、MCP、`.cjs.toml`）见 [agent.md](agent.md)。
