# agent 使用（cjs）

`cjs` 是 agent 一侧的命令行。每次调用要么直连服务端，要么复用本机 `cjs daemon` 的连接（守护进程在运行时自动使用，`--direct` 强制直连）。所有操作都由服务端按授权决策、审计，再由设备独立校验能力令牌。

## 注册与全局选项

```sh
cjs enroll --server https://jump.example.com:8443 --token cjs1.... --ca cert.pem
cjs status; cjs whoami; cjs devices
```

| 选项 | 环境变量 | 作用 |
|---|---|---|
| `--config DIR` | `CJS_CONFIG_DIR` | 配置目录（身份密钥、profile、守护进程 socket），默认平台配置目录下的 `cjs` |
| `-d, --device NAME` | `CJS_DEVICE` | 目标设备，默认取 `.cjs.toml` 的 `device` |
| `--json` | | 机器可读输出；错误为 `{"error": {"code", "message"}}`，退出码稳定（10–27） |
| `--direct` | | 不使用守护进程 |

`enroll` 的令牌也可以用 `CJS_ENROLL_TOKEN` 传入，`--transport auto|ws|http` 选择传输（默认 `auto`：先 WebSocket，失败降级到 HTTP 长轮询）。

## 命令

```sh
cjs shell [--cwd DIR] [-- CMD...]               # 交互终端（录像）
cjs exec [--cwd DIR] [--env K=V]... [--timeout 秒] -- make test
cjs --json exec -- cargo test                   # {"exit_code", "stdout", "stderr", ...}
cjs ls [dev:]path
cjs cp [--resume] [--mkdirs] ./big.tar build-box:big.tar
cjs cp -r ./src build-box:src                   # 目录树，双向
cjs forward -L [bind:]lport:host:rport          # 本地端口 → 设备看到的 host:rport
cjs forward -R [bind:]rport:lhost:lport         # 设备端口 → 本机 lhost:lport
cjs proxy [--listen 127.0.0.1:1080] [--via DEVICE] [--no-auth] [--env-file FILE]
cjs mcp                                         # MCP stdio 服务
cjs daemon                                      # 保持一条连接供其他调用复用
```

`cp` 的两端恰好一端是远程（`device:path`，省略设备名时用默认设备）。`--resume` 续传中断的传输（整文件 SHA-256 校验）。`-r/--recursive` 递归复制目录树：符号链接与特殊文件被跳过（不跟随，结束时列出），设备返回的文件名在变成本地路径前会被校验（拒绝 `..`、分隔符等）。文件访问只能在授权的项目根之内。

输出到终端时（`shell` 和 `exec`）会过滤 OSC 52 剪贴板写入序列（按数值比较参数，识别 C1 引导/终止符的原始与 UTF-8 形式）；输出到管道或文件时保持原样。下载与 MCP 读取在设备发送的数据超过其声明大小时立即中止。

## 本地代理（cjs proxy）

一个端口同时提供 SOCKS5（CONNECT）、HTTP CONNECT 和普通 HTTP 转发代理（`GET http://host/path`，改写为 origin-form 并带 `Connection: close`）。每个连接都是一条 `egress` 流，由服务端按出口规则决策并审计；`--via DEVICE` 改为从设备出口（需要该设备上的 `egress` 授权，设备在 DNS 解析后再按签入令牌的规则复核地址）。

默认要求凭据：启动时随机生成用户名 `cjs` 与口令，SOCKS5 用用户名/口令认证，HTTP 用 `Proxy-Authorization: Basic`，否则本机其他进程或用户可以借用这个 agent 的身份。凭据写在输出的 export 行里：

```sh
export HTTP_PROXY=http://cjs:<口令>@127.0.0.1:1080      # 以及 HTTPS_PROXY、http_proxy、https_proxy
export ALL_PROXY=socks5h://cjs:<口令>@127.0.0.1:1080    # 以及 all_proxy
export NO_PROXY=localhost,127.0.0.1,::1                 # 以及 no_proxy
```

代理一直运行，所以不要用 `eval "$(cjs proxy)"`（命令替换会等到它退出）。推荐把这些行写进只有自己可读的文件，再在 shell 里加载：

```sh
cjs proxy --env-file ~/.cjs/proxy.env &      # 文件以 0600 新建（已存在则先删除）
sleep 1; . ~/.cjs/proxy.env
curl https://crates.io/
```

不带 `--env-file` 时 export 行打印到 stdout（诊断信息在 stderr），可以重定向到文件后再 `.` 加载。`--no-auth` 关闭认证（会打印警告，任何本机进程都能使用该 agent 的身份），只应在单用户、受控的环境中使用。监听非环回地址时同样会警告。

## MCP 服务（cjs mcp）

```json
{"mcpServers": {"cjs": {"command": "cjs", "args": ["mcp"]}}}
```

| 工具 | 参数 | 说明 |
|---|---|---|
| `cjs_list_devices` | — | 可用设备、允许的动作与项目根 |
| `cjs_exec` | `device?`, `command` 或 `argv`, `cwd?`, `stdin?`, `timeout_secs?` | 在沙箱中运行命令（`command` 用 `/bin/sh -c`，Windows 设备用 `cmd /C`），返回 stdout、stderr、退出码（输出最多 1 MiB） |
| `cjs_read_file` | `device?`, `path` | 读项目根内的文本文件（最多 4 MiB） |
| `cjs_write_file` | `device?`, `path`, `content`, `mkdirs?` | 创建或替换项目根内的文本文件（最多 4 MiB） |
| `cjs_list_dir` | `device?`, `path?` | 列目录 |
| `cjs_forward_start` | `device?`, `host`, `port`, `local_port?` | 在 `127.0.0.1` 上监听（`local_port` 省略或为 0 时自动选择），转发到设备看到的 `host:port`，返回本地地址和 forward id；每个连接单独授权、审计 |
| `cjs_forward_list` | — | 列出由 `cjs_forward_start` 建立的转发 |
| `cjs_forward_stop` | `id` | 停止转发 |

`device` 省略时使用 `.cjs.toml` 的默认设备。转发只监听环回地址，每个 MCP 会话最多 32 个；MCP 服务退出时全部关闭。

## 项目配置（.cjs.toml）

```toml
device = "build-box"       # 默认设备
cwd = "/srv/work/project"  # shell / exec / ls 的默认远端工作目录
```

只允许这两个键（未知键报错）。查找规则：

- 从当前目录开始向上逐级查找，用找到的第一个有效文件；
- 到达 git 仓库根（含 `.git` 的目录）或用户主目录后停止，不再继续向上；
- Unix 上忽略（并警告）属于其他用户、或可被组 / 其他用户写入（`mode & 022`）的文件，然后继续向上查找，这样放在 `/tmp` 等共享目录里的文件无法替你选择设备或远端目录。Windows 上不做属主检查。

命令行的 `-d` / `--cwd` 优先于 `.cjs.toml`。

## 本地守护进程

`cjs daemon` 在 `<配置目录>/agent.sock`（0700 目录；Windows 为命名管道 `\\.\pipe\cjs-agent-<hash>`）上服务其他 `cjs` 调用，并生成随机令牌 `daemon.token`（0600，守护进程退出时删除）。连接时双方做挑战-应答：守护进程先证明自己持有令牌，客户端再证明，令牌本身从不经过 socket。因此连到冒名 socket / 管道的客户端不会泄露任何东西，其他本地用户也无法借用守护进程的连接。

## 经过会重签 TLS 的代理

客户端信任系统根证书（遵守 `SSL_CERT_FILE`）、Mozilla 根证书和 `--ca`，并遵守 `HTTPS_PROXY` / `NO_PROXY`。会话内容由钉住服务端公钥的 Noise 加密，传输控制消息带 MAC，中间人只能使连接断开（随后自动续传）。
