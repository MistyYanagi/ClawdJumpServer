# ClawdJumpServer

A bastion ("jump server") for AI agents and the people who run them. Agents
reach their devices only through the server, which authenticates them,
decides every request against explicit grants (default deny), records every
terminal session, and writes a tamper-evident audit trail. Devices verify
the server's decision again before acting and run shells inside an OS
sandbox confined to the project directories.

面向 AI agent 的堡垒机：统一认证、默认拒绝的细粒度授权、终端录像、防篡改审计；设备端独立复核每次授权，并在操作系统沙箱里运行 shell。

## Components

| Binary | Role |
|---|---|
| `cjs-server` | gateway, policy enforcement, relay with recording, egress proxy, REST API, web console — one port |
| `cjs-device` | daemon on each target machine; dials out, verifies capabilities, sandboxed shells/commands, jailed files, forwards |
| `cjs` | agent CLI: `shell`, `exec --json`, `cp [-r] [--resume]`, `ls`, `forward -L/-R`, `proxy` (SOCKS5 / HTTP, authenticated), `mcp`, `daemon` |
| `cjsctl` | administration CLI over the REST API |

Everything dials out to the server over WebSocket, falling back to HTTP
long-polling, through TLS-intercepting proxies if needed: sessions are
end-to-end encrypted with Noise IK against the pinned server key and resume
transparently after network failures.

## Quick start

Requires Rust 1.88+ (or Docker).

```sh
cargo build --release --locked
cjs-server --data ./srv init --admin admin --hostname HOST   # prints password + TOTP secret
cjs-server --data ./srv user-add audit1 --roles auditor      # separation of duties
cjs-server --data ./srv run --listen 0.0.0.0:8443            # logs the audit key fingerprint: pin it
cjsctl login --server https://HOST:8443 --name admin --ca ./srv/tls/cert.pem
cjsctl token create --kind device --name box1        # then on the device:
cjs-device enroll --server https://HOST:8443 --token cjs1... --ca cert.pem && cjs-device run
cjsctl token create --kind agent --name claude1      # then for the agent:
cjs enroll --server https://HOST:8443 --token cjs1... --ca cert.pem
cjsctl grants put g1 grant.json                      # see docs/deployment.md
cjs exec -d box1 --json -- uname -a
```

With Docker:

```sh
docker build -t cjs-server .
docker run --rm -v cjs-data:/var/lib/cjs-server cjs-server init --hostname HOST
docker run -d --name cjs -p 8443:8443 -v cjs-data:/var/lib/cjs-server cjs-server
```

See [docs/deployment.md](docs/deployment.md) for TLS certificates, bootstrapping
administrators, services on Linux/macOS/Windows and backups, and
[docs/agent.md](docs/agent.md) for the agent CLI, proxy and MCP tools.

## Documentation

- [docs/architecture.md](docs/architecture.md) — components and the life of a stream
- [docs/protocol.md](docs/protocol.md) — wire protocol
- [docs/4a.md](docs/4a.md) — security requirements (Account, Authentication, Authorization, Audit) and their conformance tests
- [docs/deployment.md](docs/deployment.md) — install (binaries, Docker), operate, configure
- [docs/agent.md](docs/agent.md) — agent CLI, local proxy, MCP tools, `.cjs.toml`
- [docs/HANDOFF.md](docs/HANDOFF.md) — development status and notes

## Development

```sh
cargo test --workspace                       # unit, e2e and 4A conformance tests
CJS_TEST_TRANSPORT=http cargo test -p cjs-tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

License: GPL-3.0-only.
