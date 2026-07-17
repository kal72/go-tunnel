---
inclusion: always
---

# Project Overview: go-tunnel

## What is go-tunnel?

go-tunnel is a Go-based **reverse tunneling gateway** that exposes private/local services to the public internet over TLS/HTTPS. The server handles TLS termination and routing, while the agent (client CLI) opens an outbound connection from the local machine and forwards traffic back through the tunnel.

**Module name**: `gotunnel`
**Go version**: 1.26
**Default admin credentials**: `admin` / `admin123`

---

## Core Features

- **Automatic TLS** via ACME/Let's Encrypt (`autocert.Manager`) or wildcard certificates
- **Multiplexed connections** over a single TLS connection using `hashicorp/yamux`
- **Multi-protocol support**: HTTP, HTTPS, raw TCP (SSH, databases), and Minecraft Java Edition
- **Minecraft Protocol Sniffing** (`peekMinecraft`): detects non-TLS Minecraft handshake packets on port 443 and routes transparently
- **HAProxy PROXY Protocol v1** injection for real player IP in Minecraft (`minecraft-proxy` mode)
- **SNI Multiplexing** (`peekSNI`): routes traffic based on TLS SNI hostname at L4 without decrypting
- **Role-Based Access Control (RBAC)**: Admin (`role=1`) vs Regular User (`role=0`)
- **Redis-backed sessions** with instant JWT token revocation
- **Rate limiting** per-host with global thresholds (req/s and burst)
- **Live request inspector** via SSE + Redis Pub/Sub (`tunnel_inspect:<hostname>`)
- **Real-time system stats** (CPU, memory, network I/O) via SSE (`/api/stats/stream`)
- **Domain management**: allowlist subdomains under a wildcard domain in Redis DB 1
- **Cross-platform CLI** with interactive login, config management, and self-update

---

## Tech Stack

| Concern | Library |
|---|---|
| Web router | `github.com/go-chi/chi/v5` |
| Multiplexing | `github.com/hashicorp/yamux` |
| Database | PostgreSQL via `github.com/jmoiron/sqlx` + `github.com/lib/pq` |
| Cache / Pub-Sub | Redis via `github.com/redis/go-redis/v9` |
| Auth | `github.com/golang-jwt/jwt/v5` |
| UUIDs | `github.com/google/uuid` |
| System metrics | `github.com/shirou/gopsutil/v3` |
| Logging | `go.uber.org/zap` |
| Config | `github.com/joho/godotenv` |
| Testing | `github.com/stretchr/testify` + `github.com/DATA-DOG/go-sqlmock` |
| Mock generation | `github.com/vektra/mockery/v2` |
| Frontend | Go HTML templates + Alpine.js + Tailwind CSS (CDN) |

---

## Entry Points (binaries)

| Binary | Path | Role |
|---|---|---|
| `gotunnel-proxy` | `cmd/proxy/main.go` | Public edge proxy (ports 80/443), SNI multiplexer, ACME |
| `gotunnel-server` | `cmd/tunnel/main.go` | Tunnel server (Yamux, port 9443) + internal HTTP (port 8443) |
| `gotunnel-webui` | `cmd/webui/main.go` | Web UI Manager (port 8080) |
| `gotunnel-client` | `cmd/client/main.go` | CLI agent for end-users |

---

## Key Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `GATEWAY_DOMAIN` | — | Public HTTPS gateway domain |
| `TUNNEL_DOMAIN` | — | Agent connection domain (SNI-routed) |
| `WEBUI_DOMAIN` | `localhost` | Web UI manager domain |
| `PROXY_HTTP_PORT` | `80` | ACME challenge + HTTP redirect |
| `PROXY_HTTPS_PORT` | `443` | Public edge (SNI multiplexer) |
| `TUNNEL_PORT` | `9443` | Yamux agent listener |
| `GATEWAY_PORT` | `8443` | Internal HTTP demux |
| `WEBUI_PORT` | `8080` | Web UI internal port |
| `JWT_SECRET` | — | Signing key for all tokens |
| `WEB_JWT_EXPIRE_HOURS` | `24` | Browser session TTL |
| `CLI_JWT_EXPIRE_HOURS` | `720` | CLI token TTL |
| `ACME_ENABLE` | `false` | Enable Let's Encrypt |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_DB` | `0` | Redis DB for sessions/auth |
| `DOMAIN_REDIS_DB` | `1` | Redis DB for allowed domains |
| `WILDCARD_DOMAIN` | — | e.g. `*.example.com` |
| `DB_HOST/PORT/USER/PASS/NAME` | — | PostgreSQL connection |

---

## Communication Language

- **Agent/AI chat and explanations**: always in **Indonesian (Bahasa Indonesia)**
- **Code, comments, variables, function names, documentation**: always in **English**
