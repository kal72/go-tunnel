---
inclusion: always
---

# Architecture: go-tunnel

## Package Structure

```
gotunnel/
├── cmd/
│   ├── proxy/        # Entry point: Edge Proxy binary
│   ├── tunnel/       # Entry point: Tunnel Server binary
│   ├── webui/        # Entry point: Web UI Manager binary
│   └── client/       # Entry point: CLI Agent binary
├── internal/
│   ├── config/       # ServerConfig struct, LoadServerConfig (godotenv)
│   ├── di/           # Dependency injection wiring (BuildTunnelApp, BuildWebUIApp, BuildProxyApp)
│   ├── domain/       # Domain entities, repository interfaces, mock generation targets
│   │   ├── config/
│   │   ├── errors/
│   │   ├── setting/
│   │   ├── tunnel/
│   │   └── user/
│   ├── usecase/      # Business logic implementations
│   │   ├── config/
│   │   ├── setting/
│   │   ├── tunnel/
│   │   └── user/
│   ├── delivery/
│   │   ├── tcp/      # Yamux tunnel server (handler.go), TCP handler tests
│   │   └── web/      # Chi router, HTTP handlers, middleware
│   │       ├── dto/
│   │       ├── handler/
│   │       └── middleware/
│   ├── gateway/      # Edge proxy, SNI sniffer, Minecraft sniffer
│   ├── infrastructure/
│   │   ├── cache/
│   │   │   ├── memory/   # In-memory HostRegistry
│   │   │   └── redis/    # TunnelRedisStore (sessions, pub/sub, domain locks)
│   │   ├── cert/         # ACME, TLS config helpers, self-signed cert generator
│   │   └── database/
│   │       └── postgres/ # sqlx repositories for user, config, domain, setting
│   ├── shared/
│   │   ├── crypto/       # bcrypt password hashing
│   │   ├── protocol/     # Binary framing for Yamux control messages
│   │   ├── ratelimit/    # Token-bucket limiter per hostname
│   │   └── stats/        # gopsutil CPU/memory/network collector (SSE)
│   └── client/           # CLI agent logic (login, run, update, uninstall)
├── assets/               # Embedded FS: Go HTML templates
├── db/migrations/        # golang-migrate SQL migrations (up/down)
└── docs/                 # Supplemental documentation
```

---

## Layered Architecture

The project follows a clean/layered architecture. Dependencies flow inward:

```
Delivery (handler/tcp) → Usecase → Domain (interfaces)
                                        ↑
                         Infrastructure (implements interfaces)
```

- **Domain layer** (`internal/domain/`): pure entities and repository/store interfaces. No external dependencies. Mocks live here under `domain/<name>/mocks/`.
- **Usecase layer** (`internal/usecase/`): business logic. Depends only on domain interfaces. Each usecase has its own interface in `usecase.go` and implementation in `<name>_usecase.go`. Mocks live under `usecase/<name>/mocks/`.
- **Delivery layer** (`internal/delivery/`): HTTP handlers (Chi) and TCP/Yamux server. Depends on usecase interfaces only.
- **Infrastructure layer** (`internal/infrastructure/`): concrete implementations (Redis, PostgreSQL, ACME, cert). Implements domain interfaces.
- **DI layer** (`internal/di/`): wires all components together. One `Build*` function per binary.

---

## Traffic Flow

### Public request (HTTPS)
```
Internet:443 → Edge Proxy (peekSNI)
    ├── SNI = tunnel.example.com  → L4 TCP passthrough → Tunnel Yamux (:9443)
    ├── SNI = webui.example.com   → HTTP reverse proxy → Web UI (:8080)
    └── SNI = *.example.com       → domain allowlist check → Tunnel HTTP (:8443)
                                                                    ↓
                                                         Yamux stream → agent → local service
```

### Minecraft (non-TLS on port 443)
```
Internet:443 → Edge Proxy (peekMinecraft, Packet ID 0x00)
    └── valid MC handshake → HTTP CONNECT Upgrade → Tunnel HTTP (:8443) → agent (minecraft-proxy mode)
        → PROXY TCP4 header injected → local Minecraft server (:25565)
```

### Agent connection lifecycle
```
Agent TLS dial → Tunnel :9443 → yamux.Server
    → AcceptStream (control stream)
    → REGISTER msg { auth_token, client_id, client_name, hostnames[] }
    → JWT verify (Redis revocation check)
    → domain allowlist check (PostgreSQL + Redis)
    → REGISTER_OK response
    → heartbeat loop (PING/PONG every N seconds)
    → per-request: AcceptStream → protocol.ReadDataHeader (hostname) → forward to local port
```

---

## Redis Key Schema

| Key Pattern | DB | Purpose |
|---|---|---|
| `tunnel:<sessionID>` | 0 | Active tunnel info (JSON, TTL 1h) |
| `auth:<token>` | 0 | Token validity (`valid` or `revoked`) |
| `user_tokens:<userID>` | 0 | Set of tokens per user (for bulk revocation) |
| `active_domain:<domain>` | 0 | Domain lock (NX, TTL 24h) |
| `rate_limit_enabled:<username>` | 0 | Per-user rate limit toggle |
| `tunnel_events` | 0 | Pub/Sub channel for dashboard SSE |
| `tunnel_inspect:<hostname>` | 0 | Pub/Sub channel for live request inspector |
| `allowed_domains` | 1 | Set of permitted subdomains |

---

## Authentication & Security

- **Dual JWT policy**: Web browser tokens (`WEB_JWT_EXPIRE_HOURS`, HTTP-only secure cookie) vs CLI tokens (`CLI_JWT_EXPIRE_HOURS`, Bearer header).
- **JWT claims**: `sub` (user UUID), `user` (username), `role`, `csrf` (random 32-byte hex), `exp`.
- **CSRF protection**: token embedded in JWT claims, validated per-request via `webMiddleware.CSRF()`.
- **Token revocation**: deleting the `auth:<token>` key in Redis immediately invalidates a session.
- **Admin middleware**: `handler.AdminMiddleware` checks `UserRoleKey` from context; role `1` = admin.
- **Cookies**: `HttpOnly: true`, `Secure: true`, `SameSite: Strict`.

---

## Web UI Route Groups

```
POST /api/cli/login              # CLI auth (no CORS)
GET  /api/cli/version            # Public version endpoint

[JWT required]
GET  /api/cli/config/{name}      # CLI: fetch named config
GET  /api/cli/configs            # CLI: list configs

[CORS + Security headers]
GET  /login, POST /login, GET /logout
GET  /docs

[JWT + CSRF required]
GET  /                           # Dashboard (tunnel list)
GET  /configs, /domains, /ratelimit, /downloads
GET  /api/tunnels/stream         # SSE: live tunnel list
GET  /api/tunnels/inspect/stream # SSE: live request inspector
GET|PUT /api/ratelimit
CRUD /api/configs/{id}
GET|POST|DELETE /api/domains

[Admin only]
GET  /settings, /stats, /users
GET|PUT /api/settings
GET  /api/stats/stream           # SSE: system metrics
CRUD /api/users
POST /api/users/{id}/revoke-tokens
```

---

## Dependency Injection Pattern

Each `internal/di/*.go` file wires a single binary:

1. Initialize Redis store (`redisrepo.NewTunnelRedisStore`)
2. Initialize PostgreSQL (`postgresrepo.InitDB`)
3. Create repositories (user, config, domain, setting)
4. Create usecases (inject repos + stores)
5. Create handlers (inject usecases)
6. Return the runnable app + a `cleanup func()`

The `cleanup` function is always deferred in `main()` to close DB connections and stop background collectors.
