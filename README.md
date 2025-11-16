# go-tunnel

Go-based reverse tunneling gateway that exposes private services over public TLS/HTTPS. The server keeps Let's Encrypt certificates up to date, while the agent (client) opens an outbound TLS connection and forwards HTTP or raw TCP traffic over a Yamux multiplexer.

## Key Features
- Automatic TLS termination via ACME/Let's Encrypt using `autocert.Manager` (gateway and tunnel listeners).
- Multiplex many logical streams over a single TLS connection with `hashicorp/yamux`.
- JWT (HS256) client authentication plus a 15-second ping/pong heartbeat.
- Lightweight HTML dashboard for monitoring active sessions.
- Supports `http` mode (default) and `tcp` mode for raw tunnels (SSH, databases, etc.).

## Tech Stack
- **Language & runtime**: Go 1.25 (`cmd/server`, `cmd/client`).
- **TLS & ACME**: `golang.org/x/crypto/acme/autocert` handles certificate provisioning.
- **Multiplexing**: `github.com/hashicorp/yamux` lets many requests share one TLS socket.
- **Auth**: `github.com/golang-jwt/jwt/v5` for HS256 tokens.
- **Config & env**: YAML (`config.yaml`) and `.env` via `gopkg.in/yaml.v3` and `github.com/joho/godotenv`.
- **Logging**: `go.uber.org/zap` in production mode.

## Architecture Overview
| Component | Code location | Role |
| --- | --- | --- |
| Edge server | `internal/server`, `cmd/server` | Listens on public HTTPS and tunnel TLS ports, verifies JWT, maps host → agent stream. |
| Host registry | `internal/registry` | Tracks allowed domains and enforces the ACME host policy. |
| Agent/Client | `internal/client`, `cmd/client` | Opens outbound TLS, registers hostnames + targets, serves HTTP/TCP streams. |
| Dashboard | `Server.DashboardHandler()` | Small HTML page to inspect active sessions. |

## Environment Prep
1. **Dependencies**: Go ≥ 1.25, Make (optional), and open ports 80/443/9443 on the server host.
2. **DNS**: Point your gateway/tunnel hostnames to the server IP; these names receive certificates.
3. **Storage**: Directory for certificate cache (`ACME_CACHE`, default `./cert-cache`).

### Example DNS Records
| Type | Hostname | Value | Notes |
| --- | --- | --- | --- |
| `A` | `gateway.example.com` | `203.0.113.10` | Public HTTPS gateway + dashboard host (use your server's public IP). |
| `A` | `tunnel.example.com` | `203.0.113.10` | Agents connect here (`tunnel_addr`, also your server public IP). |
| `CNAME` | `app.example.com` | `gateway.example.com.` | Routed via gateway to your local target. |
| `CNAME` | `ssh.example.com` | `gateway.example.com.` | TCP tunnel routed via gateway. |

All hostnames you configure under `tunnels.hostname` must resolve to the public IP that runs `gotunnel-server`.

## Server Configuration (`.env`)
Copy `.env.example` and adjust:

| Variable | Description |
| --- | --- |
| `GATEWAY_HOST` | Domain for the public HTTPS gateway and dashboard host check. |
| `GATEWAY_PORT` | Public HTTPS port (default 443). |
| `TUNNEL_HOST` | Domain used by agents to connect via TLS (SNI checked). |
| `TUNNEL_PORT` | TLS port used by agents (default 9443). |
| `DASHBOARD_PORT` | HTTP dashboard port (default 8080). |
| `JWT_SECRET` | HS256 key shared with clients. |
| `ACME_CACHE` | Folder for Let's Encrypt cache. |
| `ACME_ENV` | `production` (default) or `staging` ACME directory URL. |

> Keep port 80 open when using Let's Encrypt HTTP-01 challenges (see the `Dockerfile`, which exposes 80/443/9443/8080).
>
> The server keeps an in-memory registry of every hostname currently registered by the agents. Incoming HTTPS requests—and ACME certificate issuance—are only allowed for hosts that are actively registered, which prevents stray domains from being served accidentally.

## Client Configuration (`config.yaml`)
Start from `config.yaml.example`. Important fields:

```yaml
tunnel_addr: "tunnel.domain.com:9443"  # server `TUNNEL_PORT`
skip_tls_verify: false                 # set true only for testing

jwt_secret: "supersecretjwtkey"        # must match the server
jwt_issuer: "mytunnel"
jwt_expire_sec: 3600

tunnels:
  - hostname: "app.domain.com"         # registered public host
    target: "127.0.0.1:8080"           # local service being exposed
    mode: "http"                       # or "tcp"
```

> The client uses the hostname from `tunnel_addr` for TLS/SNI, so point it at the same domain you configured in the server `.env` (`TUNNEL_HOST`).
>
> The server enforces hostnames registered by active agents only; make sure your `tunnels.hostname` values resolve to the server IP.

## How to Run

### 1. Server
```sh
# run locally
go run ./cmd/server

# or build a binary
go build -o bin/gotunnel-server ./cmd/server/main.go
./bin/gotunnel-server

# or via Docker
docker build -t gotunnel-server .
docker run -p 80:80 -p 443:443 -p 9443:9443 -p 8080:8080 \
  -v $(pwd)/cert-cache:/app/cert-cache \
  --env-file .env \
  gotunnel-server
```

### 2. Client/Agent
```sh
go run ./cmd/client              # reads config.yaml by default
# or
go build -o bin/gotunnel-agent ./cmd/client/main.go
./bin/gotunnel-agent --config config.yaml  # adapt flags/wrapper as needed
```
The client retries every 2 seconds if the tunnel drops.

## End-to-End Example
1. **Server**: on a VPS, copy `.env`, run `gotunnel-server`, and make sure `app.vpsme.com` and `ssh.vpsme.com` resolve to the VPS IP.
2. **Client**: on your laptop/office, create `config.yaml`:
   ```yaml
   tunnel_addr: "tunnel.vpsme.com:9443"
   jwt_secret: "supersecretjwtkey"
   tunnels:
     - hostname: "app.vpsme.com"
       target: "127.0.0.1:8080"
       mode: "http"
     - hostname: "ssh.vpsme.com"
       target: "127.0.0.1:22"
       mode: "tcp"
   ```
3. **Automatic registration**: when the client starts it creates a JWT, sends the hostnames, and the server lists the routes on the dashboard at `http://gateway.vpsme.com:8080` (or whatever `GATEWAY_HOST`/`DASHBOARD_PORT` you set). A hostname can only belong to one active agent at a time.
4. **Access services**:
   - Open `https://app.vpsme.com` → traffic forwards to the client’s `127.0.0.1:8080`.
   - SSH to `ssh.vpsme.com:443` (TCP mode) → connection relays to local port 22.

If a hostname is already registered with another agent the server rejects the registration and logs `host already registered`.

## Troubleshooting Tips
- **Certificates never issue**: ensure ports 80/443 are reachable and DNS points at the server; inspect the `ACME_CACHE` folder.
- **Client registration fails**: verify `JWT_SECRET` matches, the hostnames resolve to the server, and no other agent already registered the same host.
- **TCP mode**: ensure the front-end HTTP server supports connection hijacking (Go’s default does). It cannot be chained behind proxies that block hijacking.


Happy tunneling! This README now covers the tech stack, how-to, and end-to-end example so onboarding is faster.
