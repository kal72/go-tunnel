# go-tunnel

Go-based reverse tunneling gateway that exposes private services over public TLS/HTTPS. The server keeps Let's Encrypt certificates up to date, while the agent (client) opens an outbound TLS connection and forwards HTTP or raw TCP traffic over a Yamux multiplexer.

## Key Features
- **Automatic TLS termination** via ACME/Let's Encrypt using `autocert.Manager`.
- **Multiplexing**: Many logical streams over a single TLS connection with `hashicorp/yamux`.
- **Redis-backed Auth**: Web UI sessions and Client tokens are stored in Redis with **instant revocation** support.
- **Web UI Manager**: Modern dashboard to manage client configurations, generate tokens, and monitor active tunnels in real-time.
- **Domain Management**: Centrally manage authorized subdomains under a base wildcard domain (e.g., `*.apps.com`) via Web UI.
- **Dynamic Configuration**: Add, edit, and delete agent configurations directly from the Web UI.
- **Wildcard Subdomain Support**: Flexible routing using manual or auto-generated random subdomains stored in Redis.
- **Supports HTTP & TCP**: Tunneling for web applications and raw TCP protocols (SSH, DB, etc.).

## Tech Stack
- **Language**: Go 1.25
- **Multiplexing**: `github.com/hashicorp/yamux`
- **State & Session**: Redis (`github.com/redis/go-redis/v9`)
- **Web UI**: Alpine.js, Tailwind CSS (via CDN), Go Templates.
- **Auth**: JWT (`github.com/golang-jwt/jwt/v5`) & HMAC-SHA256 for client tokens.
- **Logging**: `go.uber.org/zap`

## Web UI Manager
This application includes a Web UI Manager running on port `8080` (default) for easy management:
- **Login**: Secure authentication with sessions stored in Redis. (Default: `admin` / `admin123`).
- **Dashboard**: View the list of currently connected tunnels, including **Client ID**, source IP, assigned hosts, and connection time.
- **Domain Manager**: Register manual subdomains or **auto-generate random strings** under your base wildcard domain.
- **Config Editor**: Manage client configuration files (`.yaml`) without needing SSH access to the server.
- **Token Management**: Generate new tokens for clients or instantly **revoke** existing tokens to disconnect specific agents.

## Example DNS Records
| Type | Hostname | Value | Notes |
| --- | --- | --- | --- |
| `A` | `gateway.example.com` | `203.0.113.10` | Public HTTPS gateway + dashboard host (use your server's public IP). |
| `A` | `tunnel.example.com` | `203.0.113.10` | Agents connect here (`tunnel_addr`, also your server public IP). |
| `CNAME` | `app.example.com` | `gateway.example.com.` | Routed via gateway to your local target. |
| `CNAME` | `*.wildcard.example.com` | `gateway.example.com.` | All subdomains routed to matching tunnel sessions. |
| `CNAME` | `ssh.example.com` | `gateway.example.com.` | TCP tunnel routed via gateway. |

## Server Configuration (`.env`)
Copy `.env.example` and adjust the variables:

| Variable | Description |
| --- | --- |
| `GATEWAY_HOST` | Domain for the public HTTPS gateway. |
| `TUNNEL_HOST` | Domain for agent TLS connections (SNI). |
| `REDIS_ADDR` | Redis server address (default `localhost:6379`). |
| `REDIS_PASS` | Redis password (optional). |
| `REDIS_DB` | Redis database for sessions/auth (default `0`). |
| `DOMAIN_REDIS_DB` | Redis database for allowed subdomains (default `1`). |
| `WILDCARD_DOMAIN` | The base wildcard pattern (e.g., `*.yourdomain.com`). |
| `WEBUI_PORT` | Port for the Web UI Manager (default `8080`). |
| `JWT_SECRET` | Master secret used to generate client tokens and JWTs. |

## How to Run

### 1. Server & Web UI (Local)
Ensure Redis is running before starting the server.
```sh
go run ./cmd/server/main.go
go run ./cmd/webui/main.go
```

### 2. Server & Web UI (Docker)
Build and run everything using Docker:
```sh
docker build -t gotunnel .
docker run -p 80:80 -p 443:443 -p 8080:8080 -p 9443:9443 --env-file .env gotunnel
```

### 3. Client/Agent
Download the configuration from the Web UI or use a local file.
```sh
go run ./cmd/client/main.go
```

## Token Revocation Flow
1. Admin generates a token for a specific Client ID in the Web UI.
2. The token is stored in Redis.
3. When a Client connects, the Server verifies the token status in Redis.
4. If the Admin clicks **Revoke** in the Web UI, the token is removed from Redis, and subsequent authentication attempts (or heartbeats) from that agent will be rejected.

## Domain Management Flow
1. Admin configures `WILDCARD_DOMAIN=*.example.com` in `.env`.
2. Admin uses **Domain Manager** in Web UI to add a subdomain:
   - **Manual**: Enter `myapp` -> `myapp.example.com` is added to Redis DB 1.
   - **Random**: System generates `a1b2c3d4` -> `a1b2c3d4.example.com` is added to Redis DB 1.
3. When a Client tries to register a host, the Server checks:
   - Is the host explicitly in the Redis DB 1 allowlist? (Required even if it matches the wildcard pattern).
4. If authorized, the tunnel is established and ACME SSL issuance is permitted.

## Architecture Overview
| Component | Role |
| --- | --- |
| **Edge Server** | Handles public traffic and TLS tunnel connections from agents. |
| **Redis Store** | Maintains active tunnel states and valid/revoked token lists. |
| **Web UI Handler** | Provides the API and interface for configuration management. |
| **Agent** | The client that opens the outbound tunnel to the server. |

Happy tunneling!
