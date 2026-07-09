# go-tunnel

Go-based reverse tunneling gateway that exposes private services over public TLS/HTTPS. The server keeps Let's Encrypt certificates up to date, while the agent (client) opens an outbound TLS connection and forwards HTTP or raw TCP traffic over a Yamux multiplexer.

## Key Features
- **Automatic TLS termination** via ACME/Let's Encrypt using `autocert.Manager`.
- **Multiplexing**: Many logical streams over a single TLS connection with `hashicorp/yamux`.
- **Minecraft Server Tunneling (`peekMinecraft`)**: Protocol sniffing on public port `443` (`ProxyHttpsPort`) that detects non-TLS Minecraft Java Edition Handshake packets (`Packet ID 0x00`) and routes them transparently to your local PaperMC/BungeeCord server (`localhost:25565`). Players connect directly via `mc.example.com:443` without installing client software or configuring TLS bridges.
- **Real Player IP Injection (`PROXY TCP4`)**: Dedicated `minecraft-proxy` stream mode that injects HAProxy PROXY Protocol v1 headers at the start of TCP streams, enabling Minecraft servers (`proxy-protocol: true`) to log real player IP addresses instead of localhost (`127.0.0.1`).
- **Real-Time System Statistics**: Admin-only live server monitoring (`/stats`) powered by `gopsutil` (`internal/shared/stats`) streaming real-time CPU percentage, memory utilization, and network throughput (upload/download in B/s, KB/s, MB/s) via Server-Sent Events (`/api/stats/stream`).
- **Traffic Control & Rate Limiting**: Standalone Rate Limiting dashboard (`/ratelimit`) and API (`/api/ratelimit`) protecting active tunnel hostnames against excessive request rates (`req/s`) and DDoS surges. Regular users (`role == 0`) can toggle rate limiting ON/OFF for their own active tunnels, while Admins (`role == 1`) manage global request rate and burst thresholds.
- **Live Request Inspector**: Real-time HTTP traffic streaming (`/api/tunnels/inspect/stream`) using single multiplexed SSE connections and Redis Pub/Sub ephemeral channels (`tunnel_inspect:<hostname>`) with an interactive glassmorphism drawer in Alpine.js.
- **Role-Based Access Control (RBAC)**: Distinct permissions for Administrators (`role == 1`) vs Regular Users (`role == 0`). Regular users can only view, inspect, and toggle rate limits for tunnels registered under their own username, while Administrators manage the entire system.
- **PostgreSQL Config Management**: Client configs are stored in PostgreSQL per user. Create, list, and manage configurations directly from the WebUI.
- **Interactive CLI & Seamless Downloads**: The client CLI supports interactive login (`gotunnel login`), configuration listing (`gotunnel list`), and execution (`gotunnel run <name>`).
- **One-liner Installations**: The Web UI serves pre-compiled binaries for MacOS, Linux, and Windows with dynamic `curl` install scripts.
- **Redis-backed Auth & Revocation**: Web UI sessions and Client tokens are stored in Redis with **instant revocation** support.
- **Domain Management**: Centrally manage authorized subdomains under a base wildcard domain (e.g., `*.apps.com`) via Web UI.
- **Supports HTTP, HTTPS, TCP & Minecraft**: Flexible tunneling for web applications and raw TCP protocols (SSH, DB, Minecraft, etc.).

## Tech Stack
- **Language**: Go 1.26
- **Multiplexing**: `github.com/hashicorp/yamux`
- **System Metrics**: `github.com/shirou/gopsutil/v4`
- **Database (Config)**: PostgreSQL (`github.com/jackc/pgx/v5`)
- **State, Sessions & Pub/Sub**: Redis (`github.com/redis/go-redis/v9`)
- **Web UI & Telemetry**: Alpine.js, Tailwind CSS (via CDN), Go Templates, Server-Sent Events (SSE).
- **Auth**: JWT (`github.com/golang-jwt/jwt/v5`) & HMAC-SHA256 for client tokens.
- **Logging**: `go.uber.org/zap`

## Web UI Manager
This application includes a Web UI Manager running on port `8080` (default) for easy management:
- **Login**: Secure authentication with sessions stored in Redis. (Default: `admin` / `admin123`).
- **Dashboard**: View the list of currently connected tunnels, including **Client ID**, source IP, assigned hosts, connection time, and interactive **Live Request Inspector** drawers.
- **System Statistics (`/stats`)**: Dedicated admin dashboard displaying real-time CPU usage, memory consumption, and network I/O charts updated live via Server-Sent Events.
- **Rate Limiting (`/ratelimit`)**: Manage and toggle per-host request thresholds (`req/s` and burst capacity) to protect your exposed services.
- **Domain Manager**: Register manual subdomains or **auto-generate random strings** under your base wildcard domain.
- **Config Editor**: Manage client configurations per user, saved securely to PostgreSQL.
- **Client Downloads**: Download pre-compiled, auto-configured agent binaries for MacOS, Linux, and Windows straight from the dashboard.
- **Token Management**: Generate new tokens for clients or instantly **revoke** existing tokens to disconnect specific agents.

## Example DNS Records
| Type | Hostname | Value | Notes |
| --- | --- | --- | --- |
| `A` | `gateway.example.com` | `203.0.113.10` | Public HTTPS gateway + dashboard host (use your server's public IP). |
| `A` | `tunnel.example.com` | `203.0.113.10` | Agents connect here (`tunnel_addr`, also your server public IP). |
| `CNAME` | `app.example.com` | `gateway.example.com.` | Routed via gateway to your local target. |
| `CNAME` | `mc.example.com` | `gateway.example.com.` | Minecraft server domain. Direct connection via `mc.example.com:443` (`peekMinecraft`). Note: Must use direct/DNS-only without Cloudflare HTTP proxy. |
| `CNAME` | `*.wildcard.example.com` | `gateway.example.com.` | All subdomains routed to matching tunnel sessions. |
| `CNAME` | `ssh.example.com` | `gateway.example.com.` | TCP tunnel routed via gateway. |

## Server Configuration (`.env`)
Copy `.env.example` and adjust the variables:

| Variable | Description |
| --- | --- |
| `GATEWAY_DOMAIN` | Domain for the public HTTPS gateway. |
| `PROXY_HTTP_PORT` | Port for the public Proxy HTTP/ACME (default `80`). |
| `PROXY_HTTPS_PORT` | Port for the public Edge Gateway Proxy (default `443`). |
| `WEBUI_PORT` | Port for the Web UI Manager (default `8080`). |
| `WEBUI_DOMAIN` | Domain for accessing the Web UI (e.g., `webui.example.com`). |
| `CLI_LATEST_VERSION` | Version string distributed to clients (default `dev`). |
| `GATEWAY_PORT` | Internal port used by the Tunnel to handle local HTTP traffic (default `8443`). |
| `TUNNEL_DOMAIN` | Domain for agent TCP connections (SNI, e.g. `tunnel.example.com`). |
| `TUNNEL_PORT` | Port for agent TCP Yamux connections (default `9443`). |
| `JWT_SECRET` | Master secret used to generate client tokens and JWTs. |
| `WEB_JWT_EXPIRE_HOURS` | Expiration duration in hours for Web UI login sessions (default `24`). |
| `CLI_JWT_EXPIRE_HOURS` | Expiration duration in hours for CLI authentication tokens (default `720`). |
| `ACME_ENABLE` | Enable Let's Encrypt automatic certificate issuance (default `false`). |
| `ACME_CACHE` | Directory to store Let's Encrypt certificates (default `./cert-cache`). |
| `ACME_ENV` | Let's Encrypt environment: `production` or `staging`. |
| `REDIS_ADDR` | Redis server address (default `localhost:6379`). |
| `REDIS_PASS` | Redis password (optional). |
| `REDIS_DB` | Redis database for sessions/auth (default `0`). |
| `DOMAIN_REDIS_DB` | Redis database for allowed subdomains (default `1`). |
| `WILDCARD_DOMAIN` | The base wildcard pattern (e.g., `*.yourdomain.com`). |
| `WILDCARD_CERT_PATH` | Path to custom wildcard SSL certificate (`fullchain.pem`). |
| `WILDCARD_KEY_PATH` | Path to custom wildcard SSL private key (`privkey.pem`). |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME` | PostgreSQL database connection settings. |

## How to Run

### 1. Server, Proxy & Web UI (Local)
Ensure Redis is running before starting the services.
```sh
go run ./cmd/proxy/main.go
go run ./cmd/tunnel/main.go
go run ./cmd/webui/main.go
```

### 2. Run with Docker
Build and run everything using Docker:
```sh
docker build -t gotunnel .
docker run -p 80:80 -p 443:443 --env-file .env gotunnel
```

### 3. Client/Agent
Download and install the pre-compiled client from the Web UI `Downloads` page. You can easily install it on Linux/macOS via the terminal:
```sh
curl -fsSL https://<YOUR_WEBUI_DOMAIN>/dl/install.sh | bash
```

Once installed, use the interactive CLI:
```sh
# 1. Login to retrieve your authentication token (prompts for username/password)
gotunnel login

# 2. List all available configurations attached to your account
gotunnel list

# 3. Run a specific configuration by name
gotunnel run my-web-app
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
| **Edge Proxy (`cmd/proxy`)** | Handles public HTTPS traffic, Let's Encrypt ACME, L4 SNI Multiplexing (`peekSNI`), and Minecraft Protocol Sniffing (`peekMinecraft`). |
| **Tunnel Server (`cmd/tunnel`)** | Manages TCP Yamux streams, internal HTTP Demultiplexing, and HAProxy PROXY Protocol injection. |
| **Web UI (`cmd/webui`)** | Provides the API and visual interface for configuration management, System Stats (`/stats`), Rate Limiting (`/ratelimit`), and Live Inspector. |
| **Redis Store** | Maintains active tunnel states, live inspect pub/sub channels, and domain validation rules. |
| **Agent / Client** | The local client that opens the outbound tunnel to the server and forwards traffic to local ports (`localhost:80`, `localhost:25565`). |

## Production Architecture

`go-tunnel` is designed to be highly self-sufficient. Because we built a custom **Edge Proxy (`cmd/proxy`)** with L4 SNI Multiplexing (`peekSNI`), Minecraft Protocol Sniffing (`peekMinecraft`), and automatic Let's Encrypt (ACME), you **DO NOT need external reverse proxies like Nginx or HAProxy**.

Our Edge Proxy binds directly to your public port `443` and handles all complex routing internally.

```mermaid
%%{init: {'theme': 'dark'}}%%
graph TD
    Client[Web/API Client] -->|"HTTPS (Port 443)"| EdgeProxy["Edge Proxy<br>(cmd/proxy)"]
    Player[Minecraft Player] -->|"Raw Packet 0x00 (Port 443)"| EdgeProxy
    Agent[Go-Tunnel CLI Agent] -->|"TLS SNI / L4 Yamux (Port 443)"| EdgeProxy
    Admin[Admin/User Browser] -->|"HTTPS / Short JWT + CSRF (Port 443)"| EdgeProxy

    subgraph "Server Core Services"
        EdgeProxy -- "Host: *.example.com<br>HTTP Reverse Proxy" --> TunnelHttp["Tunnel Internal HTTP<br>(Port 8443)"]
        EdgeProxy -- "Minecraft Host: mc.example.com<br>Upgrade: tcp" --> TunnelHttp
        EdgeProxy -- "Host: webui.example.com<br>HTTP Reverse Proxy" --> WebUI["Web UI Manager<br>(Port 8080)"]
        EdgeProxy -- "SNI: tunnel.example.com<br>L4 TCP Passthrough" --> TunnelTCP["Tunnel Yamux Listener<br>(Port 9443)"]
        
        TunnelHttp -.->|"Multiplexed Traffic + PROXY TCP4"| TunnelTCP
        
        WebUI -->|"Session & Revocation"| Redis[(Redis Store<br>DB 0 & DB 1)]
        TunnelTCP -->|"Domain & Token Check"| Redis
        
        WebUI -->|"Users, Configs & Settings"| Postgres[(PostgreSQL DB)]
        TunnelTCP -->|"Fetch Domain Allowlists"| Postgres
    end
```

### Key Architectural Highlights
1. **Single Port Exposure**: The external firewall only needs to open ports `80` (for ACME challenge) and `443` (for Edge Proxy).
2. **Intelligent Protocol Sniffing & Routing (`peekSNI` & `peekMinecraft`)**:
   - Requests to `webui.example.com` are forwarded to the Web UI container (`:8080`).
   - Requests to `*.example.com` (*Free Domains* / web application subdomains) are validated against Redis DB 1 & PostgreSQL allowlists before forwarding to Tunnel Internal HTTP (`:8443`).
   - Non-TLS Minecraft packets arriving at port `443` are inspected via `peekMinecraft` (`Packet ID 0x00`), and if valid (`mc.example.com`), bridged transparently to Tunnel Internal HTTP (`:8443`) via `Upgrade: tcp`.
   - Requests to `tunnel.example.com` are routed via **L4 TCP Stream Passthrough** directly to the Yamux Listener (`:9443`).
3. **Multi-Tier Security & State**:
   - **Redis (DB 0 & DB 1)**: Powers ultra-fast Web UI session checks, instant JWT token revocations, wildcard routing tables, and real-time inspect telemetry.
   - **PostgreSQL**: Persistent storage for multi-user accounts, dynamic client YAML configurations, and domain metadata.
   - **Dual JWT Policy**: Web browser login issues short-lived HTTP-only secure cookies (`WEB_JWT_EXPIRE_HOURS`), while CLI login issues long-lived API tokens (`CLI_JWT_EXPIRE_HOURS`).

Happy tunneling!
