# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Minecraft Server Tunneling (`peekMinecraft`)**: Added server-side Minecraft Java Edition protocol sniffing (`internal/gateway/sni.go`) on port `443` (`ProxyHttpsPort`). Automatically detects non-TLS Minecraft Handshake packets (`Packet ID 0x00`), parses the target server address (`mc.example.com`), and transparently bridges traffic via HTTP `CONNECT` / `Upgrade: tcp` to the internal Yamux gateway (`GatewayPort`). Allows players to connect directly using a single custom domain (e.g., `mc.example.com:443`) without installing additional client software or configuring TLS bridges on their game client. Added `tcp-proxy` and `minecraft-proxy` stream modes to inject HAProxy PROXY Protocol v1 (`PROXY TCP4 ...`) headers for accurate real player IP forwarding to PaperMC / BungeeCord servers.
- **System Statistics Dashboard**: Added real-time server resource monitoring dashboard (`/stats`) with dedicated sidebar menu accessible exclusively to Administrators (`role == 1`). Features background system metric collection via `gopsutil` (`internal/shared/stats`) with 5-second caching and delta network bandwidth calculation (upload/download throughput in B/s, KB/s, MB/s). Streams live CPU percentage, RAM utilization, and network I/O to the frontend via Server-Sent Events (`/api/stats/stream`) and Alpine.js without database persistence or excessive server overhead.
- **Traffic Control & Rate Limiting**: Added standalone Rate Limiting navigation menu (`/ratelimit`) and API (`/api/ratelimit`) ala Ngrok / Cloudflare (`internal/shared/ratelimit`). Protects active tunnel hostnames from excessive HTTP requests and DDoS surges. Features role-based access control where regular users (`role == 0`) can only toggle rate limiting ON/OFF for their own active tunnels (automatically deleting `rate_limit_enabled:<username>` from storage when the tunnel session cleans up or becomes inactive), while Administrators (`role == 1`) manage the global threshold settings (request rate `req/s`, burst capacity, and admin tunnel bypass). Designed purely in-memory without audit logging and excluded from CLI remote config.
- **Auth & Access Control**: Added role-based access control for Active Tunnels list (`/` and `/api/tunnels/stream`) and Live Request Inspector (`/api/tunnels/inspect/stream`). Admins (`role == 1`) can view and inspect all active tunnels, whereas regular users (`role == 0`) can only view and inspect active tunnels registered under their own username.
- **Web UI & Tunnel Dashboard**: Added Live Request Inspector featuring real-time HTTP traffic streaming via Redis Pub/Sub ephemeral channels (`tunnel_inspect:<hostname>`), Server-Sent Events (`/api/tunnels/inspect/stream`), and an interactive glassmorphism drawer in Alpine.js with zero persistence. Features a wider modal layout (`max-w-6xl`), a clean dropdown Host Selector supporting long domain names (defaults to monitoring all hosts), a Pause/Resume traffic button, and a traffic log buffer limit defaulting to 100 items (configured purely via `INSPECT_DEFAULT_LIMIT` environment variable).
- **CI/CD**: Added cross-compile matrix validation for client binaries across 5 target platforms (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`) inside the automated quality checks workflow.
- **Testing**: Added comprehensive table-driven unit tests achieving 100% coverage for Web UI handlers: `AuthHandler` ([auth_test.go](file:///Users/kal/Projects/go-tunnel/internal/delivery/web/handler/auth_test.go)), `CLIHandler` ([cli_test.go](file:///Users/kal/Projects/go-tunnel/internal/delivery/web/handler/cli_test.go)), `UserHandler` ([user_test.go](file:///Users/kal/Projects/go-tunnel/internal/delivery/web/handler/user_test.go)), and `Handler` system settings endpoints ([setting_test.go](file:///Users/kal/Projects/go-tunnel/internal/delivery/web/handler/setting_test.go)). Also fixed static asset prefix path matching in `JWTMiddleware`.
- **CI/CD**: Configured GitHub Actions PR labeler tool via `labeler.yml` for automated context tagging of pull requests based on changed paths.

### Changed
- **Traffic Control & Rate Limiting**: Set default Rate Limiting status to OFF (`false`) for new regular users (`role == 0`). When new user accounts are created or when rate limit settings have not been explicitly toggled, rate limiting defaults to disabled for their active tunnels.
- **Web UI & Tunnel Dashboard**: Optimized Active Tunnels table column layout by fine-tuning the Tunnel column width (`min-w-[200px] w-1/5`) and constraining the Actions column width (`w-32 max-w-[130px]`) for clean responsiveness.
- **Web UI & Tunnel Dashboard**: Upgraded Live Request Inspector SSE streaming architecture to Single Multiplexed Stream (`/api/tunnels/inspect/stream?hosts=...`). Replaced multi-stream per host connections with a unified single SSE stream per dashboard view, significantly reducing server goroutine allocations and Redis Pub/Sub subscriptions on tunnels with large host counts. Added host badge display on UI request logs for clean multiplexed visual differentiation.
- **CI/CD**: Enhanced unit testing workflow with a 5-minute timeout flag (`-timeout 5m`) to prevent hung runners.

### Fixed
- **Minecraft Tunneling (`minecraft-proxy`)**: Fixed connection rejections (`Failed to connect to server`) when using PaperMC / BungeeCord with `proxy-protocol=true` due to HAProxy PROXY Protocol v1 sending source port `0` (`PROXY TCP4 ... 0 25565`). Updated `internal/gateway/proxy.go` to forward the client's actual TCP source port via `X-Real-Port` header when upgrading HTTP `CONNECT` streams, and updated `internal/delivery/tcp/handler.go` to always guarantee a valid non-zero source port (`> 0 and <= 65535`, defaulting to `54321` if unavailable) and proper IPv4/IPv6 family prefix (`TCP4`/`TCP6`), fully satisfying Netty's strict HAProxy message decoder requirements.
- **Web UI**: Allowed HTTPS tunnel targets to be configured without a port (e.g., just a domain/hostname) in the configuration form, matching the client agent's automatic fallback behavior.
- **Web UI**: Fixed sidebar navigation menu flicker by adding default text/SVG color classes in the static HTML and executing a tiny inline script to apply active states immediately on page load before first paint.
- **CI/CD**: Fixed parsing of Go unit test coverage reports in GitHub Actions to correctly extract package names and display total coverage badges with status icons.
- **CI/CD**: Fixed `vlaurin/action-ghcr-prune` inputs and authorization in the manual deployment pipeline by replacing `organization` with `user`, using the correct `prune-untagged` key, setting the target container name to `gotunnel`, and replacing `GITHUB_TOKEN` with `GHCR_TOKEN` to resolve permission and `Error: Not Found` issues.

### Removed
- **Minecraft Tunneling**: Removed redundant `minecraft` stream mode option from the Web UI dropdown selector, Quick Guide, and backend (`client.go`, `handler.go`). Since standard `tcp` mode natively bridges raw TCP streams (including Vanilla Minecraft and PaperMC without proxy protocol), `tcp` is the unified option for non-proxy Minecraft connections while `minecraft-proxy` remains exclusively for PaperMC/BungeeCord configurations with `proxy-protocol: true`.

## [1.1.0] - 2026-06-28

### Added
- **Web UI & Tunnel Dashboard**: Real-time active tunnel monitoring using Redis Pub/Sub, Server-Sent Events (SSE) streaming handler (`/api/tunnels/stream`), and Alpine.js reactive DOM updates.
- **Security**: XSS protection via Content Security Policy (CSP) and strict HTTP security headers middleware (`SecurityHeaders`).
- **Domain Management**: Restriction on Free Domain options in Web UI and backend validation when wildcard domain is unconfigured.
- **Auth & Tokens**: Admin action to revoke all JWT tokens for a specific user via Redis set index (`user_tokens:<userID>`).
- **Web UI**: Auto-redirect to `/login` when intercepting `401 Unauthorized` responses in fetch wrapper.
- **CLI**: Display update notification check when running `gotunnel` without arguments.
- **Documentation**: Added roadmap and future engineering backlog in `docs/ROADMAP.md`.

### Changed
- **Auth**: Separate JWT token expiration duration for Web UI sessions (`WEB_JWT_EXPIRE_HOURS`) and CLI sessions (`CLI_JWT_EXPIRE_HOURS`).
- **Reliability & Client Resilience**: Implement jittered exponential backoff for client agent connection retries (`gotunnel`) to prevent thundering herd problem.
- **Reliability & Gateway Proxy**: Implement graceful connection draining with a 30-second timeout on shutdown and double-close protection on `ChanListener`.
- **Web UI**: Improve sidebar navigation menu styling with dynamic active state indicator, coloring text and icons to match the menu item's unique color when selected.
- **Documentation**: Translate and expand Web UI portal documentation (`docs.html`) with TCP connection examples, detailed root domain CNAME guide, CLI reference table, troubleshooting FAQ, and standardized Table of Contents styling.

### Fixed
- **Client Build**: Resolve cross-platform compilation error on Windows (`GOOS=windows`) by properly casting `os.Stdin` file descriptor for `term.ReadPassword`.
- **CI/CD**: Remove manual version input from deployment workflow, enforcing release execution from Git tags.
