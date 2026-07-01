# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Auth & Access Control**: Added role-based access control for Active Tunnels list (`/` and `/api/tunnels/stream`) and Live Request Inspector (`/api/tunnels/inspect/stream`). Admins (`role == 1`) can view and inspect all active tunnels, whereas regular users (`role == 0`) can only view and inspect active tunnels registered under their own username.
- **Web UI & Tunnel Dashboard**: Added Live Request Inspector featuring real-time HTTP traffic streaming via Redis Pub/Sub ephemeral channels (`tunnel_inspect:<hostname>`), Server-Sent Events (`/api/tunnels/inspect/stream`), and an interactive glassmorphism drawer in Alpine.js with zero persistence. Features a wider modal layout (`max-w-6xl`), a clean dropdown Host Selector supporting long domain names (defaults to monitoring all hosts), a Pause/Resume traffic button, and a traffic log buffer limit defaulting to 100 items (configured purely via `INSPECT_DEFAULT_LIMIT` environment variable).
- **CI/CD**: Added cross-compile matrix validation for client binaries across 5 target platforms (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`) inside the automated quality checks workflow.
- **CI/CD**: Configured GitHub Actions PR labeler tool via `labeler.yml` for automated context tagging of pull requests based on changed paths.

### Changed
- **Web UI & Tunnel Dashboard**: Optimized Active Tunnels table column layout by fine-tuning the Tunnel column width (`min-w-[200px] w-1/5`) and constraining the Actions column width (`w-32 max-w-[130px]`) for clean responsiveness.
- **Web UI & Tunnel Dashboard**: Upgraded Live Request Inspector SSE streaming architecture to Single Multiplexed Stream (`/api/tunnels/inspect/stream?hosts=...`). Replaced multi-stream per host connections with a unified single SSE stream per dashboard view, significantly reducing server goroutine allocations and Redis Pub/Sub subscriptions on tunnels with large host counts. Added host badge display on UI request logs for clean multiplexed visual differentiation.
- **CI/CD**: Enhanced unit testing workflow with a 5-minute timeout flag (`-timeout 5m`) to prevent hung runners.

### Fixed
- **Web UI**: Allowed HTTPS tunnel targets to be configured without a port (e.g., just a domain/hostname) in the configuration form, matching the client agent's automatic fallback behavior.
- **Web UI**: Fixed sidebar navigation menu flicker by adding default text/SVG color classes in the static HTML and executing a tiny inline script to apply active states immediately on page load before first paint.
- **CI/CD**: Fixed parsing of Go unit test coverage reports in GitHub Actions to correctly extract package names and display total coverage badges with status icons.
- **CI/CD**: Fixed `vlaurin/action-ghcr-prune` inputs and authorization in the manual deployment pipeline by replacing `organization` with `user`, using the correct `prune-untagged` key, setting the target container name to `gotunnel`, and replacing `GITHUB_TOKEN` with `GHCR_TOKEN` to resolve permission and `Error: Not Found` issues.

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
