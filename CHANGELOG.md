# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **CI/CD**: Added cross-compile matrix validation for client binaries across 5 target platforms (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`) inside the automated quality checks workflow.
- **CI/CD**: Configured GitHub Actions PR labeler tool via `labeler.yml` for automated context tagging of pull requests based on changed paths.

### Changed
- **CI/CD**: Enhanced unit testing workflow with a 5-minute timeout flag (`-timeout 5m`) to prevent hung runners.

### Fixed
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
