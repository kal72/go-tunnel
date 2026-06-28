# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Security**: XSS protection via Content Security Policy (CSP) and strict HTTP security headers middleware (`SecurityHeaders`).
- **Domain Management**: Restriction on Free Domain options in Web UI and backend validation when wildcard domain is unconfigured.
- **Auth & Tokens**: Admin action to revoke all JWT tokens for a specific user via Redis set index (`user_tokens:<userID>`).
- **Web UI**: Auto-redirect to `/login` when intercepting `401 Unauthorized` responses in fetch wrapper.
- **Documentation**: Added roadmap and future engineering backlog in `docs/ROADMAP.md`.

### Changed
- **Auth**: Separate JWT token expiration duration for Web UI sessions (`WEB_JWT_EXPIRE_HOURS`) and CLI sessions (`CLI_JWT_EXPIRE_HOURS`).
- **Reliability & Client Resilience**: Implement jittered exponential backoff for client agent connection retries (`gotunnel`) to prevent thundering herd problem.
- **Reliability & Gateway Proxy**: Implement graceful connection draining with a 30-second timeout on shutdown and double-close protection on `ChanListener`.
- **Web UI**: Improve sidebar navigation menu styling with dynamic active state indicator, coloring text and icons to match the menu item's unique color when selected.
- **Documentation**: Translate and expand Web UI portal documentation (`docs.html`) with TCP connection examples, detailed root domain CNAME guide, CLI reference table, troubleshooting FAQ, and standardized Table of Contents styling.
