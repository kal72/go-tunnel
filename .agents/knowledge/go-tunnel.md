# Project Knowledge Item: `go-tunnel`

This file is a workspace-scoped Knowledge Item for the **`go-tunnel`** project, consolidating architectural audits, design decisions, and implementation roadmaps discussed during this session.

---

## 1. Project Overview & Architecture
`go-tunnel` is a Go-based reverse-tunneling gateway designed to expose private/local services over public TLS/HTTPS connections using:
- **ACME (`autocert.Manager`)**: Automatic Let's Encrypt TLS termination.
- **Yamux (`hashicorp/yamux`)**: Multiplexing multiple logical streams over a single outbound TLS connection.
- **Redis (`go-redis`)**: Session management, active tunnel registry, and dynamic domain allowlisting (wildcard and static).
- **Web UI Engine**: Alpine.js, Tailwind, and Go Templates to generate tokens, manage client configuration files, and monitor active tunnels.

---

## 2. Session Context & Diagnostic Findings

During the architectural audit performed in this session, the following critical issues were identified:

### A. Security Vulnerabilities
- **Hardcoded Secrets**: Admin credentials (`admin` / `admin123`) and the JWT signing key (`very-secret-key-change-me`) are hardcoded in `internal/webui/handler/auth.go`.
- **JWT Secret Discrepancy**: The `JWT_SECRET` loaded from `.env` in `cmd/webui/main.go` is only passed to the client token validator and is not used to sign the Web UI session cookies.
- **Cookie Settings**: The session cookie lacks `Secure` and `SameSite` flags.

### B. Concurrency & Performance Bottlenecks
- **Blocking Redis under Mutex**: The gateway checks domain authorization via Redis network calls (`IsDomainAllowed`) *inside* the global write lock (`s.mu.Lock()`) in `internal/tunnel/server/server.go`. Slow Redis performance blocks all connection lookups and teardowns.

### C. Protocol Limitations
- **HTTP/2 Hijacking Incompatibility**: The server negotiates HTTP/2 via TLS (`NextProtos`), but the raw TCP tunnel handlers hijack connection buffers, which is unsupported on standard Go HTTP/2 connections.

### D. Persistence Risks
- **Ephemeral Configurations**: Docker configurations lack a persistent volume mount for the Web UI configuration directory (`assets/configs/`), causing configuration changes to be lost on container recreation.

---

## 3. Approved Implementation Plan

The following step-by-step resolution roadmap has been structured:
1. **Phase 1: Security Hardening**
   - Parametrise Web UI credentials in `config.ServerConfig`.
   - Pass loaded `.env` secret keys to the Web UI auth handler.
   - Restructure cookie attributes for transport security.
2. **Phase 2: Mutex Optimization**
   - Refactor `handleClientConn` to perform Redis lookups outside the global critical lock section.
3. **Phase 3: Proxy Reliability**
   - Drop `"h2"` advertisement on TLS tunnels running in TCP mode.
   - Implement RFC-compliant proxy header scrubbing and inject `X-Forwarded-*` tags.
4. **Phase 4: Persistence**
   - Update `Dockerfile` and `cicd.yaml` to declare and mount `/app/assets/configs` as a persistent volume.
