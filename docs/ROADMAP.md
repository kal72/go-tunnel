# Roadmap & Future Architectural Ideas for `go-tunnel`

This document details future feature proposals, system enhancements, and long-term architectural blueprints validated for feasibility. These initiatives are categorized by priority and their structural impact on the overall ecosystem.

---

## 1. Observability & Analytics

### 1.1 Per-Tunnel Bandwidth & Traffic Analytics
- **Description:** Track data transfer statistics (Bytes Sent/Received, Total HTTP Requests, Active Connections) for every individual tunnel session in real-time.
- **Implementation:** Maintain atomic in-memory or Redis counters (`INCRBY`), presenting historical charts and live metrics across the Web UI dashboard.
- **Benefit:** Gives users granular visibility over data consumption and traffic patterns directed at their local services.

### 1.2 Live Request Inspector (Web UI / CLI)
- **Description:** Interactive HTTP request/response inspection utility similar to local inspection interfaces like ngrok.
- **Implementation:** Buffer the most recent ~50 requests (capturing URL, HTTP Method, Status Code, execution duration, and payload size) in an in-memory ring buffer or Redis stream.
- **Benefit:** Accelerates debugging for local webhook development and REST API testing without requiring developers to check terminal logs.

### 1.3 Admin Audit Logs
- **Description:** Record all critical administrative actions and lifecycle events inside the primary database.
- **Implementation:** Create an `audit_logs` table (`user_id`, `action`, `target`, `ip_address`, `timestamp`) logging events such as user logins, token revocations, domain creation/deletion, and user status updates.
- **Benefit:** Enhances platform governance, compliance, and enterprise-grade security oversight.

---

## 2. Security & Traffic Control

### 2.1 Per-Domain Rate Limiting
- **Description:** Limit the maximum allowable HTTP requests per second/minute from public IP addresses targeting specific tunnel subdomains.
- **Implementation:** Introduce a Token Bucket or Redis-backed rate limiting middleware inside the reverse proxy gateway (`gotunnel-proxy`).
- **Benefit:** Protects user local servers (`TUNNEL_TARGET`) from exhaustion, DDoS floods, and high-rate brute-force attempts.

### 2.2 Per-Domain IP Allowlist / Blocklist
- **Description:** Enable domain owners via the Web UI to define IP allowlists and blocklists for access restrictions.
- **Implementation:** Evaluate visitor IP addresses at the L7 reverse proxy layer before multiplexing streams over Yamux client connections.
- **Benefit:** Essential for securing internal staging environments, corporate intranets, or private APIs restricted to specific team IP ranges.

### 2.3 Custom API Token Expiry
- **Description:** Flexible expiration policies when generating new authentication tokens.
- **Implementation:** Expand Web UI schemas and API endpoints to allow users to select token durations (e.g., 7 days, 30 days, 1 year, or non-expiring).

---

## 3. Reliability & Client Resilience

### 3.1 Jittered Exponential Backoff in Client Agent
- **Description:** Upgrade the automatic reconnection logic across the `gotunnel` CLI client during network interruptions or gateway restarts.
- **Implementation:** Incorporate randomized jitter into the backoff retry delay calculation.
- **Benefit:** Prevents the *Thundering Herd* effect (thousands of agents simultaneously pounding the gateway after a brief server restart or network hiccup).

### 3.2 Graceful Connection Draining
- **Description:** Clean, non-disruptive termination mechanism (`graceful shutdown`) for edge and core services.
- **Implementation:** Upon intercepting `SIGTERM` / `SIGINT` signals, servers immediately cease accepting new incoming connections while allowing active HTTP/Yamux transactions a 30-second window to complete normally.
- **Benefit:** Prevents abruptly dropping active large file transfers or critical API transactions during deployments.

---

## 4. Deferred Architecture: High-Performance UDP Tunneling

*Status: Deferred — Originally designed June 2026*

### 4.1 Background & Engineering Challenges
Encapsulating UDP datagrams inside standard TCP streams causes **TCP Head-of-Line (HoL) Blocking and Meltdown** whenever packet loss occurs on the WAN. This completely degrades real-time latency-sensitive applications such as Game Servers (Minecraft, CS2), DNS, and VPN tunnels.

### 4.2 High-Performance Solution Blueprint (Performance #1)
- **Persistent Stream Worker Pool:** UDP tunnel sessions pre-open and maintain a pool of parallel persistent streams during registration, eliminating per-packet stream opening and teardown handshakes.
- **Zero-Copy Buffer Pool (`sync.Pool`):** Recycles 64KB UDP packet buffers, suppressing Garbage Collector (GC) pressure to achieve near-zero memory allocation on hot-path operations.
- **Non-Blocking Dropping Policy:** When a tunnel link experiences network congestion or buffer exhaustion, the server prioritizes dropping new incoming datagrams rather than queuing them in memory, adhering strictly to UDP low-latency semantics.
- **Explicit Port Mapping:** Clients register explicit public UDP port numbers (e.g., `30005`), instructing the server to open dedicated public UDP listeners directly wired to the client's multiplexed channel.
