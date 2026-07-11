# Web UI Manager

Web UI dashboard for managing YAML configuration files, API tokens, and real-time tunnel monitoring.

## Tech Stack

| Layer | Library |
| :--- | :--- |
| HTTP | `chi` v5 |
| Template | `html/template` (stdlib) |
| YAML | `gopkg.in/yaml.v3` |
| Frontend | Alpine.js + Tailwind CSS |
| Dev reload | `air` |

## Project Structure

```
go-tunnel/
├── cmd/
│   └── webui/
│       └── main.go          # Entry point for Web UI
├── internal/
│   ├── webui/
│   │   ├── handler/
│   │   │   ├── auth.go      # JWT Auth handlers
│   │   │   └── config.go    # HTTP handlers (Dashboard, Configs, Domains, Docs)
│   │   ├── model/           # Data models
│   │   ├── schema/          # Validation schemas
│   │   └── service/         # Business logic
│   └── tunnel/              # Tunnel core logic
├── assets/
│   └── templates/
│       ├── base.html
│       ├── index.html       # Config editor UI
│       ├── dashboard.html   # Active tunnels dashboard
│       ├── domains.html     # Domain management UI
│       ├── docs.html        # Public documentation page
│       └── login.html       # Login portal UI
└── docs/
    └── USAGE_GUIDE.md       # Client Usage Guide
```

## Running Locally

### Development (with live reload)

```bash
go install github.com/air-verse/air@latest
go mod tidy
air
```

### Production

```bash
go mod tidy
go build -o webui ./cmd/webui/main.go
./webui
```

## Key Features

1. **Dashboard**: Monitor active connected clients, remote IP addresses, and assigned hostnames in real-time.
2. **Config Editor**: Directly edit client configuration files from your web browser with live YAML validation and preview.
3. **Domain Manager**: Manage whitelisted and custom subdomains permitted for client tunnel mapping.
4. **Token Management**: Instantly generate, inspect, and revoke client authentication tokens.
5. **Public Documentation**: Accessible `/docs` page providing setup instructions and quick start commands for client devices.
