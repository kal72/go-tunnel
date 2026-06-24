# Web UI Manager

Web UI untuk mengelola file konfigurasi YAML dan memantau status tunnel secara real-time.

## Tech Stack

| Layer      | Library                  |
|------------|--------------------------|
| HTTP       | `chi` v5                 |
| Template   | `html/template` (stdlib) |
| YAML       | `gopkg.in/yaml.v3`       |
| Frontend   | Alpine.js + Tailwind CSS |
| Dev reload | `air`                    |

## Struktur Project

```
go-tunnel/
├── cmd/
│   └── webui/
│       └── main.go          # Entry point untuk Web UI
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
    ├── PANDUAN_PENGGUNAAN.md # Panduan dalam Bahasa Indonesia
    └── USAGE_GUIDE.md        # English Usage Guide
```

## Cara Menjalankan

### Development (dengan live reload)

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

## Fitur Utama

1.  **Dashboard**: Pantau client yang sedang terhubung, alamat IP, dan hostname yang digunakan.
2.  **Config Editor**: Edit file konfigurasi client secara langsung dari browser dengan preview YAML otomatis.
3.  **Domain Manager**: Kelola daftar subdomain yang diizinkan untuk tunnel.
4.  **Token Management**: Generate dan revoke token autentikasi client secara instan.
5.  **Dokumentasi Publik**: Halaman `/docs` yang dapat diakses publik untuk panduan pengaturan client.
