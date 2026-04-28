# Config Manager

Web UI untuk mengelola file konfigurasi YAML, dibangun dengan Go monolith.

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
config-manager/
├── main.go
├── go.mod
├── .air.toml
├── configs/
│   └── client.yaml          # file konfigurasi yang dikelola
├── internal/
│   ├── handler/
│   │   ├── auth.go          # JWT Auth handlers
│   │   └── config.go        # HTTP handlers (Configs & Domains)
│   ├── model/config.go      # typed struct (ClientConfig, TunnelEntry)
│   ├── service/config.go    # read/write YAML logic + auto-backup
│   └── tunnel/state/redis.go # Redis store implementation
└── assets/
    └── templates/
        ├── base.html
        ├── index.html       # Config editor UI
        ├── dashboard.html   # Active tunnels dashboard
        └── domains.html     # Domain management UI
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
go build -o config-manager .
./config-manager
```

Buka browser: http://localhost:8080

## API Endpoints

| Method | Path                   | Deskripsi                        |
|--------|------------------------|----------------------------------|
| GET    | `/`                    | Dashboard Tunnel Aktif           |
| GET    | `/configs`             | Halaman Config Manager           |
| GET    | `/domains`             | Halaman Domain Manager           |
| GET    | `/api/configs`         | List semua file .yaml            |
| GET    | `/api/config/{name}`   | Baca config sebagai JSON         |
| PUT    | `/api/config/{name}`   | Simpan config (payload: JSON)    |
| POST   | `/api/config/{name}`   | Buat config baru                 |
| DELETE | `/api/config/{name}`   | Hapus config + cabut token       |
| GET    | `/api/domains`         | List domain/wildcard dari Redis  |
| POST   | `/api/domains`         | Tambah subdomain (manual/random) |
| DELETE | `/api/domains/{domain}` | Hapus domain dari Redis          |
| GET    | `/api/generate-token`  | Generate token HMAC client       |
| DELETE | `/api/revoke-token`    | Cabut token client secara paksa  |

## Menambah Config File Baru

1. Buat file YAML baru di folder `configs/`, misalnya `configs/redis.yaml`
2. Tambahkan struct baru di `internal/model/` jika perlu typed validation
3. Restart server — file otomatis muncul di sidebar UI

## Fitur

- Active Tunnel Dashboard (real-time dari Redis)
- Domain & Wildcard Management (simpan di Redis)
- Form UI dengan input fields (text, number, toggle, select)
- Dynamic array editor untuk `tunnels[]`
- Input `jwt_secret` menggunakan `type="password"` + toggle show/hide
- YAML preview real-time (jwt_secret selalu di-mask di preview)
- Auto-backup `.yaml.bak` sebelum setiap save
- JWT Authentication (Default: `admin`/`admin123`)
- Seluruh asset di-embed ke binary (satu file executable)
