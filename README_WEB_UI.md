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
│   ├── handler/config.go    # HTTP handlers
│   ├── model/config.go      # typed struct (ClientConfig, TunnelEntry)
│   ├── schema/schema.go     # schema definitions
│   └── service/config.go    # read/write YAML logic + auto-backup
└── web/
    └── templates/
        ├── base.html
        └── index.html       # Alpine.js form UI
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
| GET    | `/`                    | Halaman utama                    |
| GET    | `/api/configs`         | List semua file .yaml            |
| GET    | `/api/config/{name}`   | Baca config sebagai JSON         |
| PUT    | `/api/config/{name}`   | Simpan config (payload: JSON)    |

## Menambah Config File Baru

1. Buat file YAML baru di folder `configs/`, misalnya `configs/redis.yaml`
2. Tambahkan struct baru di `internal/model/` jika perlu typed validation
3. Restart server — file otomatis muncul di sidebar UI

## Fitur

- Form UI dengan input fields (text, number, toggle, select)
- Dynamic array editor untuk `tunnels[]`
- Input `jwt_secret` menggunakan `type="password"` + toggle show/hide
- YAML preview real-time (jwt_secret selalu di-mask di preview)
- Auto-backup `.yaml.bak` sebelum setiap save
- Seluruh asset di-embed ke binary (satu file executable)
