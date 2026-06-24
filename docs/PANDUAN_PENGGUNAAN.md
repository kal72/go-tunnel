# Panduan Penggunaan Go-Tunnel (Client)

Dokumentasi ini menjelaskan langkah-langkah untuk menghubungkan layanan lokal Anda ke internet menggunakan `go-tunnel`, mulai dari konfigurasi di sisi server (Web UI) hingga menjalankan client.

## 1. Persiapan di Web UI (Server)

Sebelum client dapat terhubung, Anda harus menyiapkan akses dan mendaftarkan subdomain di server melalui Web UI.

1. **Login ke Web UI**: Akses dashboard manajemen di browser (default port `8080`). Gunakan kredensial Anda (default: `admin` / `admin123`).
2. **Daftarkan Subdomain**:
   - Buka menu **Domain Manager**.
   - Tambahkan subdomain yang ingin Anda gunakan (misalnya `app.vpskamu.com`) secara manual, atau gunakan fitur *Generate Random* untuk membuat subdomain acak.
3. **Generate Auth Token**:
   - Buka menu **Token Management** atau **Client Config**.
   - Buat token baru untuk perangkat Anda dengan memasukkan *Client ID* (misalnya: `office-laptop`).
   - Salin **Auth Token** yang dihasilkan. Token ini akan digunakan di konfigurasi client.

> [!IMPORTANT]
> Pastikan subdomain yang Anda daftarkan sesuai dengan `WILDCARD_DOMAIN` atau telah diarahkan (CNAME/A Record) dengan benar di pengaturan DNS Anda.

---

## 2. Membuat File Konfigurasi (Client)

Di komputer lokal/client, Anda perlu membuat file konfigurasi berformat YAML.

1. Buat file bernama `config.yaml` di direktori yang sama dengan aplikasi client. (Anda juga bisa menyalin dari `config.yaml.example`).
2. Isi file tersebut dengan format berikut:

```yaml
# Koneksi ke listener tunnel di server VPS
tunnel_addr: "tunnel.vpskamu.com:9443"
skip_tls_verify: false

# Autentikasi dari Web UI
client_id: "office-laptop"
auth_token: "paste-token-from-dashboard"

# Mapping host -> target layanan lokal
tunnels:
  # Contoh untuk layanan HTTP (Web)
  - hostname: "app.vpskamu.com"
    target: "127.0.0.1:8080"
    mode: "http"
    
  # Contoh untuk layanan raw TCP (misal: SSH atau Database)
  - hostname: "ssh.vpskamu.com"
    target: "127.0.0.1:22"
    mode: "tcp"
```

**Penjelasan Konfigurasi:**
- `tunnel_addr`: Alamat dan port server tunnel Anda.
- `client_id`: Identifikasi unik untuk client ini.
- `auth_token`: Token yang disalin dari Web UI sebelumnya.
- `tunnels`: Daftar layanan lokal yang ingin diekspos. Pastikan `hostname` sudah didaftarkan di Domain Manager Web UI. `target` adalah alamat layanan lokal Anda yang sedang berjalan.

---

## 3. Menjalankan Client & Konek ke Tunnel

Setelah konfigurasi selesai, Anda siap untuk menghubungkan client ke server.

Jalankan perintah berikut di terminal komputer lokal Anda:

```bash
go run ./cmd/client/main.go
```
*(Jika Anda menggunakan file binary yang sudah di-build, cukup jalankan eksekusi binary-nya, misal: `./go-tunnel-client`)*

**Proses yang terjadi:**
1. Client akan membaca `config.yaml`.
2. Melakukan koneksi TLS ke `tunnel_addr`.
3. Mengirimkan `client_id` dan `auth_token` untuk divalidasi oleh server (via Redis).
4. Jika sukses, tunnel akan terbuka. Trafik dari internet yang menuju `hostname` (misal `app.vpskamu.com`) akan otomatis diteruskan ke `target` lokal (misal `127.0.0.1:8080`).

> [!TIP]
> Jika Anda mengalami kendala saat koneksi SSL/TLS lokal dengan self-signed certificate pada tahap ujicoba, Anda bisa mengubah `skip_tls_verify: true` di konfigurasi, namun **tidak disarankan** untuk lingkungan produksi.

---

## 4. Monitoring & Manajemen

- **Melihat Status**: Anda dapat memantau status perangkat yang sedang terhubung secara *real-time* di menu **Dashboard** pada Web UI. Anda akan melihat Client ID, IP sumber, hostname yang di-mapping, dan waktu koneksi.
- **Memutuskan Koneksi**: Jika Anda perlu memutuskan akses client secara paksa, masuk ke menu Token Management dan klik **Revoke**. Koneksi client akan langsung terputus dan token tersebut tidak bisa digunakan lagi.
