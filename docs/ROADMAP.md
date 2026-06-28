# Roadmap & Ide Pengembangan Masa Depan `go-tunnel`

Dokumen ini berisi daftar ide fitur, peningkatan sistem (*improvement*), dan rancangan arsitektur masa depan yang telah diverifikasi kelayakannya. Fitur-fitur ini dikelompokkan berdasarkan prioritas dan dampaknya terhadap sistem.

---

## 1. Observability & Analytics (Pantauan & Statistik)

### 1.1 Bandwidth & Traffic Analytics per Tunnel
- **Deskripsi:** Menghitung statistik aliran data (Bytes Sent/Received, Jumlah Request HTTP, Koneksi Aktif) untuk setiap sesi tunnel secara real-time.
- **Implementasi:** Menyimpan *counter* metrik di memori server atau Redis atomik (`INCRBY`), kemudian menampilkannya di halaman utama Web UI (*Dashboard*) dalam bentuk grafik visual atau kartu statistik.
- **Manfaat:** Memberikan visibilitas penuh kepada pengguna atas konsumsi data servis lokal mereka.

### 1.2 Live Request Inspector (Web UI / CLI)
- **Deskripsi:** Fitur inspeksi lalu lintas HTTP interaktif mirip seperti *inspector* lokal pada ngrok.
- **Implementasi:** Menyimpan riwayat singkat (misal: 50 request terakhir mencakup URL, HTTP Method, Status Code, durasi eksekusi, dan ukuran payload) di *ring buffer* memori atau Redis.
- **Manfaat:** Memudahkan developer melakukan *debugging* API webhook atau *backend* yang sedang dialirkan melalui tunnel tanpa harus membuka terminal log.

### 1.3 Admin Audit Logs
- **Deskripsi:** Mencatat setiap aktivitas krusial operasional ke dalam database.
- **Implementasi:** Membuat tabel `audit_logs` (mengandung kolom `user_id`, `action`, `target`, `ip_address`, `timestamp`). Aksi yang dicatat mencakup login, pencabutan token, pembuatan/penghapusan domain, dan perubahan status pengguna.
- **Manfaat:** Meningkatkan keandalan tata kelola sistem (*governance*) dan keamanan enterprise.

---

## 2. Security & Traffic Control (Keamanan & Proteksi)

### 2.1 Rate Limiting per Domain
- **Deskripsi:** Pembatasan jumlah request HTTP maksimal per menit/detik dari alamat IP publik menuju domain tunnel tertentu.
- **Implementasi:** Menambahkan *middleware limiter* berbasis *Token Bucket* atau Redis pada *reverse proxy gateway*.
- **Manfaat:** Melindungi server lokal (*target*) milik pengguna agar tidak lumpuh atau kehabisan sumber daya akibat serangan *DDoS* atau *brute-force*.

### 2.2 IP Allowlist / Blocklist per Domain
- **Deskripsi:** Fitur di Web UI yang memungkinkan pemilik domain mendaftarkan daftar IP publik yang diizinkan (*allowlist*) atau diblokir (*blocklist*).
- **Implementasi:** Pengecekan alamat IP asal sebelum *proxy gateway* meneruskan *stream* koneksi ke *yamux session* klien.
- **Manfaat:** Sangat krusial untuk mengamankan lingkungan pengembangan internal yang rahasia (misalnya hanya boleh diakses oleh IP kantor atau VPN internal tim).

### 2.3 Custom API Token Expiry
- **Deskripsi:** Fleksibilitas durasi masa berlaku token saat pembuatan kredensial baru.
- **Implementasi:** Menambahkan opsi pada UI dan *endpoint* pembuatan token agar pengguna dapat memilih masa aktif (misal: 7 hari, 30 hari, 1 tahun, atau tanpa kedaluwarsa).

---

## 3. Reliability & Client Resilience (Keandalan Sistem)

### 3.1 Jittered Exponential Backoff pada Client Agent
- **Deskripsi:** Memperbarui algoritma *reconnect* pada CLI `gotunnel` saat terputus dari server.
- **Implementasi:** Menambahkan jeda acak (*backoff jitter*) agar pengulangan koneksi tidak terjadi serentak.
- **Manfaat:** Mencegah masalah *Thundering Herd* (ribuan klien menembak server secara bersamaan) sesaat setelah server gateway mengalami *restart* atau gangguan jaringan sesaat.

### 3.2 Graceful Connection Draining
- **Deskripsi:** Mekanisme penutupan server proxy secara halus (*graceful shutdown*).
- **Implementasi:** Saat server menerima sinyal `SIGTERM`/`SIGINT`, server berhenti menerima koneksi baru namun menunggu (maksimal 30 detik) sampai request HTTP yang sedang berjalan selesai dieksekusi sebelum menutup *stream* TCP.
- **Manfaat:** Mencegah terputusnya unduhan file besar atau transaksi API krusial yang sedang berlangsung.

---

## 4. Arsitektur Tertunda: Mode Tunnel UDP (High Performance)

*Status: Tertunda (Deferred) — Dirancang pada Juni 2026*

### 4.1 Latar Belakang & Tantangan
Membungkus lalu lintas UDP ke dalam koneksi TCP standar memicu **TCP Head-of-Line (HoL) Blocking / Meltdown** saat terjadi *packet loss*, yang merusak latensi aplikasi *real-time* seperti Game Server (Minecraft, CS2), DNS, atau VPN.

### 4.2 Rancangan Solusi Performa Tinggi (Performance #1)
- **Persistent Stream Worker Pool:** Sesi tunnel UDP membuka kolam stream paralel persisten sejak awal untuk menghindari *overhead handshake* buka-tutup stream per paket.
- **Zero-Copy Buffer Pool (`sync.Pool`):** Mendaur ulang buffer 64KB untuk menekan *Garbage Collector (GC) pressure* hingga mendekati nol alokasi di jalur *hot-path*.
- **Non-Blocking Dropping Policy:** Jika jaringan tunnel sedang penuh (*congested*), server memprioritaskan pembuangan (*drop*) paket baru daripada menahannya di antrean memori, sesuai dengan filosofi *low latency* UDP.
- **Explicit Port Mapping:** Klien mendaftarkan nomor port UDP publik secara spesifik (misal: `30005`), dan server membuka *listener* UDP publik khusus di port tersebut yang disambungkan ke agen klien.
