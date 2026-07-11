# ---------- Build stage ----------
FROM golang:1.26-alpine AS builder
WORKDIR /app

# Copy module metadata untuk caching layer
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy semua source code
COPY . .

# Build binaries
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gotunnel-tunnel ./cmd/tunnel/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gotunnel-proxy ./cmd/proxy/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gotunnel-webui ./cmd/webui/main.go


# ---------- Runtime stage ----------
FROM alpine:3.20

# Install CA certificates (untuk HTTPS / Let's Encrypt)
RUN apk add --no-cache ca-certificates

WORKDIR /app

# OCI image metadata
LABEL org.opencontainers.image.source=https://github.com/kal72/go-tunnel
LABEL org.opencontainers.image.description="Self-hosted reverse tunneling gateway that exposes private services over public TLS/HTTPS with automatic Let's Encrypt certificates, Yamux multiplexing, and a built-in Web UI manager."
LABEL org.opencontainers.image.licenses=MIT

# Copy binaries dari builder
COPY --from=builder /app/gotunnel-tunnel .
COPY --from=builder /app/gotunnel-proxy .
COPY --from=builder /app/gotunnel-webui .

RUN mkdir -p /app/cert-cache

# Buat start script untuk menjalankan ketiga service
RUN printf '#!/bin/sh\nset -e\n./gotunnel-webui &\n./gotunnel-tunnel &\nexec ./gotunnel-proxy "$@"\n' \
    > /app/start.sh \
    && chmod +x /app/start.sh

# Expose ports:
# 80    -> HTTP-01 ACME challenge & Public HTTP Edge Proxy
# 443   -> HTTPS publik & Edge Gateway Proxy (semua trafik masuk ke sini)
# 8080  -> Web UI Dashboard (Internal/Pod access)
# 8443  -> Internal Gateway Port (Untuk diakses antar-Pod oleh gotunnel-proxy)
# 9443  -> Internal Tunnel Port (Untuk diakses antar-Pod oleh gotunnel-proxy atau agen langsung)
EXPOSE 80 443 8080 8443 9443

# Gunakan array form (lebih aman, tidak wrap shell)
CMD ["./start.sh"]