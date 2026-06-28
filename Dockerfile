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
# 80    -> HTTP-01 ACME challenge
# 443   -> HTTPS publik & Edge Gateway Proxy (semua trafik masuk ke sini)
EXPOSE 80 443

# Gunakan array form (lebih aman, tidak wrap shell)
CMD ["./start.sh"]