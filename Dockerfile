# ---------- Build stage ----------
FROM golang:1.26-alpine AS builder
WORKDIR /app

# Copy module metadata untuk caching layer
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy semua source code
COPY . .

# Build binaries
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gotunnel-server ./cmd/server/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gotunnel-webui ./cmd/webui/main.go


# ---------- Runtime stage ----------
FROM alpine:3.20

# Install CA certificates (untuk HTTPS / Let's Encrypt)
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binaries dari builder
COPY --from=builder --chown=gotunnel:gotunnel /app/gotunnel-server .
COPY --from=builder --chown=gotunnel:gotunnel /app/gotunnel-webui .


RUN mkdir -p /app/assets/configs
COPY --from=builder /app/assets/configs/client.yaml /app/assets/configs/client.yaml
RUN mkdir -p /app/cert-cache

# Buat start script langsung (tanpa URL encoding)
RUN printf '#!/bin/sh\nset -e\n./gotunnel-webui &\nexec ./gotunnel-server "$@"\n' \
    > /app/start.sh \
    && chmod +x /app/start.sh

# Expose ports:
# 80    -> HTTP-01 ACME challenge
# 443   -> HTTPS publik
# 9443  -> Tunnel TLS
# 8080  -> Tunnel Manager (WebUI)
EXPOSE 80 443 9443 8080

# Gunakan array form (lebih aman, tidak wrap shell)
CMD ["./start.sh"]