# ---------- Build stage ----------
FROM golang:1.26-alpine AS builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy module metadata untuk caching layer
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy semua source code
COPY . .

# Build binaries dengan optimasi size & security
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags="-w -s -extldflags '-static'" \
      -trimpath \
      -o gotunnel-server ./cmd/server/main.go

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags="-w -s -extldflags '-static'" \
      -trimpath \
      -o gotunnel-webui ./cmd/webui/main.go

# ---------- Runtime stage ----------
FROM alpine:3.20

# Install runtime deps dalam 1 layer
RUN apk add --no-cache ca-certificates tzdata \
    && update-ca-certificates \
    # Buat non-root user lebih awal (best practice)
    && adduser -D -H -s /sbin/nologin gotunnel \
    # Buat direktori & set permission sekaligus
    && mkdir -p /app/cert-cache /app/assets/configs \
    && chown -R gotunnel:gotunnel /app

WORKDIR /app

# Copy binaries dari builder
COPY --from=builder --chown=gotunnel:gotunnel /app/gotunnel-server .
COPY --from=builder --chown=gotunnel:gotunnel /app/gotunnel-webui .

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

USER gotunnel

# Gunakan array form (lebih aman, tidak wrap shell)
CMD ["./start.sh"]