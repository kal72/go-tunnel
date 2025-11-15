# ---------- Build stage ----------
FROM golang:1.25 AS builder

WORKDIR /app

# Copy module metadata untuk caching
COPY go.mod go.sum ./
RUN go mod download

# Copy semua source code
COPY . .

# Build binary statis (tanpa CGO, lebih ringan)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gotunnel-server ./cmd/server/main.go

# ---------- Runtime stage ----------
FROM alpine:3.20

# Install CA certificates (untuk HTTPS / Let's Encrypt)
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy hasil build
COPY --from=builder /app/gotunnel-server .
RUN mkdir -p /app/cert-cache

# Expose port:
# 80    -> HTTP-01 challenge (Let's Encrypt)
# 8443   -> HTTPS publik
# 9443  -> Tunnel TLS (client)
# 8081  -> Dashboard admin
EXPOSE 80 443 9443 8080

# Default command
CMD ["./gotunnel-server"]
