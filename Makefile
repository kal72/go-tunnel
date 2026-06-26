.PHONY: all build test generate run-server run-webui podman-build podman-run podman-stop clean migrate-up migrate-down

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGENERATE=$(GOCMD) generate
PROXY_BINARY=./bin/gotunnel-proxy
SERVER_BINARY=./bin/gotunnel-server
WEBUI_BINARY=./bin/gotunnel-webui
CLIENT_BINARY=./bin/gotunnel-client

# Podman parameters
IMAGE_NAME=gotunnel
CONTAINER_NAME=tunnel

ifneq (,$(wildcard ./.env))
    include .env
    export
endif

DB_HOST ?= localhost
DB_PORT ?= 5432
DB_USER ?= postgres
DB_PASS ?= postgres
DB_NAME ?= gotunnel

# DB parameters
DB_URL ?= "postgres://$(DB_USER):$(DB_PASS)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable"

SERVER_URL ?= https://tun.yourdomain.com
VERSION ?= v0.0

all: generate build test

build:
	@echo "Building binaries..."
	$(GOBUILD) -o $(SERVER_BINARY) ./cmd/tunnel/main.go
	$(GOBUILD) -o $(PROXY_BINARY) ./cmd/proxy/main.go
	$(GOBUILD) -o $(WEBUI_BINARY) ./cmd/webui/main.go
	$(GOBUILD) -o $(CLIENT_BINARY) ./cmd/client/main.go

build-clients:
	@echo "Building cross-platform clients to ./downloads..."
	@mkdir -p ./downloads
	@sed 's|{{DL_URL}}|$(SERVER_URL)/dl|g' ./scripts/install/install.sh.tmpl > ./downloads/install.sh || true
	@sed 's|{{DL_URL}}|$(SERVER_URL)/dl|g' ./scripts/install/install.cmd.tmpl > ./downloads/install.cmd || true
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags="-X main.ServerURL=$(SERVER_URL) -X main.version=$(VERSION)" -o ./downloads/gotunnel-darwin-amd64 ./cmd/client/main.go
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags="-X main.ServerURL=$(SERVER_URL) -X main.version=$(VERSION)" -o ./downloads/gotunnel-darwin-arm64 ./cmd/client/main.go
	GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="-X main.ServerURL=$(SERVER_URL) -X main.version=$(VERSION)" -o ./downloads/gotunnel-linux-amd64 ./cmd/client/main.go
	GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags="-X main.ServerURL=$(SERVER_URL) -X main.version=$(VERSION)" -o ./downloads/gotunnel-linux-arm64 ./cmd/client/main.go
	GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="-X main.ServerURL=$(SERVER_URL) -X main.version=$(VERSION)" -o ./downloads/gotunnel-windows-amd64.exe ./cmd/client/main.go

test:
	@echo "Running unit tests..."
	$(GOTEST) -v -race ./...

generate:
	@echo "Generating mocks with mockery..."
	$(GOGENERATE) ./...

run-server:
	@echo "Starting server..."
	$(GOCMD) run ./cmd/tunnel/main.go

run-webui:
	@echo "Starting Web UI..."
	$(GOCMD) run ./cmd/webui/main.go

run-proxy:
	@echo "Starting proxy..."
	$(GOCMD) run ./cmd/proxy/main.go

# Podman Targets
deploy: podman-stop podman-build podman-run

podman-build:
	@echo "Building image with Podman..."
	podman build -t $(IMAGE_NAME):latest .

podman-run: podman-stop
	@echo "Running container with Podman..."
	podman run -d --name $(CONTAINER_NAME) \
		-p 80:80 -p 443:443 -p 9443:9443 -p 8080:8080 \
		-v $(shell pwd)/cert-cache:/app/cert-cache:Z \
		--env-file .env \
		$(IMAGE_NAME):latest

podman-stop:
	@echo "Stopping and removing container..."
	@podman stop $(CONTAINER_NAME) >/dev/null 2>&1 || true
	@podman rm $(CONTAINER_NAME) >/dev/null 2>&1 || true

clean:
	@echo "Cleaning up binaries..."
	rm -f $(SERVER_BINARY) $(WEBUI_BINARY) $(CLIENT_BINARY)

migrate-up:
	@echo "Running migrations up..."
	migrate -path db/migrations -database $(DB_URL) up

migrate-down:
	@echo "Running migrations down..."
	migrate -path db/migrations -database $(DB_URL) down -all

lint:
	@echo "Running golangci linter..."
	golangci-lint run
