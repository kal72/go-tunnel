.PHONY: all build test generate run-server run-webui podman-build podman-run podman-stop clean

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGENERATE=$(GOCMD) generate
SERVER_BINARY=./bin/gotunnel-server
WEBUI_BINARY=./bin/gotunnel-webui
CLIENT_BINARY=./bin/gotunnel-client

# Podman parameters
IMAGE_NAME=gotunnel
CONTAINER_NAME=tunnel

all: generate build test

build:
	@echo "Building binaries..."
	$(GOBUILD) -o $(SERVER_BINARY) ./cmd/server/main.go
	$(GOBUILD) -o $(WEBUI_BINARY) ./cmd/webui/main.go
	$(GOBUILD) -o $(CLIENT_BINARY) ./cmd/client/main.go


test:
	@echo "Running unit tests..."
	$(GOTEST) -v -race ./...

generate:
	@echo "Generating mocks with mockery..."
	$(GOGENERATE) ./...

run-server:
	@echo "Starting server..."
	$(GOCMD) run ./cmd/server/main.go

run-webui:
	@echo "Starting Web UI..."
	$(GOCMD) run ./cmd/webui/main.go

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
	rm -f $(SERVER_BINARY) $(WEBUI_BINARY)
