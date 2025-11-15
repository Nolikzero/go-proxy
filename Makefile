# Go Proxy Makefile

# Variables
BINARY_NAME=go-proxy
BINARY_PATH=./bin/$(BINARY_NAME)
DOCKER_IMAGE=go-proxy
DOCKER_TAG=latest
GO_VERSION=1.21

# Build information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"
BUILD_FLAGS=-trimpath $(LDFLAGS)

# Default target
.PHONY: all
all: clean build

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  run            - Run the application"
	@echo "  test           - Run tests"
	@echo "  test-verbose   - Run tests with verbose output"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  clean          - Clean build artifacts"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  lint           - Run golangci-lint (requires golangci-lint)"
	@echo "  deps           - Download dependencies"
	@echo "  tidy           - Tidy go modules"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  docker-push    - Push Docker image"
	@echo "  compose-up     - Start with docker-compose"
	@echo "  compose-down   - Stop docker-compose"
	@echo "  install        - Install binary to GOPATH/bin"
	@echo "  release        - Build release binaries for multiple platforms"

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	go build $(BUILD_FLAGS) -o $(BINARY_PATH) .
	@echo "Binary built: $(BINARY_PATH)"

# Run the application
.PHONY: run
run:
	@echo "Running $(BINARY_NAME)..."
	go run .

# Run with example configuration
.PHONY: run-example
run-example:
	@echo "Running $(BINARY_NAME) with example configuration..."
	PROXY_PORT=8080 \
	PROXY_LOG_LEVEL=debug \
	PROXY_LOG_FORMAT=text \
	go run .

# Run with auth enabled
.PHONY: run-auth
run-auth:
	@echo "Running $(BINARY_NAME) with authentication..."
	PROXY_PORT=8080 \
	PROXY_REQUIRE_AUTH=true \
	PROXY_AUTH_USER=admin \
	PROXY_AUTH_PASSWORD=secret123 \
	PROXY_LOG_LEVEL=debug \
	go run .

# Test targets
.PHONY: test
test:
	@echo "Running tests..."
	go test -race -short ./...

.PHONY: test-verbose
test-verbose:
	@echo "Running tests with verbose output..."
	go test -race -v ./...

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Benchmark tests
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Code quality targets
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

.PHONY: vet
vet:
	@echo "Running go vet..."
	go vet ./...

.PHONY: lint
lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2"; exit 1)
	golangci-lint run

# Dependency management
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	go mod download

.PHONY: tidy
tidy:
	@echo "Tidying go modules..."
	go mod tidy

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	go clean

# Docker targets
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

.PHONY: docker-run
docker-run: docker-build
	@echo "Running Docker container..."
	docker run --rm -p 8080:8080 --name $(BINARY_NAME) $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: docker-run-daemon
docker-run-daemon: docker-build
	@echo "Running Docker container in background..."
	docker run -d -p 8080:8080 --name $(BINARY_NAME) $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: docker-stop
docker-stop:
	@echo "Stopping Docker container..."
	docker stop $(BINARY_NAME) || true
	docker rm $(BINARY_NAME) || true

.PHONY: docker-push
docker-push: docker-build
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

# Docker Compose targets
.PHONY: compose-up
compose-up:
	@echo "Starting services with docker-compose..."
	docker-compose up -d

.PHONY: compose-down
compose-down:
	@echo "Stopping services with docker-compose..."
	docker-compose down

.PHONY: compose-logs
compose-logs:
	@echo "Showing docker-compose logs..."
	docker-compose logs -f

.PHONY: compose-restart
compose-restart:
	@echo "Restarting services with docker-compose..."
	docker-compose restart

# Installation
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp $(BINARY_PATH) $(GOPATH)/bin/$(BINARY_NAME)
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

# Release builds for multiple platforms
.PHONY: release
release: clean
	@echo "Building release binaries..."
	@mkdir -p bin/release
	
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o bin/release/$(BINARY_NAME)-linux-amd64 .
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o bin/release/$(BINARY_NAME)-linux-arm64 .
	
	# Darwin AMD64 (Intel Mac)
	GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -o bin/release/$(BINARY_NAME)-darwin-amd64 .
	
	# Darwin ARM64 (M1 Mac)
	GOOS=darwin GOARCH=arm64 go build $(BUILD_FLAGS) -o bin/release/$(BINARY_NAME)-darwin-arm64 .
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o bin/release/$(BINARY_NAME)-windows-amd64.exe .
	
	@echo "Release binaries built in bin/release/"
	@ls -la bin/release/

# Development helpers
.PHONY: dev
dev: fmt vet test build

.PHONY: check
check: fmt vet lint test

# Watch for changes and rebuild (requires entr: brew install entr)
.PHONY: watch
watch:
	@echo "Watching for changes... (requires 'entr' command)"
	find . -name '*.go' | entr -r make run

# Create a new release tag
.PHONY: tag
tag:
	@read -p "Enter new version (e.g., v1.0.0): " version && \
	git tag $$version && \
	git push origin $$version

# Show project information
.PHONY: info
info:
	@echo "Project Information:"
	@echo "  Binary Name: $(BINARY_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo "  Git Commit: $(GIT_COMMIT)"
	@echo "  Go Version: $(shell go version)"
	@echo "  Docker Image: $(DOCKER_IMAGE):$(DOCKER_TAG)"

# Initialize git hooks (optional)
.PHONY: hooks
hooks:
	@echo "Setting up git hooks..."
	@mkdir -p .git/hooks
	@echo "#!/bin/sh\nmake check" > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed"