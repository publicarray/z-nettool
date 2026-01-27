.PHONY: build clean test install

BINARY=netool
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-trimpath -ldflags="-s -w" -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)"

# Build the binary
build:
	go build $(LDFLAGS) -o $(BINARY) netool-linux.go
	@echo "Built $(BINARY) $(VERSION)"

# Clean build artifacts
clean:
	rm -f $(BINARY)
	go clean

# Install to system
install: build
	install -m 0755 $(BINARY) /usr/local/bin/

# Build for multiple architectures
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 netool-linux.go
	# GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64 netool-darwin.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-windows-amd64.exe netool-windows.go

# Static compilation
build-static:
	CGO_ENABLED=0 go build -a -installsuffix cgo $(LDFLAGS) -o $(BINARY) netool-linux.go
	@echo "Built static $(BINARY) $(VERSION)"

# Check dependencies
deps:
	go mod tidy
	go mod verify

# Format code
fmt:
	go fmt

# Lint code
lint:
	golangci-lint run

.DEFAULT_GOAL := help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  clean         - Clean build artifacts"
	@echo "  install       - Install to /usr/local/bin"
	@echo "  build-all     - Build for multiple architectures"
	@echo "  build-static  - Build static binary"
	@echo "  deps          - Check and verify dependencies"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run linter"
	@echo "  help          - Show this help"
