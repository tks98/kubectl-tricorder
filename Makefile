# Binary name for the kubectl plugin
BINARY_NAME=kubectl-tricorder

# Version information
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go related variables
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard *.go)

# Build flags
LDFLAGS=-ldflags "-w -s -X main.Version=$(VERSION)"

# Platform specific variables
UNAME_S:=$(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    GOOS=darwin
    GOARCH=amd64
    BINARY=$(GOBIN)/$(BINARY_NAME)
    INSTALL_DIR=/usr/local/bin
else
    GOOS=linux
    GOARCH=amd64
    BINARY=$(GOBIN)/$(BINARY_NAME)
    INSTALL_DIR=~/.local/bin
endif

# Ensure the bin directory exists
$(GOBIN):
	mkdir -p $(GOBIN)

# Default target
all: clean build

# Build the binary
build: $(GOBIN)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o $(BINARY) $(GOFILES)

# Build for all platforms
build-all: clean
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-amd64 $(GOFILES)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-linux-amd64 $(GOFILES)

# Clean build artifacts
clean:
	rm -rf $(GOBIN)

# Install the plugin locally
install: build
	@if [ "$(UNAME_S)" = "Darwin" ]; then \
		sudo mkdir -p $(INSTALL_DIR); \
		sudo cp $(BINARY) $(INSTALL_DIR)/$(BINARY_NAME); \
		echo "Installed to $(INSTALL_DIR)/$(BINARY_NAME)"; \
	else \
		mkdir -p $(INSTALL_DIR); \
		cp $(BINARY) $(INSTALL_DIR)/$(BINARY_NAME); \
		echo "Installed to $(INSTALL_DIR)/$(BINARY_NAME)"; \
	fi

# Run tests
test:
	go test -v ./...

# Run linter
lint:
	golangci-lint run

# Show help
help:
	@echo "Available targets:"
	@echo "  all        - Clean and build for current platform"
	@echo "  build      - Build for current platform"
	@echo "  build-all  - Build for all platforms (darwin, linux)"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install the plugin locally"
	@echo "  test       - Run tests"
	@echo "  lint       - Run linter"
	@echo "  help       - Show this help message"

.PHONY: all build build-all clean install test lint help 