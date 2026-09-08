# ETC Collector - Makefile
# Go binary builder for multi-platform support

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "2.0.0-dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Strip 'v' prefix for release archive names
RELEASE_VERSION = $(patsubst v%,%,$(VERSION))

LDFLAGS := -s -w \
	-X main.Version=$(RELEASE_VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.BuildDate=$(BUILD_DATE)

BUILD_DIR := dist
BINARY := etc-collector
MODULE := github.com/etcsec-com/etc-collector

# Go settings
GO := go
GOFLAGS := -trimpath
CGO_ENABLED := 0

.PHONY: all build build-all test lint clean deps tidy help release latest-json sign

# Default target
all: deps build

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Tidy modules
tidy:
	$(GO) mod tidy

# Build local binary
build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/etc-collector

# Build for all platforms
build-all: build-linux build-darwin build-windows

# Linux builds
build-linux:
	@echo "Building for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/etc-collector
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-arm64 ./cmd/etc-collector

# macOS builds
build-darwin:
	@echo "Building for macOS..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./cmd/etc-collector
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/etc-collector

# Windows builds
build-windows:
	@echo "Building for Windows..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./cmd/etc-collector

# Run tests
test:
	$(GO) test -v -race -coverprofile=coverage.out ./...

# Run tests with coverage report
test-coverage: test
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Lint code
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: brew install golangci-lint"; \
	fi

# Format code
fmt:
	$(GO) fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

# Run the application
run:
	$(GO) run ./cmd/etc-collector $(ARGS)

# Run in server mode
run-server:
	$(GO) run ./cmd/etc-collector server $(ARGS)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Create release archives: etc-collector-{version}-{os}-{arch}.{ext}
# Each archive extracts to a directory containing the binary
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	@# Linux amd64
	@mkdir -p $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-linux-amd64
	@cp $(BUILD_DIR)/$(BINARY)-linux-amd64 $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-linux-amd64/$(BINARY)
	cd $(BUILD_DIR) && tar czf release/$(BINARY)-$(RELEASE_VERSION)-linux-amd64.tar.gz $(BINARY)-$(RELEASE_VERSION)-linux-amd64
	@# Linux arm64
	@mkdir -p $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-linux-arm64
	@cp $(BUILD_DIR)/$(BINARY)-linux-arm64 $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-linux-arm64/$(BINARY)
	cd $(BUILD_DIR) && tar czf release/$(BINARY)-$(RELEASE_VERSION)-linux-arm64.tar.gz $(BINARY)-$(RELEASE_VERSION)-linux-arm64
	@# macOS amd64
	@mkdir -p $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-darwin-amd64
	@cp $(BUILD_DIR)/$(BINARY)-darwin-amd64 $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-darwin-amd64/$(BINARY)
	cd $(BUILD_DIR) && tar czf release/$(BINARY)-$(RELEASE_VERSION)-darwin-amd64.tar.gz $(BINARY)-$(RELEASE_VERSION)-darwin-amd64
	@# macOS arm64
	@mkdir -p $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-darwin-arm64
	@cp $(BUILD_DIR)/$(BINARY)-darwin-arm64 $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-darwin-arm64/$(BINARY)
	cd $(BUILD_DIR) && tar czf release/$(BINARY)-$(RELEASE_VERSION)-darwin-arm64.tar.gz $(BINARY)-$(RELEASE_VERSION)-darwin-arm64
	@# Windows amd64
	@mkdir -p $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-windows-amd64
	@cp $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(BUILD_DIR)/$(BINARY)-$(RELEASE_VERSION)-windows-amd64/$(BINARY).exe
	cd $(BUILD_DIR) && zip -r release/$(BINARY)-$(RELEASE_VERSION)-windows-amd64.zip $(BINARY)-$(RELEASE_VERSION)-windows-amd64
	@# Checksums
	cd $(BUILD_DIR)/release && sha256sum *.tar.gz *.zip > checksums.sha256
	@# Generate latest.json
	@$(MAKE) latest-json
	@echo "Release artifacts in $(BUILD_DIR)/release/"

# Generate latest.json metadata file
latest-json:
	@echo "Generating latest.json..."
	@echo '{' > $(BUILD_DIR)/release/latest.json
	@echo '  "version": "$(RELEASE_VERSION)",' >> $(BUILD_DIR)/release/latest.json
	@echo '  "date": "$(shell date -u +%Y-%m-%d)",' >> $(BUILD_DIR)/release/latest.json
	@echo '  "checksums": "https://get.etcsec.com/downloads/checksums.sha256",' >> $(BUILD_DIR)/release/latest.json
	@echo '  "downloads": {' >> $(BUILD_DIR)/release/latest.json
	@echo '    "linux-amd64": "https://get.etcsec.com/downloads/$(BINARY)-$(RELEASE_VERSION)-linux-amd64.tar.gz",' >> $(BUILD_DIR)/release/latest.json
	@echo '    "linux-arm64": "https://get.etcsec.com/downloads/$(BINARY)-$(RELEASE_VERSION)-linux-arm64.tar.gz",' >> $(BUILD_DIR)/release/latest.json
	@echo '    "windows-amd64": "https://get.etcsec.com/downloads/$(BINARY)-$(RELEASE_VERSION)-windows-amd64.zip",' >> $(BUILD_DIR)/release/latest.json
	@echo '    "darwin-amd64": "https://get.etcsec.com/downloads/$(BINARY)-$(RELEASE_VERSION)-darwin-amd64.tar.gz",' >> $(BUILD_DIR)/release/latest.json
	@echo '    "darwin-arm64": "https://get.etcsec.com/downloads/$(BINARY)-$(RELEASE_VERSION)-darwin-arm64.tar.gz"' >> $(BUILD_DIR)/release/latest.json
	@echo '  }' >> $(BUILD_DIR)/release/latest.json
	@echo '}' >> $(BUILD_DIR)/release/latest.json

# Sign binaries (conditional - only runs if CODE_SIGN_PFX is set)
sign:
	@if [ -n "$(CODE_SIGN_PFX)" ]; then \
		echo "Signing Windows binary with Authenticode..."; \
		osslsigncode sign -pkcs12 "$(CODE_SIGN_PFX)" -pass "$(CODE_SIGN_PASSWORD)" \
			-n "ETC Collector" -i "https://etcsec.com" \
			-ts http://timestamp.digicert.com \
			-in $(BUILD_DIR)/$(BINARY)-windows-amd64.exe \
			-out $(BUILD_DIR)/$(BINARY)-windows-amd64-signed.exe && \
		mv $(BUILD_DIR)/$(BINARY)-windows-amd64-signed.exe $(BUILD_DIR)/$(BINARY)-windows-amd64.exe; \
	else \
		echo "CODE_SIGN_PFX not set, skipping code signing"; \
	fi

# Docker build
docker:
	docker build -t etcsec/etc-collector:$(RELEASE_VERSION) --build-arg VERSION=$(RELEASE_VERSION) .
	docker tag etcsec/etc-collector:$(RELEASE_VERSION) etcsec/etc-collector:latest

# Generate mocks (requires mockgen)
generate:
	$(GO) generate ./...

# Regenerate Doc() methods on every detector + the markdown catalogs.
# Two stages: (1) cataloggen rewrites docs_gen.go in each detector package
# from AST extraction of wrapFinding/types.Finding{} calls; (2) the pro
# binary's `audit catalog` subcommand renders the AD/Azure markdowns.
#
# Note: deliberately omit LDFLAGS so main.Version stays as the in-source
# string (e.g. "3.1.20") instead of git-describe output ("3.1.20-1-gXXX-dirty").
# That keeps the regenerated markdown stable across commits and matches
# TestCatalogIsStable's hardcoded catalogVersion constant.
.PHONY: catalog
catalog:
	$(GO) run ./tools/cataloggen
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/etc-collector
	$(BUILD_DIR)/$(BINARY) audit catalog --platform ad    --output ../docs/vulnerabilities/active-directory/AD_VULNERABILITY_CATALOG.md
	$(BUILD_DIR)/$(BINARY) audit catalog --platform azure --output ../docs/vulnerabilities/azure/AZURE_VULNERABILITY_CATALOG.md

# Check for outdated dependencies
outdated:
	$(GO) list -u -m all

# Security scan
security:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

# Generate RSA keys for JWT
keys:
	@mkdir -p keys
	openssl genrsa -out keys/private.pem 2048
	openssl rsa -in keys/private.pem -pubout -out keys/public.pem
	@chmod 600 keys/private.pem
	@echo "Keys generated in keys/ directory"

# Install locally
install-local: build
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(BINARY)"

# Show version info
version:
	@echo "Version: $(RELEASE_VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# Help
help:
	@echo "ETC Collector - Makefile targets"
	@echo ""
	@echo "Build:"
	@echo "  build        - Build local binary"
	@echo "  build-all    - Build for all platforms"
	@echo "  build-linux  - Build for Linux (amd64, arm64)"
	@echo "  build-darwin - Build for macOS (amd64, arm64)"
	@echo "  build-windows- Build for Windows (amd64)"
	@echo ""
	@echo "Development:"
	@echo "  run          - Run the application"
	@echo "  run-server   - Run in server mode"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo ""
	@echo "Release:"
	@echo "  release      - Build and package all platforms"
	@echo "  sign         - Sign Windows binary (requires CODE_SIGN_PFX)"
	@echo "  latest-json  - Generate latest.json metadata"
	@echo "  docker       - Build Docker image"
	@echo ""
	@echo "Maintenance:"
	@echo "  deps         - Download dependencies"
	@echo "  tidy         - Tidy modules"
	@echo "  clean        - Clean build artifacts"
	@echo "  outdated     - Check for outdated deps"
	@echo "  security     - Run security scan"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION) (release: $(RELEASE_VERSION))"
	@echo "  ARGS=        - Pass arguments to run targets"
