# Server Makefile

GO_VERSION ?= 1.24.0
GOLANGCI_LINT_VERSION ?= v1.61.0
GOIMPORTS_VERSION ?= v0.30.0
DLV_VERSION ?= v1.24.0

# Default target when running 'make' without arguments
.PHONY: all
all: build run

# Install all dependencies
.PHONY: deps
deps:
	@echo "Installing all dependencies..."
	go get github.com/gin-gonic/gin
	go get github.com/mattn/go-sqlite3
	go get go.uber.org/zap
	go get gopkg.in/natefinch/lumberjack.v2
	go get github.com/golang-jwt/jwt/v5
	go mod tidy

# Install pinned development tools
.PHONY: install-tools
install-tools:
	@echo "Installing pinned development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install github.com/go-delve/delve/cmd/dlv@$(DLV_VERSION)

# Print local tool versions
.PHONY: verify-tools
verify-tools:
	@echo "Expected Go version: $(GO_VERSION)"
	@echo "Expected golangci-lint version: $(GOLANGCI_LINT_VERSION)"
	@echo "Go binary: $$(go version)"
	@echo "golangci-lint binary: $$(golangci-lint version | head -n1)"

# Build the server
.PHONY: build
build:
	mkdir -p build
	go build -o build/sms-sync-server ./cmd/server

# Run the server
.PHONY: run
run:
	go run ./cmd/server

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf build/

# View logs
.PHONY: logs
logs:
	@echo "Viewing logs..."
	@echo "Info logs:"
	@tail -f logs/info.log

.PHONY: logs-error
logs-error:
	@echo "Viewing error logs..."
	@tail -f logs/error.log

# Generate a JWT token (example)
.PHONY: token
token:
	@echo "Generating a JWT token..."
	@curl -X POST http://localhost:8080/auth/token -d '{"user_id":"123"}'

# Test the protected endpoint
.PHONY: test-sms
test-sms:
	@echo "Testing SMS endpoint..."
	@curl -X POST http://localhost:8080/api/sms/add \
		-H "Authorization: Bearer $(shell curl -s -X POST http://localhost:8080/auth/token -d '{"user_id":"123"}' | jq -r .token)" \
		-H "Content-Type: application/json" \
		-d '{"uuid":"123", "sender":"+1234567890", "message":"Hello", "timestamp":"2024-03-21T10:30:00Z", "retryCount":0}'

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test ./...

# Run tests with coverage
.PHONY: coverage
coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	golangci-lint run

# Check line length issues specifically
.PHONY: lint-line-length
lint-line-length:
	@echo "Checking line length issues..."
	golangci-lint run --enable-only=lll

# Run specific linter
.PHONY: lint-single
lint-single:
	@if [ -z "$(LINTER)" ]; then \
		echo "Error: LINTER is required. Usage: make lint-single LINTER=lll"; \
		echo "Available linters: lll, gofmt, govet, staticcheck, etc."; \
		exit 1; \
	fi
	@echo "Running $(LINTER) linter..."
	golangci-lint run --enable-only=$(LINTER)

# Fix auto-fixable linting issues
.PHONY: lint-fix
lint-fix:
	@echo "Auto-fixing linting issues..."
	golangci-lint run --fix

# Run security scanner
.PHONY: security
security:
	@echo "Running security scanner (gosec)..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "Error: gosec is not installed"; \
		echo "Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
		exit 1; \
	fi

# Setup git hooks for pre-commit linting
.PHONY: setup-hooks
setup-hooks:
	@echo "Setting up git hooks..."
	./scripts/setup-git-hooks.sh

# Release management
.PHONY: release-check
release-check:
	@echo "Checking if ready for release..."
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make release VERSION=v1.0.0"; \
		exit 1; \
	fi
	@if ! echo "$(VERSION)" | grep -qE "^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$$"; then \
		echo "Error: VERSION must be in format v1.2.3 or v1.2.3-alpha"; \
		exit 1; \
	fi
	@echo "Version format is valid: $(VERSION)"
	@echo "Running tests before release..."
	@go test ./...
	@echo "Running go vet..."
	@go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running linter..."; \
		golangci-lint run; \
	else \
		echo "Warning: golangci-lint not found, skipping lint check"; \
	fi
	@echo "All checks passed!"

.PHONY: release-tag
release-tag: release-check
	@echo "Creating release tag $(VERSION)..."
	@git tag -a $(VERSION) -m "Release $(VERSION)"
	@echo "Tag $(VERSION) created successfully"
	@echo "Push the tag with: git push origin $(VERSION)"

.PHONY: release-build
release-build:
	@echo "Building release binaries..."
	@mkdir -p dist
	@echo "Building for Linux (amd64)..."
	@GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION) -s -w" -o dist/sms-sync-server-$(VERSION)-linux-amd64 ./cmd/server
	@echo "Building for Linux (arm64)..."
	@GOOS=linux GOARCH=arm64 go build -ldflags="-X main.version=$(VERSION) -s -w" -o dist/sms-sync-server-$(VERSION)-linux-arm64 ./cmd/server
	@echo "Building for macOS (amd64)..."
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION) -s -w" -o dist/sms-sync-server-$(VERSION)-darwin-amd64 ./cmd/server
	@echo "Building for macOS (arm64)..."
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=$(VERSION) -s -w" -o dist/sms-sync-server-$(VERSION)-darwin-arm64 ./cmd/server
	@echo "Building for Windows (amd64)..."
	@GOOS=windows GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION) -s -w" -o dist/sms-sync-server-$(VERSION)-windows-amd64.exe ./cmd/server
	@echo "Generating checksums..."
	@cd dist && for file in sms-sync-server-$(VERSION)-*; do sha256sum "$$file" > "$$file.sha256"; done
	@echo "Release binaries built successfully in dist/"

.PHONY: release-local
release-local: release-check release-build
	@echo "Local release preparation completed!"
	@echo "Files created in dist/:"
	@ls -la dist/
	@echo ""
	@echo "To complete the release:"
	@echo "1. Review the binaries in dist/"
	@echo "2. Run: git push origin $(VERSION)"
	@echo "3. The GitHub Action will automatically create the release"

.PHONY: release
release: release-tag
	@echo "Pushing tag $(VERSION) to trigger release..."
	@git push origin $(VERSION)
	@echo "Release triggered! Check GitHub Actions for progress."

# Auto-increment release commands
.PHONY: release-patch
release-patch:
	@echo "Auto-incrementing patch version..."
	@NEW_VERSION=`./scripts/auto-version.sh patch 2>/dev/null` && \
	echo "New version will be: $$NEW_VERSION" && \
	$(MAKE) release VERSION=$$NEW_VERSION

.PHONY: release-minor
release-minor:
	@echo "Auto-incrementing minor version..."
	@NEW_VERSION=`./scripts/auto-version.sh minor 2>/dev/null` && \
	echo "New version will be: $$NEW_VERSION" && \
	$(MAKE) release VERSION=$$NEW_VERSION

.PHONY: release-major
release-major:
	@echo "Auto-incrementing major version..."
	@NEW_VERSION=`./scripts/auto-version.sh major 2>/dev/null` && \
	echo "New version will be: $$NEW_VERSION" && \
	$(MAKE) release VERSION=$$NEW_VERSION

.PHONY: release-prerelease
release-prerelease:
	@echo "Auto-incrementing prerelease version..."
	@NEW_VERSION=`./scripts/auto-version.sh prerelease alpha 2>/dev/null` && \
	echo "New version will be: $$NEW_VERSION" && \
	$(MAKE) release VERSION=$$NEW_VERSION

.PHONY: release-beta
release-beta:
	@echo "Auto-incrementing beta version..."
	@NEW_VERSION=`./scripts/auto-version.sh prerelease beta 2>/dev/null` && \
	echo "New version will be: $$NEW_VERSION" && \
	$(MAKE) release VERSION=$$NEW_VERSION

# Show next version without releasing
.PHONY: next-version
next-version:
	@echo "Next versions would be:"
	@echo -n "  Patch:      " && ./scripts/auto-version.sh patch 2>/dev/null
	@echo -n "  Minor:      " && ./scripts/auto-version.sh minor 2>/dev/null
	@echo -n "  Major:      " && ./scripts/auto-version.sh major 2>/dev/null
	@echo -n "  Prerelease: " && ./scripts/auto-version.sh prerelease alpha 2>/dev/null

# Version management
.PHONY: version
version:
	@if [ -n "$(shell git describe --tags --exact-match 2>/dev/null)" ]; then \
		echo "$(shell git describe --tags --exact-match)"; \
	else \
		echo "$(shell git describe --tags --always)-dev"; \
	fi

# Help command
.PHONY: help
help:
	@echo "Available commands:"
	@echo ""
	@echo "Development:"
	@echo "  make deps        - Install all dependencies"
	@echo "  make build       - Build the server"
	@echo "  make run         - Run the server"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make logs        - View info logs"
	@echo "  make logs-error  - View error logs"
	@echo "  make token       - Generate a JWT token"
	@echo "  make test-sms    - Test the SMS endpoint"
	@echo ""
	@echo "Testing & Quality:"
	@echo "  make test              - Run tests"
	@echo "  make coverage          - Run tests with coverage report"
	@echo "  make fmt               - Format code"
	@echo "  make lint              - Lint code (all linters)"
	@echo "  make lint-line-length  - Check line length issues (lll linter)"
	@echo "  make lint-single LINTER=<name> - Run specific linter"
	@echo "  make lint-fix          - Auto-fix linting issues"
	@echo "  make setup-hooks       - Setup git hooks for pre-commit linting"
	@echo ""
	@echo "Release Management:"
	@echo "  make release-check VERSION=v1.0.0  - Check if ready for release"
	@echo "  make release-tag VERSION=v1.0.0    - Create release tag"
	@echo "  make release-build VERSION=v1.0.0  - Build release binaries"
	@echo "  make release-local VERSION=v1.0.0  - Prepare local release"
	@echo "  make release VERSION=v1.0.0        - Create and push release tag"
	@echo ""
	@echo "Auto-Increment Release:"
	@echo "  make release-patch     - Auto-increment patch version and release"
	@echo "  make release-minor     - Auto-increment minor version and release"
	@echo "  make release-major     - Auto-increment major version and release"
	@echo "  make release-prerelease - Auto-increment prerelease version (alpha)"
	@echo "  make release-beta      - Auto-increment beta version"
	@echo "  make next-version      - Show what next versions would be"
	@echo "  make version           - Show current version"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run Docker container"
	@echo ""
	@echo "Auto-increment Release:"
	@echo "  make release-patch       - Auto-increment patch version and release"
	@echo "  make release-minor       - Auto-increment minor version and release"
	@echo "  make release-major       - Auto-increment major version and release"
	@echo "  make release-prerelease  - Auto-increment prerelease version and release"
	@echo "  make release-beta        - Auto-increment beta version and release"
	@echo "  make next-version        - Show next version numbers"
	@echo ""
	@echo "  make help        - Show this help message"
	@echo "  make release     - Create a new release"
	@echo "  make docker-build - Build the Docker image"
	@echo "  make docker-run   - Run the Docker container"
	@echo "  make version     - Show the current version"