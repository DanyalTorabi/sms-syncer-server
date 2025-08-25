# Server Makefile

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

# Build the server
.PHONY: build
build:
	mkdir -p build
	go build -o build/sms-sync-server

# Run the server
.PHONY: run
run:
	go run .

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

# Help command
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make deps        - Install all dependencies"
	@echo "  make build       - Build the server"
	@echo "  make run         - Run the server"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make logs        - View info logs"
	@echo "  make logs-error  - View error logs"
	@echo "  make token       - Generate a JWT token"
	@echo "  make test-sms    - Test the SMS endpoint"
	@echo "  make test        - Run tests"
	@echo "  make fmt         - Format code"
	@echo "  make lint        - Lint code"
	@echo "  make help        - Show this help message" 