# SMS Sync Server

A robust, production-ready SMS synchronization server built with Go, featuring JWT authentication, comprehensive testing, and enterprise-grade CI/CD pipeline.

## 🚀 Features

- **REST API** for SMS message management with JWT authentication
- **Real-time SMS synchronization** with comprehensive validation
- **Health monitoring** with detailed status endpoints
- **Database operations** with SQLite support and migrations
- **Enterprise security** with middleware and input validation
- **Comprehensive testing** with 86%+ code coverage
- **CI/CD pipeline** with automated testing, linting, and security scanning
- **Branch protection** with required reviews and status checks

## Prerequisites

- Go 1.24.0
- Git

## Setup

1. Clone the repository
2. Navigate to the Server directory
3. Install dependencies:
   ```bash
   go mod tidy
   ```

## Configuration

The server can be configured using environment variables. Copy `.env.example` to `.env` and configure as needed:

```bash
cp .env.example .env
```

**Required Environment Variables:**
- `JWT_SECRET` - Secret key for JWT token generation (generate with: `openssl rand -base64 32`)
- `TOTP_ENCRYPTION_KEY` - 32-byte hex key for TOTP encryption (generate with: `openssl rand -hex 32`)

**Optional Environment Variables:**
- `SERVER_PORT` - Port to listen on (default: 8080)
- `SERVER_HOST` - Host to bind to (default: localhost)
- `TLS_ENABLED` - Enable HTTPS/TLS mode (default: false)
- `TLS_CERT_FILE` - TLS certificate file path (required when TLS_ENABLED=true)
- `TLS_KEY_FILE` - TLS private key file path (required when TLS_ENABLED=true)
- `DATABASE_DSN` - Database connection string (default: file:sms.db?cache=shared&mode=rwc)
- `LOG_LEVEL` - Logging level: debug, info, warn, error (default: info)
- `JWT_TOKEN_EXPIRY` - JWT token expiry duration (default: 1h)
- `ADMIN_USERNAME` - Default admin username (default: admin)
- `ADMIN_PASSWORD` - Default admin password (default: admin123)

See [`.env.example`](.env.example) for comprehensive configuration documentation.

## Running the Server

```bash
go run cmd/server/main.go
```

### Run Local HTTPS (Self-Signed)

```bash
# Generate local certificate + key and run HTTPS server
make run-https-local

# Health check over HTTPS (skip verification for self-signed cert)
curl -k https://localhost:8080/health
```

To generate certs only:

```bash
make tls-cert
```

Generated files are stored in `certs/dev/` and ignored by git.

## API Endpoints

### Health Check
```
GET /health
```
Returns server status and current time.

### Authentication
```
POST /api/auth/login
Content-Type: application/json

{
  "username": "string",
  "password": "string"
}
```
Returns a JWT token for authentication.

### Add SMS
```
POST /api/sms/add
Content-Type: application/json
Authorization: Bearer <jwt-token>

{
  "phone_number": "string",
  "body": "string",
  "event_type": "string",
  "sms_timestamp": number,
  "event_timestamp": number
}
```

## 🛠️ Development

For detailed development information, see our [Development Guide](docs/DEVELOPMENT.md).

### Quick Start

```bash
# Clone and setup
git clone https://github.com/DanyalTorabi/sms-syncer-server.git
cd sms-syncer-server
go mod tidy

# Run tests
make test

# Run tests with coverage
make coverage

# Format code
make fmt

# Lint code
make lint

# Verify local tool versions match CI
make verify-tools

# Check specific linting issues
make lint-line-length        # Check line length issues (lll linter)
make lint-single LINTER=lll  # Run specific linter
make lint-fix                # Auto-fix linting issues

# Build for production  
make build
```

### Git Hooks Setup

To ensure code quality and prevent linting issues in CI, set up pre-commit hooks that run the same linters as our GitHub Actions:

```bash
# Setup git hooks (one-time setup)
./scripts/setup-git-hooks.sh
```

This will automatically install and configure:
- **gofmt** - Go code formatting
- **go vet** - Go static analysis
- **golangci-lint** - Comprehensive linting (same config as CI)
- **go mod verify** - Module integrity checks

The hooks will run automatically before each commit. To bypass in emergency situations:
```bash
git commit --no-verify
```

## 📦 Installation & Releases

### Download Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/DanyalTorabi/sms-syncer-server/releases):

```bash
# Linux (x64)
curl -L -o sms-sync-server https://github.com/DanyalTorabi/sms-syncer-server/releases/latest/download/sms-sync-server-linux-amd64
chmod +x sms-sync-server
./sms-sync-server

# macOS (Apple Silicon)
curl -L -o sms-sync-server https://github.com/DanyalTorabi/sms-syncer-server/releases/latest/download/sms-sync-server-darwin-arm64
chmod +x sms-sync-server
./sms-sync-server

# Check version
./sms-sync-server -version
```

### Docker

```bash
# Pull and run latest release
docker pull ghcr.io/danyaltorabi/sms-syncer-server:latest
docker run -p 8080:8080 ghcr.io/danyaltorabi/sms-syncer-server:latest

# Or use docker-compose
cat > docker-compose.yml << EOF
version: '3.8'
services:
  sms-server:
    image: ghcr.io/danyaltorabi/sms-syncer-server:latest
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
EOF

docker-compose up
```

### Build from Source

```bash
git clone https://github.com/DanyalTorabi/sms-syncer-server.git
cd sms-syncer-server
make build
./build/sms-sync-server
```

### Project Structure

```
sms-sync-server/
├── .github/                    # GitHub workflows and templates
│   ├── workflows/ci.yml       # CI/CD pipeline
│   ├── CODEOWNERS             # Code review assignments
│   └── ISSUE_TEMPLATE/        # Issue templates
├── cmd/server/                # Application entry point
├── docs/                      # Documentation
│   ├── CONTRIBUTING.md        # Contribution guidelines
│   ├── DEVELOPMENT.md         # Development setup
│   ├── DEPLOYMENT.md          # Deployment guide
│   └── BRANCH_STRATEGY.md     # Git workflow
├── internal/                  # Private application code
│   ├── api/                   # API layer
│   ├── config/                # Configuration management
│   ├── db/                    # Database operations
│   ├── handlers/              # HTTP handlers + integration tests
│   ├── models/                # Data models
│   └── services/              # Business logic
├── pkg/                       # Public packages
│   ├── logger/                # Logging utilities
│   ├── middleware/            # HTTP middleware
│   └── utils/                 # Shared utilities
├── router/                    # HTTP routing
├── .golangci.yml             # Linting configuration
├── Makefile                  # Build automation
├── postman-collection.json   # API testing collection
└── sms-message-schema.json   # JSON schema for SMS messages
```

### 🧪 Testing

- **Unit Tests**: `go test ./...` or `make test`
- **Integration Tests**: `go test -tags=integration ./internal/handlers/`
- **Coverage Report**: `make coverage`
- **Linting**: `make lint`

Current test coverage: **86%+**

## 🔒 Security

- JWT authentication for all SMS endpoints
- Input validation and sanitization
- SQL injection protection
- Rate limiting middleware
- Security scanning in CI pipeline
- Branch protection with required reviews

See [Security Documentation](docs/DEVELOPMENT.md#security) for details.

## 📚 Documentation

- **[Contributing Guidelines](docs/CONTRIBUTING.md)** - How to contribute to this project
- **[Development Setup](docs/DEVELOPMENT.md)** - Local development environment setup  
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[Database Schema](docs/DATABASE_SCHEMA.md)** - Complete database schema documentation with ER diagrams
- **[Release Process](docs/RELEASE_PROCESS.md)** - How to create and manage releases
- **[Branch Strategy](docs/BRANCH_STRATEGY.md)** - Git workflow and branch protection
- **[API Documentation](API_DOCUMENTATION.md)** - Complete API reference

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](docs/CONTRIBUTING.md) for details on:

- Development workflow
- Code style and standards  
- Testing requirements
- Pull request process
- Branch protection rules

### Quick Start for Contributors

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes** with tests and documentation
4. **Run the test suite**: `make test`
5. **Submit a pull request** to the `main` branch

All pull requests require:
- ✅ Passing CI checks (tests, linting, security scan)
- ✅ Code review approval
- ✅ Up-to-date branch with main
- ✅ Conversation resolution

## 📄 License

MIT License - See the [LICENSE](LICENSE) file for details.

## 🆘 Support

**No official support is provided for this project.** This is an open-source project maintained by volunteers. For details about getting help and contributing, please see our [Support Guide](SUPPORT.md).

## 📊 Project Status

![CI/CD](https://github.com/DanyalTorabi/sms-syncer-server/workflows/CI/CD%20Pipeline/badge.svg)
![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![Test Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen.svg)
![Security](https://img.shields.io/badge/security-gosec-blue.svg)

---

**Made with ❤️ for reliable SMS synchronization**