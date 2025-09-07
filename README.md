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

- Go 1.22 or later
- Git

## Setup

1. Clone the repository
2. Navigate to the Server directory
3. Install dependencies:
   ```bash
   go mod tidy
   ```

## Configuration

The server can be configured using environment variables:

- `SERVER_PORT`: Port to listen on (default: 8080)
- `LOG_LEVEL`: Logging level (default: info)

## Running the Server

```bash
go run cmd/server/main.go
```

## API Endpoints

### Health Check
```
GET /health
```
Returns server status and current time.

### Add SMS
```
POST /api/sms/add
Content-Type: application/json

{
  "uuid": "string",
  "sender": "string",
  "message": "string",
  "timestamp": "string",
  "retryCount": number
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

# Run with live reload
make dev

# Build for production  
make build
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
└── Makefile                  # Build automation
```

### 🧪 Testing

- **Unit Tests**: `go test ./...` 
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

## 📊 Project Status

![CI/CD](https://github.com/DanyalTorabi/sms-syncer-server/workflows/CI/CD%20Pipeline/badge.svg)
![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![Test Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen.svg)
![Security](https://img.shields.io/badge/security-gosec-blue.svg)

---

**Made with ❤️ for reliable SMS synchronization**