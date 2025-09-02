# Contributing to SMS Sync Server

Thank you for your interest in contributing to the SMS Sync Server project! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Branch Strategy](#branch-strategy)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please be respectful, inclusive, and professional in all interactions.

## Getting Started

### Prerequisites

- Go 1.20 or later
- Git
- Make
- SQLite3

### Development Setup

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/your-username/sms-syncer-server.git
   cd sms-syncer-server
   ```

2. **Install Dependencies**
   ```bash
   go mod download
   go mod verify
   ```

3. **Set Up Development Environment**
   ```bash
   # Copy example config (if available)
   cp config.example.yaml config.yaml
   
   # Run tests to ensure everything is working
   make test
   ```

4. **Build the Application**
   ```bash
   make build
   ```

## Development Workflow

We use a Git workflow based on feature branches and pull requests.

### Branch Strategy

Our branching strategy follows GitFlow principles:

- **`main`** - Production-ready code, protected branch
- **`develop`** - Integration branch for features, main development branch
- **`feature/*`** - Feature development branches
- **`release/*`** - Release preparation branches
- **`hotfix/*`** - Critical fixes for production

### Working on Features

1. **Create a Feature Branch**
   ```bash
   # Start from develop branch
   git checkout develop
   git pull origin develop
   
   # Create feature branch
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write code following our [coding standards](#coding-standards)
   - Add tests for new functionality
   - Update documentation as needed

3. **Commit Your Changes**
   ```bash
   # Follow conventional commit format
   git commit -m "feat: add user authentication endpoint"
   ```

4. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Pull Request Process

### Before Creating a PR

1. **Run Tests Locally**
   ```bash
   make test
   make lint
   make build
   ```

2. **Update Documentation**
   - Update API documentation if endpoints changed
   - Update README if setup process changed
   - Add/update code comments

3. **Commit Message Format**
   
   We use [Conventional Commits](https://www.conventionalcommits.org/) format:
   
   ```
   <type>[optional scope]: <description>
   
   [optional body]
   
   [optional footer(s)]
   ```
   
   Types:
   - `feat`: New feature
   - `fix`: Bug fix
   - `docs`: Documentation changes
   - `style`: Code style changes (formatting, etc.)
   - `refactor`: Code refactoring
   - `test`: Adding or updating tests
   - `chore`: Maintenance tasks

### Creating the PR

1. **PR Title**: Use conventional commit format
2. **Description**: Include:
   - What changes were made and why
   - How to test the changes
   - Any breaking changes
   - Related issues (use "Closes #123")

### PR Review Process

1. **Automated Checks**: All CI checks must pass
2. **Code Review**: At least one maintainer review required
3. **Testing**: Reviewers should test the changes locally
4. **Approval**: PR needs approval before merging

## Coding Standards

### Go Style Guide

We follow the official Go style guide and additional conventions:

1. **Formatting**: Use `gofmt` and `goimports`
2. **Linting**: Code must pass `golangci-lint`
3. **Naming**: Follow Go naming conventions
4. **Comments**: Public functions/types must have comments
5. **Error Handling**: Always handle errors appropriately

### Code Organization

```
sms-syncer-server/
├── cmd/                    # Application entry points
│   └── server/            # Main server application
├── internal/              # Private application code
│   ├── api/              # API layer
│   ├── config/           # Configuration
│   ├── db/               # Database layer
│   ├── handlers/         # HTTP handlers
│   ├── models/           # Data models
│   └── services/         # Business logic
├── pkg/                   # Public library code
│   ├── logger/           # Logging utilities
│   ├── middleware/       # HTTP middleware
│   └── utils/            # Utility functions
├── docs/                  # Documentation
├── .github/              # GitHub workflows
└── build/                # Build artifacts
```

### Best Practices

1. **Functions**: Keep functions small and focused
2. **Interfaces**: Define interfaces in the package that uses them
3. **Context**: Use context.Context for cancellation and timeouts
4. **Errors**: Return descriptive errors with context
5. **Logging**: Use structured logging with appropriate levels

## Testing Guidelines

### Test Structure

1. **Unit Tests**: Test individual functions/methods
2. **Integration Tests**: Test component interactions
3. **API Tests**: Test HTTP endpoints end-to-end

### Writing Tests

1. **File Naming**: `*_test.go`
2. **Function Naming**: `TestFunctionName` or `TestType_Method`
3. **Table Tests**: Use table-driven tests for multiple scenarios
4. **Mocking**: Use interfaces for testability

### Test Commands

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific test
go test -v ./internal/handlers -run TestLogin

# Run integration tests
go test -v -tags=integration ./...
```

### Coverage Requirements

- Unit tests: Minimum 80% coverage
- Integration tests: Critical paths must be covered
- New features: Must include comprehensive tests

## Documentation

### Types of Documentation

1. **Code Comments**: Document public APIs and complex logic
2. **API Documentation**: Keep `API_DOCUMENTATION.md` updated
3. **README**: Update for setup/usage changes
4. **Architecture Docs**: Document significant design decisions

### Documentation Standards

1. **API Docs**: Include request/response examples
2. **Code Comments**: Explain why, not what
3. **Markdown**: Use consistent formatting
4. **Examples**: Provide working examples

## Release Process

### Semantic Versioning

We use [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH`
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes (backward compatible)

### Release Workflow

1. **Feature Complete**: All features merged to `develop`
2. **Release Branch**: Create `release/v1.2.0` from `develop`
3. **Testing**: Comprehensive testing on release branch
4. **Bug Fixes**: Only bug fixes allowed on release branch
5. **Merge**: Merge to `main` and `develop`
6. **Tag**: Create git tag and GitHub release
7. **Deploy**: Automated deployment to production

### Hotfix Process

For critical production issues:

1. **Hotfix Branch**: Create `hotfix/critical-fix` from `main`
2. **Fix**: Implement minimal fix
3. **Test**: Verify fix doesn't break anything
4. **Merge**: Merge to `main` and `develop`
5. **Release**: Create patch release

## Getting Help

- **Issues**: Check existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check the `docs/` folder
- **Code**: Read existing code for patterns and style

## Recognition

Contributors will be recognized in:
- Release notes
- Contributors section of README
- Annual contributor acknowledgments

Thank you for contributing to SMS Sync Server!
