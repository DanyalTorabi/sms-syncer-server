#!/bin/bash

# Git Hooks Setup Script for SMS Syncer Server
# This script sets up pre-commit hooks for consistent code quality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[SETUP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SETUP]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[SETUP]${NC} $1"
}

print_error() {
    echo -e "${RED}[SETUP]${NC} $1"
}

print_header() {
    echo ""
    echo "=================================="
    echo "  Git Hooks Setup for SMS Syncer"
    echo "=================================="
    echo ""
}

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    print_error "This script must be run from the root of a git repository"
    exit 1
fi

print_header

print_info "Setting up git hooks for consistent code quality..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    print_info "Please install Go from https://golang.org/dl/"
    exit 1
fi

print_success "Go is installed: $(go version)"

# Check if golangci-lint is installed
if ! command -v golangci-lint &> /dev/null; then
    print_warning "golangci-lint is not installed"
    print_info "Installing golangci-lint..."
    
    # Install golangci-lint
    if command -v curl &> /dev/null; then
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin
        
        # Add GOPATH/bin to PATH if not already there
        if [[ ":$PATH:" != *":$(go env GOPATH)/bin:"* ]]; then
            print_info "Adding $(go env GOPATH)/bin to PATH in your shell profile"
            echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
            export PATH=$PATH:$(go env GOPATH)/bin
        fi
        
        if command -v golangci-lint &> /dev/null; then
            print_success "golangci-lint installed successfully"
        else
            print_error "Failed to install golangci-lint"
            print_info "Please install it manually: https://golangci-lint.run/usage/install/"
            exit 1
        fi
    else
        print_error "curl is not available. Please install golangci-lint manually"
        print_info "Visit: https://golangci-lint.run/usage/install/"
        exit 1
    fi
else
    print_success "golangci-lint is already installed: $(golangci-lint version)"
fi

# Create pre-commit hook
PRE_COMMIT_HOOK=".git/hooks/pre-commit"

if [ -f "$PRE_COMMIT_HOOK" ]; then
    print_warning "Pre-commit hook already exists"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Skipping pre-commit hook setup"
        exit 0
    fi
fi

print_info "Creating pre-commit hook..."

cat > "$PRE_COMMIT_HOOK" << 'EOF'
#!/bin/bash

# Pre-commit hook for SMS Syncer Server
# This hook runs the same linters as our GitHub Actions CI pipeline
# to catch linting issues before they reach the remote repository.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[PRE-COMMIT]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PRE-COMMIT]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[PRE-COMMIT]${NC} $1"
}

print_error() {
    echo -e "${RED}[PRE-COMMIT]${NC} $1"
}

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    print_error "This script must be run from the root of a git repository"
    exit 1
fi

print_info "Running pre-commit linting checks..."

# Get list of staged Go files
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true)

if [ -z "$STAGED_GO_FILES" ]; then
    print_info "No Go files staged for commit. Skipping linting checks."
    exit 0
fi

print_info "Found staged Go files:"
echo "$STAGED_GO_FILES" | sed 's/^/  - /'

# Check if golangci-lint is installed
if ! command -v golangci-lint &> /dev/null; then
    print_error "golangci-lint is not installed!"
    print_info "Please install it by running:"
    print_info "  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$(go env GOPATH)/bin"
    print_info "Or visit: https://golangci-lint.run/usage/install/"
    exit 1
fi

# Run gofmt check
print_info "Running gofmt check..."
GOFMT_OUTPUT=$(gofmt -l $STAGED_GO_FILES 2>&1 || true)
if [ -n "$GOFMT_OUTPUT" ]; then
    print_error "gofmt found formatting issues in the following files:"
    echo "$GOFMT_OUTPUT" | sed 's/^/  - /'
    print_info "Please run 'gofmt -w <file>' to fix the formatting issues."
    exit 1
fi
print_success "gofmt check passed"

# Run go vet
print_info "Running go vet..."
if ! go vet ./...; then
    print_error "go vet found issues"
    print_info "Please fix the issues reported by go vet"
    exit 1
fi
print_success "go vet check passed"

# Run golangci-lint on staged files only
print_info "Running golangci-lint..."
if [ -f ".golangci.yml" ] || [ -f ".golangci.yaml" ]; then
    print_info "Using existing golangci-lint configuration"
else
    print_warning "No golangci-lint configuration found, using default settings"
fi

# Create a temporary file list for golangci-lint
TEMP_FILE_LIST=$(mktemp)
echo "$STAGED_GO_FILES" > "$TEMP_FILE_LIST"

# Run golangci-lint only on staged files
if ! golangci-lint run --new-from-rev=HEAD --timeout=5m --issues-exit-code=1; then
    print_error "golangci-lint found issues in staged files"
    print_info "Please fix the linting issues before committing"
    print_info "You can run 'golangci-lint run --fix' to auto-fix some issues"
    print_info "Or use 'git commit --no-verify' to bypass this check (not recommended)"
    rm -f "$TEMP_FILE_LIST"
    exit 1
fi

rm -f "$TEMP_FILE_LIST"
print_success "golangci-lint check passed"

# Check if go.mod and go.sum are properly maintained
if git diff --cached --name-only | grep -q "go.mod\|go.sum"; then
    print_info "go.mod or go.sum changed, verifying dependencies..."
    if ! go mod verify; then
        print_error "go mod verify failed"
        print_info "Please run 'go mod tidy' and ensure go.sum is correct"
        exit 1
    fi
    print_success "Go module verification passed"
fi

print_success "All pre-commit checks passed! ✅"
print_info "Proceeding with commit..."
EOF

chmod +x "$PRE_COMMIT_HOOK"
print_success "Pre-commit hook created and made executable"

# Test the hook
print_info "Testing the pre-commit hook..."
if [ -f ".golangci.yml" ]; then
    print_success "Found golangci-lint configuration"
else
    print_warning "No golangci-lint configuration found, hook will use default settings"
fi

print_success "Git hooks setup completed! 🎉"
echo ""
print_info "The pre-commit hook will now run automatically before each commit"
print_info "It will check for:"
print_info "  - Go formatting (gofmt)"
print_info "  - Go vet issues"
print_info "  - Linting issues (golangci-lint)"
print_info "  - Go module integrity"
echo ""
print_info "To bypass the hook in emergency situations, use:"
print_info "  git commit --no-verify"
echo ""
print_success "Happy coding! 🚀"
