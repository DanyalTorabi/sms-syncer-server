#!/bin/bash

# SMS Syncer Server Release Script
# Usage: ./scripts/release.sh v1.0.0 [--dry-run]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if version is provided
if [ $# -eq 0 ]; then
    print_error "Version is required!"
    echo "Usage: $0 v1.0.0 [--dry-run]"
    echo "Examples:"
    echo "  $0 v1.0.0          # Create and push release"
    echo "  $0 v1.0.0 --dry-run # Test release process without pushing"
    exit 1
fi

VERSION=$1
DRY_RUN=false

# Check for dry-run flag
if [ "$2" = "--dry-run" ]; then
    DRY_RUN=true
    print_warning "DRY RUN MODE - No changes will be pushed"
fi

# Validate version format
if ! echo "$VERSION" | grep -qE "^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$"; then
    print_error "Invalid version format: $VERSION"
    echo "Version must be in format v1.2.3 or v1.2.3-alpha"
    exit 1
fi

print_status "Starting release process for version: $VERSION"

# Check if we're in the right directory
if [ ! -f "go.mod" ] || [ ! -f "Makefile" ]; then
    print_error "This script must be run from the project root directory"
    exit 1
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    print_error "Working directory is not clean. Please commit or stash changes."
    git status --short
    exit 1
fi

# Ensure we're on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    print_error "Must be on main branch. Currently on: $CURRENT_BRANCH"
    exit 1
fi

# Pull latest changes
print_status "Pulling latest changes from origin/main..."
git pull origin main

# Check if tag already exists
if git tag -l | grep -q "^$VERSION$"; then
    print_error "Tag $VERSION already exists!"
    exit 1
fi

# Run pre-release checks
print_status "Running pre-release checks..."

print_status "Running tests..."
if ! go test ./...; then
    print_error "Tests failed!"
    exit 1
fi

print_status "Running linter..."
if command -v golangci-lint >/dev/null 2>&1; then
    if ! golangci-lint run; then
        print_error "Linting failed!"
        exit 1
    fi
else
    print_warning "golangci-lint not found, skipping lint check"
fi

print_status "Running go vet..."
if ! go vet ./...; then
    print_error "go vet failed!"
    exit 1
fi

print_status "Checking go mod..."
go mod tidy
if [ -n "$(git status --porcelain go.mod go.sum)" ]; then
    print_error "go.mod or go.sum are not up to date. Run 'go mod tidy' and commit."
    exit 1
fi

print_success "All pre-release checks passed!"

# Build local release (optional verification)
print_status "Building local release for verification..."
if ! make release-build VERSION="$VERSION"; then
    print_error "Failed to build release binaries!"
    exit 1
fi

print_success "Release binaries built successfully"

# Show what will be released
print_status "Release summary:"
echo "  Version: $VERSION"
echo "  Branch: $CURRENT_BRANCH"
echo "  Commit: $(git rev-parse HEAD)"
echo "  Built binaries:"
ls -la dist/ | grep "$VERSION" || true

# Confirm release
if [ "$DRY_RUN" = false ]; then
    echo ""
    read -p "Continue with release? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Release cancelled by user"
        exit 1
    fi
fi

# Create and push tag
print_status "Creating git tag: $VERSION"
git tag -a "$VERSION" -m "Release $VERSION"

if [ "$DRY_RUN" = false ]; then
    print_status "Pushing tag to origin..."
    git push origin "$VERSION"
    
    print_success "Release tag pushed successfully!"
    print_status "GitHub Actions will now build and publish the release."
    print_status "Monitor progress at: https://github.com/DanyalTorabi/sms-syncer-server/actions"
    print_status "Release will be available at: https://github.com/DanyalTorabi/sms-syncer-server/releases/tag/$VERSION"
else
    print_warning "DRY RUN: Tag created locally but not pushed"
    print_warning "To clean up: git tag -d $VERSION"
fi

# Clean up local build artifacts
print_status "Cleaning up local build artifacts..."
rm -rf dist/

print_success "Release process completed!"

if [ "$DRY_RUN" = false ]; then
    echo ""
    echo "Next steps:"
    echo "1. Monitor the GitHub Actions workflow"
    echo "2. Verify the release was created correctly"
    echo "3. Test the released binaries"
    echo "4. Update any dependent projects"
fi
