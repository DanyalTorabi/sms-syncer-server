#!/bin/bash

# Auto-increment version script
# Usage: ./scripts/auto-version.sh [patch|minor|major|prerelease] [prerelease-suffix]

set -e

# Check if running in quiet mode (for use in other scripts)
QUIET_MODE=false
if [[ -n "$QUIET" ]] || [[ "$1" == "--quiet" ]]; then
    QUIET_MODE=true
    # Remove --quiet from arguments
    if [[ "$1" == "--quiet" ]]; then
        shift
    fi
fi

# Default to patch if no argument provided
RELEASE_TYPE=${1:-patch}
PRERELEASE_SUFFIX=${2:-alpha}

# Colors for output (only used in non-quiet mode)
if [ "$QUIET_MODE" = false ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

print_usage() {
    echo "Usage: $0 [release_type] [prerelease_suffix]"
    echo ""
    echo "Release types:"
    echo "  patch       - Increment patch version (1.0.0 -> 1.0.1)"
    echo "  minor       - Increment minor version (1.0.0 -> 1.1.0)"
    echo "  major       - Increment major version (1.0.0 -> 2.0.0)"
    echo "  prerelease  - Increment patch and add suffix (1.0.0 -> 1.0.1-alpha)"
    echo ""
    echo "Examples:"
    echo "  $0 patch                    # Auto-increment patch version"
    echo "  $0 minor                    # Auto-increment minor version"
    echo "  $0 major                    # Auto-increment major version"
    echo "  $0 prerelease alpha         # Create prerelease with alpha suffix"
    echo "  $0 prerelease beta          # Create prerelease with beta suffix"
}

print_status() {
    if [ "$QUIET_MODE" = false ]; then
        echo -e "${BLUE}[INFO]${NC} $1" >&2
    fi
}

print_success() {
    if [ "$QUIET_MODE" = false ]; then
        echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
    fi
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Validate release type
case $RELEASE_TYPE in
    patch|minor|major|prerelease)
        ;;
    *)
        print_error "Invalid release type: $RELEASE_TYPE"
        if [ "$QUIET_MODE" = false ]; then
            print_usage
        fi
        exit 1
        ;;
esac

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    print_error "This script must be run from the root of a git repository"
    exit 1
fi

# Get latest tag
print_status "Getting latest version..."
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
print_status "Latest tag: $LATEST_TAG"

# Clean version (remove v prefix and prerelease suffix)
VERSION_CLEAN=$(echo $LATEST_TAG | sed 's/^v//' | sed 's/-.*$//')
print_status "Clean version: $VERSION_CLEAN"

# Split version into components
IFS='.' read -ra VERSION_PARTS <<< "$VERSION_CLEAN"
MAJOR=${VERSION_PARTS[0]:-0}
MINOR=${VERSION_PARTS[1]:-0}
PATCH=${VERSION_PARTS[2]:-0}

print_status "Current version: $MAJOR.$MINOR.$PATCH"

# Calculate next version
case $RELEASE_TYPE in
    "major")
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        NEW_VERSION="v${MAJOR}.${MINOR}.${PATCH}"
        ;;
    "minor")
        MINOR=$((MINOR + 1))
        PATCH=0
        NEW_VERSION="v${MAJOR}.${MINOR}.${PATCH}"
        ;;
    "patch")
        PATCH=$((PATCH + 1))
        NEW_VERSION="v${MAJOR}.${MINOR}.${PATCH}"
        ;;
    "prerelease")
        PATCH=$((PATCH + 1))
        NEW_VERSION="v${MAJOR}.${MINOR}.${PATCH}-${PRERELEASE_SUFFIX}"
        ;;
esac

print_success "New version: $NEW_VERSION"

# Check if tag already exists
if git tag -l | grep -q "^${NEW_VERSION}$"; then
    print_error "Tag $NEW_VERSION already exists!"
    exit 1
fi

# Output the version (this script can be used by other scripts)
echo "$NEW_VERSION"
