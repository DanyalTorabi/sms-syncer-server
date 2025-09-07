# Release Process

This document describes the release process for the SMS Syncer Server.

## Overview

The project supports both manual and automated releases:
- **Auto-increment releases**: Automatically calculate next version number
- **Manual releases**: Specify exact version numbers
- **GitHub Actions**: Automated build and release pipeline

## Release Types

- **Stable releases**: `v1.0.0`, `v1.2.3`
- **Pre-releases**: `v1.0.0-alpha`, `v1.0.0-beta`, `v1.0.0-rc1`

## Auto-Increment Release Process (Recommended)

### 1. Local Auto-Increment

```bash
# Auto-increment patch version (1.0.0 -> 1.0.1)
make release-patch

# Auto-increment minor version (1.0.0 -> 1.1.0)
make release-minor

# Auto-increment major version (1.0.0 -> 2.0.0)
make release-major

# Create prerelease (1.0.0 -> 1.0.1-alpha)
make release-prerelease

# Create beta release (1.0.0 -> 1.0.1-beta)
make release-beta

# Preview next versions without releasing
make next-version
```

### 2. GitHub Actions Auto-Increment

Go to [GitHub Actions](https://github.com/DanyalTorabi/sms-syncer-server/actions) and run the **"Auto Release"** workflow:

1. Click **"Run workflow"**
2. Select release type:
   - **patch** - Bug fixes (1.0.0 → 1.0.1)
   - **minor** - New features (1.0.0 → 1.1.0)
   - **major** - Breaking changes (1.0.0 → 2.0.0)
   - **prerelease** - Pre-release version (1.0.0 → 1.0.1-alpha)
3. For prerelease, optionally specify suffix (alpha, beta, rc1, etc.)
4. Click **"Run workflow"**

The action will:
- ✅ Auto-calculate the next version
- ✅ Run all tests and checks
- ✅ Create and push the git tag
- ✅ Trigger the main release workflow automatically

### 3. Auto-Increment Script

You can also use the script directly:

```bash
# Get next patch version
./scripts/auto-version.sh patch

# Get next minor version  
./scripts/auto-version.sh minor

# Get next major version
./scripts/auto-version.sh major

# Get next prerelease version
./scripts/auto-version.sh prerelease alpha
```

## Manual Release Process

### 1. Prepare for Release

```bash
# Ensure you're on the main branch and up to date
git checkout main
git pull origin main

# Check if ready for release (runs tests and linting)
make release-check VERSION=v1.0.0
```

### 2. Create Release

```bash
# Create and push tag (triggers GitHub Action)
make release VERSION=v1.0.0
```

Or manually:

```bash
# Create local tag
make release-tag VERSION=v1.0.0

# Build local binaries (optional, for testing)
make release-build VERSION=v1.0.0

# Push tag to trigger automated release
git push origin v1.0.0
```

### 3. Monitor Release

1. Go to [GitHub Actions](https://github.com/DanyalTorabi/sms-syncer-server/actions)
2. Watch the "Release" workflow
3. Once complete, check the [Releases page](https://github.com/DanyalTorabi/sms-syncer-server/releases)

## Version Management

### Version Format

- Use semantic versioning: `vMAJOR.MINOR.PATCH`
- Pre-releases: `vMAJOR.MINOR.PATCH-SUFFIX`

### Auto-Increment Logic

Starting from `v1.2.3`:
- **Patch**: `v1.2.4` (bug fixes)
- **Minor**: `v1.3.0` (new features)
- **Major**: `v2.0.0` (breaking changes)
- **Prerelease**: `v1.2.4-alpha` (pre-release)

### Examples

```bash
# Current version: v1.2.3

make next-version
# Output:
#   Patch:      v1.2.4
#   Minor:      v1.3.0  
#   Major:      v2.0.0
#   Prerelease: v1.2.4-alpha

make release-patch
# Creates and releases v1.2.4

make release-minor  
# Creates and releases v1.3.0

make release-prerelease
# Creates and releases v1.2.4-alpha
```

## GitHub Actions Workflows

### 1. Auto Release Workflow
- **File**: `.github/workflows/auto-release.yml`
- **Trigger**: Manual (workflow_dispatch)
- **Purpose**: Auto-increment version and trigger release

### 2. Main Release Workflow  
- **File**: `.github/workflows/release.yml`
- **Trigger**: Git tags (`v*.*.*`)
- **Purpose**: Build binaries, Docker images, create GitHub release

## Automated Release Process

When a version tag is pushed (manually or via auto-increment):

1. **Validation**: Checks version format and runs tests
2. **Build**: Creates binaries for multiple platforms:
   - Linux (amd64, arm64)
   - macOS (amd64, arm64) 
   - Windows (amd64)
3. **Release**: Creates GitHub release with:
   - Release notes (auto-generated from commits)
   - Binary attachments
   - SHA256 checksums
4. **Docker**: Builds and pushes Docker image to GitHub Container Registry

### Built-in Version Information

The application includes version information:

```bash
# Show version
./sms-sync-server -version

# Version is also logged on startup and available via health endpoint
curl http://localhost:8080/health
```

## Release Assets

Each release includes:

- **Binaries**: Pre-compiled for major platforms
- **Checksums**: SHA256 verification files
- **Docker Image**: Available at `ghcr.io/danyaltorabi/sms-syncer-server`
- **Source Code**: Automatic GitHub archive

## Quick Start Examples

### For Bug Fixes
```bash
make release-patch
```

### For New Features
```bash
make release-minor
```

### For Breaking Changes
```bash
make release-major
```

### For Testing (Prerelease)
```bash
make release-prerelease
```

### Using GitHub Actions
1. Go to **Actions** → **Auto Release**
2. Click **Run workflow**
3. Select **patch** (or desired type)
4. Click **Run workflow**

## Troubleshooting

### Release Failed

1. Check [GitHub Actions](https://github.com/DanyalTorabi/sms-syncer-server/actions) for error details
2. Common issues:
   - Test failures: Fix tests and retry
   - Tag already exists: Use different version or delete existing tag
   - Permission issues: Check repository settings

### Re-release

To fix a release:

1. Delete the problematic tag:
   ```bash
   git tag -d v1.0.0
   git push --delete origin v1.0.0
   ```
2. Delete the GitHub release if it was created
3. Fix issues and create the tag again

### Manual Release Creation

If automation fails, you can create releases manually:

```bash
# Build binaries locally
make release-build VERSION=v1.0.0

# Create release via GitHub CLI (if installed)
gh release create v1.0.0 dist/* --title "Release v1.0.0" --notes "Release notes here"
```

## Security

- Release binaries are signed with checksums
- Docker images are built from source during the release process
- No secrets or sensitive data are included in releases

## Docker Usage

Released Docker images can be used as:

```bash
# Pull latest release
docker pull ghcr.io/danyaltorabi/sms-syncer-server:latest

# Run container
docker run -p 8080:8080 ghcr.io/danyaltorabi/sms-syncer-server:latest

# Or use docker-compose
version: '3.8'
services:
  sms-server:
    image: ghcr.io/danyaltorabi/sms-syncer-server:v1.0.0
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
```
