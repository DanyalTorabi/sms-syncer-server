# 🌳 Branch Strategy and Protection

## Branch Structure

### 🚀 **Main Branches**
- **`main`**: Production-ready code, heavily protected branch
- **`develop`**: Integration branch for features, default branch for development
- **`release/*`**: Release preparation branches, protected

### 🔧 **Supporting Branches**
- **`feature/*`**: New features (`feature/sms-api`, `feature/auth-improvements`)
- **`bugfix/*`**: Bug fixes (`bugfix/jwt-validation`)  
- **`hotfix/*`**: Critical production fixes (`hotfix/security-patch`)

## 🔒 **Branch Protection Rules**

Branch governance is managed via GitHub Rulesets and versioned JSON templates in `.github/rulesets/`.

### Main Branch Protection
- ✅ **No direct pushes allowed**
- ✅ **Requires PR with 1+ approvals**
- ✅ **Requires all CI checks to pass:**
  - `Test (1.24.0)`
  - `Integration Tests`
  - `Lint`
  - `Build`
  - `Security Scan`
- ✅ **Requires up-to-date branches**
- ✅ **Requires conversation resolution**
- ✅ **Dismisses stale reviews on new commits**

### Release Branch Protection  
- ✅ **No direct pushes allowed**
- ✅ **Requires PR with 1+ approvals**
- ✅ **Requires all CI checks + security scan:**
  - All main branch checks
  - `Security Scan`
  - `Integration Tests`
- ✅ **Requires code owner review**
- ✅ **Requires up-to-date branches**

## 🔄 **Workflow Examples**

### Feature Development
```bash
# Create feature branch from main (or develop if available)
git checkout main
git pull origin main
git checkout -b feature/new-sms-endpoint

# Work on feature, commit changes with conventional commits
git add .
git commit -m "feat: add new SMS batch endpoint with validation"

# Push and create PR to main
git push origin feature/new-sms-endpoint
```

### Release Process
```bash
# Create release branch from main
git checkout main  
git pull origin main
git checkout -b release/v1.2.0

# Final testing, version bumps, documentation updates
git commit -m "chore: prepare release v1.2.0"

# Create PR to main (requires 2 approvals and all checks)
git push origin release/v1.2.0
```

### Hotfix Process
```bash
# Create hotfix from main
git checkout main
git pull origin main
git checkout -b hotfix/security-jwt-validation

# Apply fix
git commit -m "fix: improve JWT token validation"

# PR to main (fast-track for critical issues)
git push origin hotfix/security-jwt-validation
```

## 🚦 **Required CI/CD Checks**

All PRs to protected branches must pass:

### 🔁 **CI Trigger Verification (PR Workflow)**
- Open a PR targeting `release/*` and confirm CI starts automatically.
- Change the base branch of an existing PR and confirm CI re-runs automatically.
- Verify required status checks remain enforced for `main`, `develop`, and `release/*`.

### ✅ **Always Required**
- **Test (1.24.0)**: Unit/race/coverage test suite
- **Lint**: golangci-lint checks
- **Build**: Successful server compilation
- **Integration Tests**: Integration tag test run
- **Security Scan**: Workflow security scan job

### ✅ **Release Branch Additional Requirements**
- **Security Scan**: gosec vulnerability check
- **Performance Tests**: Load testing for critical endpoints
- **Documentation**: Updated API docs and changelogs

## 📋 **Pull Request Template**

```markdown
## 🎯 Description
Brief description of changes

## 🔗 Related Issue
Fixes #[issue_number]

## 🧪 Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## 📚 Documentation
- [ ] API documentation updated
- [ ] README updated if needed
- [ ] Changelog updated

## ✅ Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Tests added for new functionality
- [ ] No breaking changes without version bump
```

## 🔐 **Security Considerations**

### Required for Security-Sensitive Changes
- **Two-person rule**: Security changes require 2+ approvals
- **Code owner review**: Security team must approve auth/middleware changes
- **Security scan**: All releases must pass gosec scanning
- **Dependency audit**: Regular dependency vulnerability checks

### Protected Files
- Authentication handlers
- Middleware components  
- Database connection logic
- JWT token handling
- CI/CD configurations

## 📊 **Monitoring and Compliance**

### Branch Health Metrics
- **PR merge time**: Target < 24 hours for features
- **Test coverage**: Maintain 85%+ coverage
- **Failed CI runs**: Target < 5% failure rate
- **Security issues**: Zero tolerance for high/critical vulnerabilities

### Compliance Requirements
- All commits must be signed
- All PRs must pass automated security scanning
- Critical changes require offline security review
- Release branches require comprehensive testing

## 🚨 **Emergency Procedures**

### Critical Production Issues
1. **Create hotfix branch** from main
2. **Apply minimal fix** with comprehensive tests
3. **Fast-track review** (30min max response time)
4. **Deploy immediately** after approval
5. **Post-mortem** within 24 hours

### Branch Protection Bypass
- **No normal bypass** is allowed for protected branches
- **Emergency-only override** requires temporary ruleset modification
- **Must document reason** in security log
- **Requires post-override review** within 24 hours

## ⚙️ **Ruleset Management (Versioned)**

Rulesets are defined in:
- `.github/rulesets/main-and-develop.json`
- `.github/rulesets/release.json`

Use the helper script to preview or apply:

```bash
# Preview (no changes)
./scripts/apply-rulesets.sh

# Apply to current repo
./scripts/apply-rulesets.sh --apply

# Apply to another repo
./scripts/apply-rulesets.sh --apply --repo=owner/repo
```

---

## 📝 **Implementation Status**

- [x] Ruleset templates committed in repo (`.github/rulesets/`)
- [x] CI/CD pipeline setup with required checks
- [x] CODEOWNERS file created
- [x] Documentation updated
- [x] Rulesets applied/enforced in repository settings
- [ ] Team training completed
- [x] Emergency procedures documented

**Last Updated**: February 28, 2026
**Next Review**: March 31, 2026
