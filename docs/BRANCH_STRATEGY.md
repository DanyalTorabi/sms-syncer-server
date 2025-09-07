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

### Main Branch Protection
- ✅ **No direct pushes allowed**
- ✅ **Requires PR with 1+ approvals**
- ✅ **Requires all CI checks to pass:**
  - Unit tests with 85%+ coverage
  - Integration tests
  - Linting (golangci-lint)
  - Build verification
- ✅ **Requires up-to-date branches**
- ✅ **Requires conversation resolution**
- ✅ **Dismisses stale reviews on new commits**

### Release Branch Protection  
- ✅ **No direct pushes allowed**
- ✅ **Requires PR with 2+ approvals**
- ✅ **Requires all CI checks + security scan:**
  - All main branch checks
  - Security scan (gosec)
  - Integration tests
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

### ✅ **Always Required**
- **Unit Tests**: 85%+ coverage minimum
- **Linting**: golangci-lint with strict rules
- **Build**: Successful compilation
- **Integration Tests**: Full API workflow tests

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
- **Only repository admins** can bypass protection
- **Must document reason** in security log
- **Requires post-bypass review** within 24 hours
- **Emergency use only** for critical production issues

---

## 📝 **Implementation Status**

- [x] GitHub branch protection rules configured
- [x] CI/CD pipeline setup with required checks
- [x] CODEOWNERS file created
- [x] Documentation updated
- [x] Team training completed
- [x] Emergency procedures documented

**Last Updated**: September 3, 2025
**Next Review**: October 3, 2025
