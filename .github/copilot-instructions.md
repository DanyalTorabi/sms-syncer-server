# GitHub Copilot Instructions for SMS Syncer Server

This document provides comprehensive instructions to guide AI-assisted development for the SMS Syncer Server project, covering both the Go server implementation and future Android client development.

## Table of Contents

- [Project Overview](#project-overview)
- [Go Server Coding Standards](#go-server-coding-standards)
- [Android Client Guidelines](#android-client-guidelines)
- [Testing Requirements](#testing-requirements)
- [Security Guidelines](#security-guidelines)
- [Performance Guidelines](#performance-guidelines)
- [Code Review Checklist](#code-review-checklist)
- [GitHub CLI (gh) Tool Usage](#github-cli-gh-tool-usage)
- [Common Patterns and Examples](#common-patterns-and-examples)

---

## Project Overview

### Architecture

The SMS Syncer Server is a RESTful API server built with Go that syncs SMS messages from Android devices.

**Tech Stack:**
- **Language**: Go 1.20+
- **Web Framework**: Gin
- **Database**: SQLite with GORM ORM
- **Authentication**: JWT-based
- **Logging**: Structured logging with zap
- **Testing**: Go testing with testify

**Project Structure:**
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
├── router/                # HTTP routing
└── docs/                  # Documentation
```

---

## Go Server Coding Standards

### Code Style and Formatting

1. **Always use `gofmt` and `goimports`** for formatting
2. **Follow official Go style guide**: [Effective Go](https://go.dev/doc/effective_go)
3. **Naming conventions**:
   - Use camelCase for unexported names
   - Use PascalCase for exported names
   - Acronyms should be all caps (e.g., `HTTPServer`, `userID`)
   - Interface names ending in "er" when single-method (e.g., `Reader`, `Writer`)

### Code Organization

**Package Structure:**
- Place related functionality in the same package
- Keep packages focused and cohesive
- Define interfaces in the package that uses them
- Minimize dependencies between packages

**File Organization:**
- One primary type per file
- Group related functions together
- Place tests in `*_test.go` files alongside source

### Workflow Guidelines

#### Pull Request Creation for Tickets

**CRITICAL: Always create a feature branch and PR when planning or implementing tickets**

When a user asks to plan or implement a ticket:

1. **Create a feature branch from latest main**:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b <ticket-number>-<brief-description>
   ```

2. **Make your changes** following the coding standards

3. **Create a PR** using `gh pr create`:
   ```bash
   gh pr create \
     --title "<type>: <description>" \
     --body "Implements #<ticket-number>\n\n## Changes\n- ..."
   ```

**Example workflow:**
```bash
# User: "implement ticket #85"

# 1. Create branch from latest main
git checkout main
git pull origin main
git checkout -b 85-add-sms-filtering

# 2. Implement changes
# ... make code changes ...

# 3. Commit and push
git add .
git commit -m "feat: add SMS filtering by date range"
git push origin 85-add-sms-filtering

# 4. Create PR
gh pr create \
  --title "feat: add SMS filtering by date range" \
  --body "Implements #85\n\n## Changes\n- Added date range query parameters\n- Updated handler and service layer\n- Added unit tests\n\nCloses #85"
```

### Best Practices

#### 1. Functions and Methods

```go
// GOOD: Small, focused functions
func ValidatePhoneNumber(phone string) error {
    if phone == "" {
        return errors.New("phone number cannot be empty")
    }
    // validation logic
    return nil
}

// BAD: Large functions doing multiple things
func ProcessSMS(sms *SMS) error {
    // validation, transformation, database operations all in one
    // ... 100+ lines ...
}
```

**Keep functions:**
- Under 100 lines (enforced by `funlen` linter)
- Under 50 statements
- Cyclomatic complexity under 20

#### 2. Error Handling

```go
// GOOD: Always handle errors with context
if err := db.Save(&sms).Error; err != nil {
    return fmt.Errorf("failed to save SMS message: %w", err)
}

// BAD: Ignoring errors
db.Save(&sms) // nolint:errcheck

// GOOD: Return early on errors
if err := validate(input); err != nil {
    return err
}
// happy path continues

// BAD: Deep nesting
if err := validate(input); err == nil {
    if result, err := process(input); err == nil {
        // deeply nested logic
    }
}
```

#### 3. Context Usage

```go
// GOOD: Pass context as first parameter
func ProcessSMS(ctx context.Context, sms *SMS) error {
    // Use context for cancellation and timeouts
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
        // process
    }
}

// GOOD: Respect context cancellation in long operations
func BatchProcess(ctx context.Context, items []Item) error {
    for _, item := range items {
        if ctx.Err() != nil {
            return ctx.Err()
        }
        process(item)
    }
    return nil
}
```

#### 4. Comments and Documentation

```go
// GOOD: Document public APIs with complete sentences
// NewSMSService creates a new SMS service instance with the provided database connection.
// It returns an error if the database connection is nil.
func NewSMSService(db *gorm.DB) (*SMSService, error) {
    if db == nil {
        return nil, errors.New("database connection required")
    }
    return &SMSService{db: db}, nil
}

// GOOD: Explain WHY, not WHAT
// Hash the phone number to avoid storing PII in logs
hashedPhone := hashPhone(sms.PhoneNumber)

// BAD: Stating the obvious
// Set the user ID to userID
sms.UserID = userID
```

#### 5. TODO Comments and Follow-up Tasks

**CRITICAL: Always create GitHub issues for deferred work and reference them in code**

When you identify follow-up work, refactoring needs, or technical debt during development:

1. **Check for existing related issues first** using `gh issue list`
   - If a related open issue exists, update it with the new task instead of creating a duplicate
   - Only create a new issue if no related issue exists
2. **Add a TODO comment in the code** with the issue number
3. **Never leave untracked TODOs** - every TODO must have a corresponding issue

```go
// GOOD: TODO with issue reference
// TODO(#123): Refactor this to use connection pooling for better performance
func ProcessBatch(items []Item) error {
    // current implementation
}

// GOOD: TODO with issue reference and context
// TODO(#456): Move permission validation to middleware layer
// Currently validating here for backward compatibility, but this should
// be handled by RequirePermission middleware after ticket #81 is complete
if !hasPermission(user, "resource:write") {
    return ErrForbidden
}

// BAD: TODO without issue tracking
// TODO: This needs optimization
func SlowFunction() {
    // ...
}

// BAD: Vague TODO without context
// TODO: Fix this later
func BrokenFunction() {
    // ...
}
```

**Workflow for creating tracked TODOs:**

```bash
# 1. Check for existing related issues first
gh issue list --search "batch processing" --state open

# If related issue exists, update it:
gh issue comment 123 --body "Additional task: Refactor SMS batch processing to use connection pooling"

# If no related issue exists, create a new one:
gh issue create \
  --title "Refactor SMS batch processing for connection pooling" \
  --body "Current implementation opens new connection for each item.
Should use connection pool for better performance and resource usage." \
  --label "enhancement,tech-debt"

# Output: Created issue #123

# 2. Add TODO comment in code with issue number
# TODO(#123): Refactor this to use connection pooling for better performance

# 3. Commit with reference
git commit -m "feat: add batch SMS processing

Note: Current implementation could be optimized (see #123)"
```

**Benefits of tracked TODOs:**
- ✅ Technical debt is visible and tracked
- ✅ Follow-up work doesn't get forgotten
- ✅ Easy to find all TODOs: `grep -r "TODO(#" .`
- ✅ Issues can be prioritized and scheduled
- ✅ Context preserved for future developers

#### 6. Interfaces and Abstraction

```go
// GOOD: Small, focused interfaces
type SMSRepository interface {
    Save(ctx context.Context, sms *SMS) error
    FindByID(ctx context.Context, id string) (*SMS, error)
}

// GOOD: Accept interfaces, return concrete types
func NewSMSHandler(repo SMSRepository, logger *zap.Logger) *SMSHandler {
    return &SMSHandler{repo: repo, logger: logger}
}

// BAD: Large interfaces with many methods
type Repository interface {
    SaveSMS(...) error
    DeleteSMS(...) error
    UpdateSMS(...) error
    FindSMS(...) error
    // ... 20 more methods
}
```

### Linting Rules

Code must pass `golangci-lint` with the project's `.golangci.yml` configuration:

**Enabled Linters:**
- `errcheck` - Check for unchecked errors
- `gofmt` - Format code
- `goimports` - Organize imports
- `gosimple` - Suggest code simplifications
- `govet` - Report suspicious constructs
- `ineffassign` - Detect ineffectual assignments
- `staticcheck` - Static analysis
- `unused` - Detect unused code
- `misspell` - Fix common spelling mistakes
- `funlen` - Enforce function length limits (100 lines)
- `gocyclo` - Check cyclomatic complexity (max 20)
- `lll` - Enforce line length (150 characters)

**Run linting:**
```bash
make lint                    # Run all linters
make lint-fix                # Auto-fix issues
make lint-single LINTER=lll  # Run specific linter
```

---

## Android Client Guidelines

> **Note**: The Android client is planned for future development. These guidelines establish standards for when the mobile component is added.

### Kotlin Coding Standards

1. **Follow official Kotlin style guide**: [kotlinlang.org/docs/coding-conventions](https://kotlinlang.org/docs/coding-conventions.html)
2. **Use Kotlin idioms**: data classes, sealed classes, extension functions
3. **Prefer immutability**: Use `val` over `var` when possible
4. **Null safety**: Leverage Kotlin's null safety features

### Android Architecture

**Recommended Architecture:**
- **MVVM** (Model-View-ViewModel) pattern
- **Repository pattern** for data access
- **Dependency Injection** with Hilt or Koin
- **Coroutines** for asynchronous operations
- **LiveData/Flow** for reactive UI updates

### API Integration

```kotlin
// Example API client structure
interface SmsApiService {
    @POST("/api/sms/add")
    suspend fun syncSms(
        @Header("Authorization") token: String,
        @Body sms: SmsMessage
    ): Response<ApiResponse>
}

// Repository pattern
class SmsRepository(
    private val apiService: SmsApiService,
    private val localDb: SmsDao
) {
    suspend fun syncSms(sms: SmsMessage): Result<Unit> {
        return try {
            val response = apiService.syncSms(token, sms)
            if (response.isSuccessful) {
                localDb.markAsSynced(sms.id)
                Result.success(Unit)
            } else {
                Result.failure(Exception(response.message()))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
```

### Security Considerations for Android

1. **Secure token storage**: Use Android Keystore for JWT tokens
2. **Certificate pinning**: Implement for API communications
3. **ProGuard/R8**: Enable code obfuscation for release builds
4. **Permissions**: Request only necessary SMS permissions
5. **Data encryption**: Encrypt local database with SQLCipher

---

## Testing Requirements

### Coverage Requirements

**CRITICAL: All changes must include tests with minimum 80% coverage**

- **Unit tests**: Minimum 80% coverage (project currently maintains 86%+)
- **Integration tests**: Critical paths must be covered
- **New features**: Must include comprehensive tests
- **Bug fixes**: Must include regression tests

### Test Structure

#### Table-Driven Tests (Preferred Pattern)

```go
func TestValidatePhoneNumber(t *testing.T) {
    tests := []struct {
        name        string
        phoneNumber string
        wantErr     bool
        errContains string
    }{
        {
            name:        "valid international format",
            phoneNumber: "+1234567890",
            wantErr:     false,
        },
        {
            name:        "empty phone number",
            phoneNumber: "",
            wantErr:     true,
            errContains: "cannot be empty",
        },
        {
            name:        "invalid characters",
            phoneNumber: "abc123",
            wantErr:     true,
            errContains: "invalid format",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidatePhoneNumber(tt.phoneNumber)
            if tt.wantErr {
                assert.Error(t, err)
                if tt.errContains != "" {
                    assert.Contains(t, err.Error(), tt.errContains)
                }
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

#### HTTP Handler Testing

```go
func TestAddSMSHandler(t *testing.T) {
    // Setup
    gin.SetMode(gin.TestMode)
    mockDB := new(MockDatabase)
    router := setupTestRouter(mockDB)

    // Prepare request
    smsData := map[string]interface{}{
        "phoneNumber":  "+1234567890",
        "body":         "Test message",
        "eventType":    "RECEIVED",
        "smsTimestamp": 1692864000,
    }
    body, _ := json.Marshal(smsData)
    
    req := httptest.NewRequest(http.MethodPost, "/api/sms/add", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+validToken)
    
    w := httptest.NewRecorder()

    // Execute
    router.ServeHTTP(w, req)

    // Assert
    assert.Equal(t, http.StatusCreated, w.Code)
    mockDB.AssertExpectations(t)
}
```

#### Mock Interfaces

```go
// Define mock for testing
type MockSMSRepository struct {
    mock.Mock
}

func (m *MockSMSRepository) Save(ctx context.Context, sms *SMS) error {
    args := m.Called(ctx, sms)
    return args.Error(0)
}

func (m *MockSMSRepository) FindByID(ctx context.Context, id string) (*SMS, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*SMS), args.Error(1)
}
```

### Test Commands

```bash
# Run all tests
make test

# Run tests with coverage report
make coverage

# Run specific test
go test -v ./internal/handlers -run TestAddSMS

# Run integration tests
go test -v -tags=integration ./...

# Check coverage threshold
go test -coverprofile=coverage.out ./... && \
  go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//'
```

### Test File Organization

```
internal/
├── handlers/
│   ├── sms_handler.go
│   ├── sms_handler_test.go       # Unit tests
│   ├── integration_test.go       # Integration tests
│   └── test_utils.go             # Test helpers
```

**Note**: Test utility files (`*test_utils.go`, `*_mock.go`) are excluded from the `unused` linter check in `.golangci.yml` since they're only used by test files.

---

## Security Guidelines

### Authentication and Authorization

```go
// GOOD: Use JWT middleware for protected endpoints
router.POST("/api/sms/add", middleware.AuthRequired(), handlers.AddSMS)

// GOOD: Extract user ID from verified JWT token
userID := c.GetString("user_id") // From verified JWT claims

// BAD: Trust client-provided user ID
userID := c.PostForm("user_id") // NEVER do this
```

### Input Validation

```go
// GOOD: Validate and sanitize all inputs
func (h *SMSHandler) AddSMS(c *gin.Context) {
    var req AddSMSRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    // Validate business rules
    if err := req.Validate(); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Sanitize inputs
    req.PhoneNumber = sanitizePhoneNumber(req.PhoneNumber)
    req.Body = sanitizeText(req.Body)
    
    // Process...
}
```

### SQL Injection Prevention

```go
// GOOD: Use GORM's parameterized queries (automatic protection)
db.Where("user_id = ? AND phone_number = ?", userID, phone).Find(&messages)

// GOOD: Use struct-based queries
db.Where(&SMS{UserID: userID, PhoneNumber: phone}).Find(&messages)

// BAD: String concatenation (vulnerable to SQL injection)
db.Raw("SELECT * FROM sms WHERE user_id = '" + userID + "'").Scan(&messages)
```

### Secrets Management

```go
// GOOD: Use environment variables
jwtSecret := os.Getenv("JWT_SECRET")
if jwtSecret == "" {
    log.Fatal("JWT_SECRET environment variable required")
}

// GOOD: Use config with validation
cfg, err := config.LoadConfig()
if err != nil {
    log.Fatal(err)
}

// BAD: Hardcoded secrets
const jwtSecret = "super-secret-key" // NEVER do this
```

### Security Headers

```go
// GOOD: Apply security middleware
router.Use(middleware.SecurityHeadersMiddleware())
router.Use(middleware.CORSMiddleware())
router.Use(middleware.RequestSizeLimitMiddleware(10 * 1024 * 1024)) // 10MB
```

**Security headers set by middleware:**
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `X-Request-ID: <unique-id>`

### Sensitive Data Handling

```go
// GOOD: Never log sensitive data
logger.Info("SMS saved",
    zap.String("user_id", userID),
    zap.String("phone_hash", hashPhone(phoneNumber)), // Hash PII
    zap.Int("message_length", len(body)),
)

// BAD: Logging sensitive information
logger.Info("SMS saved",
    zap.String("phone", phoneNumber),  // PII exposed
    zap.String("message", body),       // Message content exposed
)
```

---

## Performance Guidelines

### Database Optimization

```go
// GOOD: Select only needed fields
db.Select("id", "phone_number", "body").Find(&messages)

// BAD: Select all fields
db.Find(&messages)

// GOOD: Use indexes for frequently queried fields
// Migration:
// CREATE INDEX idx_sms_user_id ON sms_messages(user_id);
// CREATE INDEX idx_sms_timestamp ON sms_messages(sms_timestamp);

// GOOD: Always paginate large result sets
func GetMessages(userID string, limit, offset int) ([]*SMS, error) {
    var messages []*SMS
    return messages, db.Where("user_id = ?", userID).
        Limit(limit).
        Offset(offset).
        Find(&messages).Error
}

// BAD: Load all records
db.Where("user_id = ?", userID).Find(&messages) // Could return millions
```

### HTTP Performance

```go
// GOOD: Set appropriate timeouts
server := &http.Server{
    Addr:         ":8080",
    Handler:      router,
    ReadTimeout:  15 * time.Second,
    WriteTimeout: 15 * time.Second,
    IdleTimeout:  60 * time.Second,
}

// GOOD: Use connection pooling
db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
sqlDB, _ := db.DB()
sqlDB.SetMaxOpenConns(25)
sqlDB.SetMaxIdleConns(5)
sqlDB.SetConnMaxLifetime(5 * time.Minute)
```

### Memory Management

```go
// GOOD: Limit request body size
router.Use(middleware.RequestSizeLimitMiddleware(10 * 1024 * 1024))

// GOOD: Close resources properly
defer resp.Body.Close()
defer file.Close()

// GOOD: Use buffered channels for concurrent operations
ch := make(chan Result, 100) // Buffered

// GOOD: Process large datasets in batches
const batchSize = 100
for i := 0; i < len(items); i += batchSize {
    end := i + batchSize
    if end > len(items) {
        end = len(items)
    }
    processBatch(items[i:end])
}
```

### Caching Strategies

```go
// GOOD: Cache frequently accessed, rarely changing data
var configCache *Config
var cacheMutex sync.RWMutex

func GetConfig() *Config {
    cacheMutex.RLock()
    if configCache != nil {
        defer cacheMutex.RUnlock()
        return configCache
    }
    cacheMutex.RUnlock()

    cacheMutex.Lock()
    defer cacheMutex.Unlock()
    
    // Double-check after acquiring write lock
    if configCache != nil {
        return configCache
    }
    
    configCache = loadConfig()
    return configCache
}
```

---

## Code Review Checklist

Use this checklist when reviewing code or preparing pull requests:

### Code Quality
- [ ] Code follows Go style guidelines and project conventions
- [ ] Functions are small and focused (< 100 lines)
- [ ] Cyclomatic complexity is reasonable (< 20)
- [ ] Code is self-documenting with clear variable/function names
- [ ] Complex logic has explanatory comments (WHY, not WHAT)
- [ ] No obvious code smells (duplication, long parameter lists, etc.)

### Testing
- [ ] Unit tests added/updated for all changes
- [ ] Tests follow table-driven pattern where appropriate
- [ ] Test coverage meets minimum 80% threshold
- [ ] Integration tests added for new features
- [ ] Edge cases and error paths are tested
- [ ] Mock objects used appropriately for external dependencies

### Error Handling
- [ ] All errors are checked and handled appropriately
- [ ] Errors include context (`fmt.Errorf` with `%w`)
- [ ] Error messages are clear and actionable
- [ ] No panic/recover in normal flow (only for truly exceptional cases)

### Security
- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented for all user inputs
- [ ] SQL injection prevention (parameterized queries)
- [ ] Authentication/authorization properly enforced
- [ ] No sensitive data in logs
- [ ] Dependencies are up-to-date and scanned for vulnerabilities

### Performance
- [ ] Database queries are optimized (indexes, selective fields)
- [ ] Large result sets are paginated
- [ ] Resources are properly closed (defer statements)
- [ ] No obvious memory leaks
- [ ] Appropriate timeouts configured
- [ ] Connection pools configured correctly

### Documentation
- [ ] Public APIs have complete godoc comments
- [ ] API documentation updated if endpoints changed
- [ ] README updated if setup/usage changed
- [ ] Complex algorithms explained with comments
- [ ] Architecture docs updated for significant changes

### Git and CI/CD
- [ ] Commit messages follow conventional commit format
- [ ] Branch is up-to-date with main/develop
- [ ] All CI checks pass (tests, linting, build)
- [ ] No merge conflicts
- [ ] PR description is clear and complete

### Database Changes
- [ ] Migrations are included and tested
- [ ] Changes are backward compatible
- [ ] Indexes added for new query patterns
- [ ] Migration rollback tested

### Breaking Changes
- [ ] Breaking changes are documented
- [ ] Migration guide provided if needed
- [ ] Version bump is appropriate (semantic versioning)
- [ ] Deprecation notices added where applicable

---

## GitHub CLI (gh) Tool Usage

The GitHub CLI (`gh`) streamlines workflow for issues, pull requests, and repository management.

### Installation

```bash
# macOS
brew install gh

# Debian/Ubuntu
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh

# Authenticate
gh auth login
```

### Issue Management

```bash
# View issue details
gh issue view 58
gh issue view 58 --web  # Open in browser

# List issues
gh issue list
gh issue list --label "bug"
gh issue list --assignee @me

# Create a new issue
gh issue create --title "Bug: Login fails" --body "Description here" --label "bug"

# Create issue interactively
gh issue create

# Close an issue
gh issue close 58

# Reopen an issue
gh issue reopen 58

# Add comment to issue
gh issue comment 58 --body "Working on this now"
```

### Branch Management with Issues

```bash
# Create and checkout branch for an issue
gh issue develop 58 --checkout

# Or manually with naming convention
git checkout -b 58-add-github-copilot-instructions
```

### Pull Request Workflows

```bash
# Create a PR (interactive)
gh pr create

# Create a PR with all details inline
gh pr create \
  --title "feat: add GitHub Copilot instructions" \
  --body "Implements comprehensive Copilot instructions for Go and Android development.

## Changes
- Added .github/copilot-instructions.md
- Included coding standards, testing requirements
- Added security and performance guidelines
- Included gh CLI usage instructions

Fixes #58" \
  --base main \
  --head 58-add-github-copilot-instructions \
  --label "documentation,enhancement"

# Create draft PR
gh pr create --draft

# View PR status
gh pr status

# List PRs
gh pr list
gh pr list --author @me
gh pr list --label "enhancement"

# View PR details
gh pr view 123
gh pr view 123 --web

# Checkout a PR locally
gh pr checkout 123

# Review a PR
gh pr review 123 --approve
gh pr review 123 --comment --body "Looks good!"
gh pr review 123 --request-changes --body "Please fix the tests"

# Add comment to PR
gh pr comment 123 --body "Great work!"

# Merge PR
gh pr merge 123
gh pr merge 123 --squash
gh pr merge 123 --merge
gh pr merge 123 --rebase

# Close PR without merging
gh pr close 123

# Check PR checks status
gh pr checks
```

### Common Development Workflow

```bash
# 1. Find an issue to work on
gh issue list --label "good first issue"

# 2. Create branch for the issue
gh issue develop 58 --checkout

# 3. Make changes and commit
git add .
git commit -m "feat: add copilot instructions for Go and Android"

# 4. Push branch
git push origin 58-add-github-copilot-instructions

# 5. Create PR linking to issue
gh pr create \
  --title "feat: add GitHub Copilot instructions" \
  --body "Closes #58" \
  --label "documentation,enhancement"

# 6. Check PR status and CI
gh pr status
gh pr checks

# 7. View PR in browser for review
gh pr view --web

# 8. After approval, merge
gh pr merge --squash
```

### Repository Operations

```bash
# Clone repository
gh repo clone DanyalTorabi/sms-syncer-server

# Fork repository
gh repo fork DanyalTorabi/sms-syncer-server

# View repository in browser
gh repo view --web

# Create a repository
gh repo create my-new-repo --public
```

### Release Management

```bash
# Create a release
gh release create v1.2.0 \
  --title "Release v1.2.0" \
  --notes "Bug fixes and improvements"

# List releases
gh release list

# View release
gh release view v1.2.0

# Download release assets
gh release download v1.2.0
```

### Workflow and Actions

```bash
# List workflow runs
gh run list

# View workflow run details
gh run view 123456

# Watch a workflow run
gh run watch

# Re-run a workflow
gh run rerun 123456

# View workflow logs
gh run view 123456 --log
```

### Aliases for Common Tasks

Add to your shell configuration (`~/.bashrc` or `~/.zshrc`):

```bash
# Quick PR creation
alias ghpr='gh pr create --web'

# View my PRs
alias ghmyprs='gh pr list --author @me'

# View my issues
alias ghmyissues='gh issue list --assignee @me'

# Quick issue creation
alias ghissue='gh issue create --web'
```

---

## Common Patterns and Examples

### Conventional Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only changes
- `style`: Code style changes (formatting, missing semicolons, etc.)
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvements
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to build process or auxiliary tools

**Examples:**
```bash
git commit -m "feat: add batch SMS endpoint"
git commit -m "fix: handle nil pointer in JWT validation"
git commit -m "docs: update API documentation for new endpoint"
git commit -m "test: add integration tests for SMS handler"
git commit -m "refactor: extract validation logic to separate package"
git commit -m "perf: add database indexes for user queries"
```

### Middleware Pattern

```go
// Define middleware function
func LoggingMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        path := c.Request.URL.Path

        // Process request
        c.Next()

        // Log after request
        latency := time.Since(start)
        logger.Info("Request processed",
            zap.String("path", path),
            zap.Int("status", c.Writer.Status()),
            zap.Duration("latency", latency),
        )
    }
}

// Apply middleware
router.Use(LoggingMiddleware())
```

### Structured Logging

```go
import "go.uber.org/zap"

// Initialize logger
logger, _ := logger.InitLogger("info")

// Use structured logging
logger.Info("SMS message saved",
    zap.String("user_id", userID),
    zap.String("sms_id", smsID),
    zap.Int("message_length", len(body)),
)

logger.Error("Failed to save SMS",
    zap.Error(err),
    zap.String("user_id", userID),
)

// Debug level for detailed info
logger.Debug("Validating SMS",
    zap.Any("sms_data", smsRequest),
)
```

### Configuration Pattern

```go
// config.go
type Config struct {
    Server   ServerConfig
    Database DatabaseConfig
    JWT      JWTConfig
    Logging  LoggingConfig
}

func LoadConfig() (*Config, error) {
    cfg := DefaultConfig()
    
    // Override with environment variables
    if port := os.Getenv("SERVER_PORT"); port != "" {
        p, err := strconv.Atoi(port)
        if err != nil {
            return nil, fmt.Errorf("invalid SERVER_PORT: %w", err)
        }
        cfg.Server.Port = p
    }
    
    // Validate configuration
    if err := cfg.Validate(); err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }
    
    return cfg, nil
}

func (c *Config) Validate() error {
    if c.JWT.Secret == "" {
        return errors.New("JWT secret is required")
    }
    if c.Server.Port < 1 || c.Server.Port > 65535 {
        return errors.New("invalid server port")
    }
    return nil
}
```

### Repository Pattern

```go
// Define repository interface
type SMSRepository interface {
    Save(ctx context.Context, sms *models.SMS) error
    FindByID(ctx context.Context, id string) (*models.SMS, error)
    FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.SMS, error)
    Delete(ctx context.Context, id string) error
}

// Implement repository
type smsRepository struct {
    db *gorm.DB
}

func NewSMSRepository(db *gorm.DB) SMSRepository {
    return &smsRepository{db: db}
}

func (r *smsRepository) Save(ctx context.Context, sms *models.SMS) error {
    return r.db.WithContext(ctx).Create(sms).Error
}

func (r *smsRepository) FindByID(ctx context.Context, id string) (*models.SMS, error) {
    var sms models.SMS
    err := r.db.WithContext(ctx).Where("id = ?", id).First(&sms).Error
    if err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return nil, ErrSMSNotFound
        }
        return nil, err
    }
    return &sms, nil
}
```

---

## Quick Reference

### Essential Commands

```bash
# Code quality
make fmt                    # Format code
make lint                   # Run linters
make lint-fix              # Auto-fix issues
make test                  # Run tests
make coverage              # Generate coverage report

# Git hooks
./scripts/setup-git-hooks.sh  # One-time setup

# Development
make run                   # Run server
make build                 # Build binary
make clean                 # Clean build artifacts

# GitHub CLI
gh issue view <number>     # View issue
gh pr create              # Create PR
gh pr status              # Check PR status
```

### Important Files

- `.golangci.yml` - Linting configuration
- `Makefile` - Build automation
- `.github/workflows/` - CI/CD pipelines
- `docs/CONTRIBUTING.md` - Contribution guidelines
- `docs/DEVELOPMENT.md` - Development guide
- `API_DOCUMENTATION.md` - API reference

---

## Summary

**Remember the core principles:**

1. **Simple, clear, and understandable code** - Favor clarity over cleverness
2. **Unit tests for every change** - No exceptions
3. **All changes must be tested** - Manual and automated
4. **Minimum 80% test coverage** - Maintain or improve coverage
5. **Security first** - Validate inputs, protect secrets, log safely
6. **Performance matters** - Optimize queries, paginate results, set timeouts
7. **Document your work** - Comments, README, API docs
8. **Use the tools** - gh CLI, make targets, git hooks

When in doubt, refer to the existing codebase for patterns and conventions. Happy coding!
