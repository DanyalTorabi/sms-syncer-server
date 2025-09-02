# Development Guide

This guide provides detailed information for developers working on the SMS Sync Server project.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Development Environment](#development-environment)
- [Database Management](#database-management)
- [API Development](#api-development)
- [Testing Strategy](#testing-strategy)
- [Debugging](#debugging)
- [Performance Considerations](#performance-considerations)
- [Security Guidelines](#security-guidelines)

## Architecture Overview

### System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SMS Client    │    │  Load Balancer  │    │    Database     │
│   (Android)     │◄──►│     (nginx)     │◄──►│    (SQLite)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  SMS Sync       │
                    │  Server (Go)    │
                    └─────────────────┘
```

### Component Overview

- **HTTP Server**: Gin-based REST API server
- **Authentication**: JWT-based authentication system
- **Database**: SQLite with GORM ORM
- **Middleware**: Logging, CORS, rate limiting
- **Services**: Business logic layer
- **Models**: Data structures and validation

### Request Flow

1. Client sends request to API endpoint
2. Middleware processes request (auth, logging, etc.)
3. Handler extracts and validates parameters
4. Service layer processes business logic
5. Database layer persists/retrieves data
6. Response sent back through middleware chain

## Development Environment

### Required Tools

```bash
# Install Go (1.20+)
https://golang.org/dl/

# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/go-delve/delve/cmd/dlv@latest

# Install SQLite tools
sudo apt-get install sqlite3  # Ubuntu/Debian
brew install sqlite3          # macOS
```

### IDE Setup

#### VS Code
Recommended extensions:
- Go (official)
- REST Client
- SQLite Viewer
- Thunder Client (API testing)

#### GoLand/IntelliJ
- Built-in Go support
- Database tools
- HTTP client

### Environment Variables

Create a `.env` file for development:

```bash
# Server Configuration
SERVER_HOST=localhost
SERVER_PORT=8080

# Database
DATABASE_DSN=./sms.db

# JWT Configuration
JWT_SECRET=your-secret-key-here
JWT_TOKEN_EXPIRY=24h

# Logging
LOG_LEVEL=debug
LOG_PATH=./server.log

# Development
GO_ENV=development
DEBUG=true
```

## Database Management

### Schema Evolution

The database schema is managed through migrations:

```go
// internal/db/migrations.go
func runMigrations(db *gorm.DB) error {
    return db.AutoMigrate(
        &models.SMSMessage{},
        &models.User{},
    )
}
```

### Development Database

```bash
# Reset development database
rm -f sms.db
go run cmd/server/main.go  # Will recreate schema

# Inspect database
sqlite3 sms.db
.tables
.schema sms_messages
SELECT * FROM sms_messages LIMIT 5;
```

### Database Testing

Use separate test databases:

```go
func setupTestDB(t *testing.T) *db.Database {
    tempDir := t.TempDir()
    dbPath := filepath.Join(tempDir, "test.db")
    database, err := db.NewDatabase("file:" + dbPath)
    require.NoError(t, err)
    return database
}
```

## API Development

### Adding New Endpoints

1. **Define the model** (if needed):
```go
// internal/models/example.go
type Example struct {
    ID        uint      `json:"id" gorm:"primaryKey"`
    Name      string    `json:"name" validate:"required"`
    CreatedAt time.Time `json:"created_at"`
}
```

2. **Create the service**:
```go
// internal/services/example_service.go
type ExampleService struct {
    db *db.Database
}

func (s *ExampleService) CreateExample(example *models.Example) error {
    return s.db.Create(example)
}
```

3. **Implement the handler**:
```go
// internal/handlers/example_handler.go
func (h *ExampleHandler) CreateExample(c *gin.Context) {
    var example models.Example
    if err := c.ShouldBindJSON(&example); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    if err := h.service.CreateExample(&example); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    c.JSON(http.StatusCreated, example)
}
```

4. **Register the route**:
```go
// router/router.go
func SetupRoutes(r *gin.Engine, services *Services) {
    api := r.Group("/api")
    {
        examples := api.Group("/examples")
        examples.Use(middleware.AuthMiddleware())
        {
            examples.POST("/", exampleHandler.CreateExample)
        }
    }
}
```

### Request/Response Patterns

#### Standard Response Format
```go
// Success response
{
    "data": {...},
    "message": "Success",
    "status": 200
}

// Error response
{
    "error": "Error message",
    "code": "ERROR_CODE",
    "status": 400
}
```

#### Pagination
```go
type PaginatedResponse struct {
    Data       interface{} `json:"data"`
    Pagination Pagination  `json:"pagination"`
}

type Pagination struct {
    Page       int `json:"page"`
    Limit      int `json:"limit"`
    Total      int `json:"total"`
    TotalPages int `json:"total_pages"`
}
```

## Testing Strategy

### Test Structure

```
internal/
├── handlers/
│   ├── auth_handler.go
│   ├── auth_handler_test.go      # Unit tests
│   └── integration_test.go       # Integration tests
├── services/
│   ├── sms_service.go
│   └── sms_service_test.go       # Unit tests
└── models/
    ├── sms.go
    └── sms_test.go               # Model tests
```

### Testing Patterns

#### Table-Driven Tests
```go
func TestValidatePhoneNumber(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    bool
        wantErr bool
    }{
        {"valid US number", "+1234567890", true, false},
        {"invalid format", "123", false, true},
        {"empty string", "", false, true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ValidatePhoneNumber(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidatePhoneNumber() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("ValidatePhoneNumber() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

#### HTTP Handler Testing
```go
func TestCreateSMS(t *testing.T) {
    // Setup
    router := setupTestRouter()
    
    // Test data
    sms := SMSMessage{
        PhoneNumber: "+1234567890",
        Body:        "Test message",
        EventType:   "RECEIVED",
    }
    
    body, _ := json.Marshal(sms)
    req := httptest.NewRequest("POST", "/api/sms", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer " + validJWT)
    
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    // Assert
    assert.Equal(t, http.StatusCreated, w.Code)
}
```

### Mock Generation

Use mockgen for generating mocks:

```bash
# Install mockgen
go install github.com/golang/mock/mockgen@latest

# Generate mocks
mockgen -source=internal/services/sms_service.go -destination=internal/mocks/sms_service_mock.go
```

## Debugging

### Logging

Use structured logging:

```go
import "sms-sync-server/pkg/logger"

// In handlers
logger.Info("Processing SMS request", 
    "user_id", userID,
    "phone_number", msg.PhoneNumber,
)

logger.Error("Failed to save SMS",
    "user_id", userID,
    "error", err.Error(),
)
```

### Delve Debugger

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug application
dlv debug cmd/server/main.go

# Debug specific test
dlv test internal/handlers/ -- -test.run TestLogin
```

### Common Debug Scenarios

#### Database Issues
```bash
# Check database file
ls -la *.db

# Inspect database
sqlite3 sms.db
.tables
.schema

# Check connections
lsof -p $(pgrep sms-sync-server)
```

#### HTTP Issues
```bash
# Check server logs
tail -f server.log

# Test endpoints manually
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}'
```

## Performance Considerations

### Database Optimization

1. **Indexes**: Add indexes for frequently queried fields
```sql
CREATE INDEX idx_sms_user_id ON sms_messages(user_id);
CREATE INDEX idx_sms_timestamp ON sms_messages(sms_timestamp);
```

2. **Query Optimization**: Use appropriate queries
```go
// Good: specific fields
db.Select("id", "phone_number", "body").Find(&messages)

// Bad: select all
db.Find(&messages)
```

3. **Pagination**: Always paginate large result sets
```go
func GetMessages(userID string, limit, offset int) ([]*SMSMessage, error) {
    var messages []*SMSMessage
    return messages, db.Where("user_id = ?", userID).
        Limit(limit).
        Offset(offset).
        Find(&messages).Error
}
```

### HTTP Performance

1. **Connection Pooling**: Configure HTTP client timeouts
2. **Compression**: Enable gzip compression
3. **Rate Limiting**: Implement rate limiting middleware
4. **Caching**: Cache frequent database queries

### Memory Management

1. **Connection Pools**: Limit database connections
2. **Request Size**: Limit request body size
3. **Timeout**: Set appropriate timeouts
4. **Garbage Collection**: Monitor GC performance

## Security Guidelines

### Authentication & Authorization

1. **JWT Security**: Use strong secrets, proper expiration
2. **Password Hashing**: Use bcrypt for password hashing
3. **Rate Limiting**: Prevent brute force attacks
4. **Input Validation**: Validate all user inputs

### Data Protection

1. **SQL Injection**: Use parameterized queries (GORM handles this)
2. **XSS Prevention**: Sanitize user inputs
3. **HTTPS**: Always use HTTPS in production
4. **Sensitive Data**: Don't log sensitive information

### Configuration Security

1. **Environment Variables**: Use env vars for secrets
2. **File Permissions**: Secure config files (600 permissions)
3. **Secret Rotation**: Implement secret rotation
4. **Audit Logging**: Log security events

### Development Security

```go
// Good: Environment-based secrets
jwtSecret := os.Getenv("JWT_SECRET")
if jwtSecret == "" {
    log.Fatal("JWT_SECRET environment variable required")
}

// Bad: Hardcoded secrets
jwtSecret := "hardcoded-secret-key"
```

Remember to never commit secrets to version control and always use environment variables or secure secret management systems in production.
