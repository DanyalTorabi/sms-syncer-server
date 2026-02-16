# User Management System - Complete Ticket Tree

This document outlines all GitHub issues created for implementing the user management and authentication system across both the server and Android client.

---

## **Server Repository: sms-syncer-server**

**Repository:** https://github.com/DanyalTorabi/sms-syncer-server  
**Total Tickets:** 30 (Issues #60-#89)  
**Total Effort:** ~75 story points

### **EPIC Issue**
- **#60** - EPIC: Implement User Management & RBAC System
  - Main tracking issue for all server-side user management work

---

### **Milestone 1: Database Schema & Models** (3 tickets, 7 points)

**Start Here** - No dependencies, foundation for everything else

1. **#61** - Create Database Schema for Users, Groups, and Permissions
   - **Priority:** HIGH | **Effort:** 3 points
   - **Dependencies:** None
   - **Tasks:** Create SQLite tables, indexes, foreign keys
   - **Files:** `internal/db/database.go`

2. **#62** - Create User, Group, and Permission Models
   - **Priority:** HIGH | **Effort:** 2 points
   - **Dependencies:** #61
   - **Tasks:** Go structs, JSON tags, validation, helper methods
   - **Files:** `internal/models/user.go`, `group.go`, `permission.go`

3. **#63** - Create Database Seed Data with Admin User & Default Permissions
   - **Priority:** HIGH | **Effort:** 2 points
   - **Dependencies:** #61, #62
   - **Tasks:** SeedDatabase() function, admin user, default permissions
   - **Files:** `internal/db/database.go`, `internal/config/config.go`, `cmd/server/main.go`

---

### **Milestone 2: User Repository & Service Layer** (5 tickets, 18 points)

**Depends on:** Milestone 1 complete

4. **#64** - Create User Repository with CRUD Operations
   - **Priority:** HIGH | **Effort:** 5 points
   - **Dependencies:** #62
   - **Tasks:** UserRepository interface, SQL queries, CRUD methods
   - **Files:** `internal/db/user_repository.go`

5. **#65** - Create Group Repository with CRUD Operations
   - **Priority:** HIGH | **Effort:** 3 points
   - **Dependencies:** #62
   - **Tasks:** GroupRepository interface, CRUD methods
   - **Files:** `internal/db/group_repository.go`

6. **#66** - Create Permission Repository with CRUD Operations
   - **Priority:** MEDIUM | **Effort:** 2 points
   - **Dependencies:** #62
   - **Tasks:** PermissionRepository interface, CRUD methods
   - **Files:** `internal/db/permission_repository.go`

7. **#67** - Create User Service with Business Logic
   - **Priority:** HIGH | **Effort:** 5 points
   - **Dependencies:** #64
   - **Tasks:** Password hashing (bcrypt), TOTP validation, business logic
   - **Files:** `internal/services/user_service.go`
   - **New Dependencies:** `bcrypt`, `otp`, `uuid`

8. **#68** - Create Group & Permission Services
   - **Priority:** MEDIUM | **Effort:** 3 points
   - **Dependencies:** #65, #66
   - **Tasks:** GroupService, PermissionService with validation
   - **Files:** `internal/services/group_service.go`, `permission_service.go`

---

### **Milestone 3: Authentication API** (5 tickets, 19 points)

**Depends on:** Milestone 2 complete

9. **#69** - Enhance JWT Token Generation with Permission UUIDs
   - **Priority:** HIGH | **Effort:** 3 points
   - **Dependencies:** #67
   - **Tasks:** Update Claims struct, include permissions array, 1-hour expiry
   - **Files:** `internal/handlers/auth_handler.go`, `internal/config/config.go`

10. **#70** - Implement Login Endpoint with Password + 2FA Verification
    - **Priority:** HIGH | **Effort:** 5 points
    - **Dependencies:** #67, #69
    - **Tasks:** Replace hardcoded login, bcrypt verification, TOTP check, account lockout
    - **Files:** `internal/handlers/auth_handler.go`

11. **#71** - Implement User Registration Endpoint
    - **Priority:** HIGH | **Effort:** 3 points
    - **Dependencies:** #67
    - **Tasks:** POST /api/users, validation, password strength check
    - **Files:** `internal/handlers/user_handler.go`, `cmd/server/server.go`

12. **#72** - Implement Password Reset Endpoint
    - **Priority:** MEDIUM | **Effort:** 4 points
    - **Dependencies:** #67
    - **Tasks:** Admin reset, self-reset with old password verification
    - **Files:** `internal/handlers/user_handler.go`

13. **#73** - Implement 2FA Enable/Disable Endpoints
    - **Priority:** MEDIUM | **Effort:** 4 points
    - **Dependencies:** #67, #69
    - **Tasks:** TOTP secret generation, QR code, AES encryption
    - **Files:** `internal/handlers/auth_handler.go`, `internal/services/user_service.go`
    - **New Dependencies:** `go-qrcode`

---

### **Milestone 4: User Management API** (3 tickets, 7 points)

**Depends on:** Milestone 3 (#71) complete

14. **#74** - Implement User List & View Endpoints
    - **Priority:** HIGH | **Effort:** 2 points
    - **Dependencies:** #67, #71
    - **Tasks:** GET /api/users (pagination), GET /api/users/:id
    - **Files:** `internal/handlers/user_handler.go`, `cmd/server/server.go`

15. **#75** - Implement User Update & Delete Endpoints
    - **Priority:** HIGH | **Effort:** 3 points
    - **Dependencies:** #67
    - **Tasks:** PUT /api/users/:id, DELETE /api/users/:id (soft delete)
    - **Files:** `internal/handlers/user_handler.go`

16. **#76** - Implement User-Group Assignment Endpoints
    - **Priority:** MEDIUM | **Effort:** 2 points
    - **Dependencies:** #67, #68
    - **Tasks:** POST/DELETE /api/users/:id/groups, GET /api/users/:id/groups
    - **Files:** `internal/handlers/user_handler.go`

---

### **Milestone 5: Group & Permission Management API** (3 tickets, 7 points)

**Depends on:** Milestone 2 (#68) complete

17. **#77** - Implement Group CRUD Endpoints
    - **Priority:** MEDIUM | **Effort:** 3 points
    - **Dependencies:** #68
    - **Tasks:** POST/GET/PUT/DELETE /api/groups, pagination
    - **Files:** `internal/handlers/group_handler.go`, `cmd/server/server.go`

18. **#78** - Implement Group-Permission Assignment Endpoints
    - **Priority:** MEDIUM | **Effort:** 2 points
    - **Dependencies:** #77
    - **Tasks:** POST/DELETE /api/groups/:id/permissions
    - **Files:** `internal/handlers/group_handler.go`

19. **#79** - Implement Permission CRUD Endpoints
    - **Priority:** LOW | **Effort:** 2 points
    - **Dependencies:** #68
    - **Tasks:** POST/GET/PUT/DELETE /api/permissions
    - **Files:** `internal/handlers/permission_handler.go`

---

### **Milestone 6: Authorization Middleware** (2 tickets, 7 points)

**Depends on:** Milestone 3 (#69) complete, all API endpoints done

20. **#80** - Create Permission-Based Authorization Middleware
    - **Priority:** HIGH | **Effort:** 4 points
    - **Dependencies:** #69
    - **Tasks:** RequirePermission(), RequireAnyPermission(), IsSelfOrHasPermission()
    - **Files:** `pkg/middleware/auth.go`

21. **#81** - Apply Permission Middleware to All Protected Routes
    - **Priority:** HIGH | **Effort:** 3 points
    - **Dependencies:** #80, #74, #75, #76, #77, #78, #79
    - **Tasks:** Update all route definitions with permission checks
    - **Files:** `cmd/server/server.go`, `API_DOCUMENTATION.md`

---

### **Milestone 7: Documentation & Configuration** (3 tickets, 5 points)

**Depends on:** All API work complete

22. **#82** - Update API Documentation
    - **Priority:** MEDIUM | **Effort:** 2 points
    - **Dependencies:** #81
    - **Tasks:** Update API_DOCUMENTATION.md, Postman collection
    - **Files:** `API_DOCUMENTATION.md`, `postman-collection.json`

23. **#83** - Add Environment Variable Configuration
    - **Priority:** HIGH | **Effort:** 2 points
    - **Dependencies:** #63, #69, #73
    - **Tasks:** Load from env vars, create .env.example, validation
    - **Files:** `internal/config/config.go`, `.env.example`, `README.md`

24. **#84** - Add Database Migrations Documentation
    - **Priority:** LOW | **Effort:** 1 point
    - **Dependencies:** #61
    - **Tasks:** Create DATABASE_SCHEMA.md, ER diagram
    - **Files:** `docs/DATABASE_SCHEMA.md`, `README.md`

---

### **Milestone 8: Integration & End-to-End Testing** (2 tickets, 8 points)

**Depends on:** All implementation complete

25. **#85** - Create End-to-End Integration Tests
    - **Priority:** HIGH | **Effort:** 5 points
    - **Dependencies:** #81
    - **Tasks:** Full user lifecycle tests, 2FA flows, permission enforcement
    - **Files:** `internal/handlers/integration_test.go`

26. **#86** - Add Security Tests
    - **Priority:** HIGH | **Effort:** 3 points
    - **Dependencies:** #85
    - **Tasks:** SQL injection, JWT tampering, sensitive data exposure tests
    - **Files:** `internal/handlers/security_test.go`

---

### **Milestone 9: Performance & Cleanup** (3 tickets, 5 points)

**Final polish**

27. **#87** - Add Database Indexes for Performance
    - **Priority:** MEDIUM | **Effort:** 1 point
    - **Dependencies:** #61
    - **Tasks:** Review queries, add indexes, document strategy
    - **Files:** `internal/db/database.go`, `docs/DATABASE_SCHEMA.md`

28. **#88** - Add Logging for Security Events
    - **Priority:** MEDIUM | **Effort:** 2 points
    - **Dependencies:** #70, #71, #72, #73
    - **Tasks:** Structured logging for login, password changes, 2FA, user CRUD
    - **Files:** `internal/handlers/auth_handler.go`, `user_handler.go`, `internal/services/user_service.go`

29. **#89** - Code Review & Cleanup
    - **Priority:** LOW | **Effort:** 2 points
    - **Dependencies:** #87, #88
    - **Tasks:** Lint, test coverage ≥80%, cleanup, documentation
    - **Files:** All files

---

## **Android Client Repository: SmsLogger**

**Repository:** https://github.com/DanyalTorabi/SmsLogger  
**Total Tickets:** 14 (Issues #44-#59)  
**Total Effort:** ~35 story points

### **EPIC Issue**
- **#44** - EPIC: Support User Management & Authentication System
  - Main tracking issue for all Android client work
  - **Depends on Server:** Complete #60-#81 minimum for testing

---

### **Milestone 1: Authentication UI & Flow** (4 tickets, 14 points)

**Start Here** - Foundation for Android authentication

1. **#45** - Create Login Screen UI with Username/Password Fields
   - **Priority:** HIGH | **Effort:** 3 points
   - **Dependencies:** None
   - **Tasks:** LoginActivity, Material Design 3, username/password/TOTP fields
   - **Files:** `app/src/main/java/com/example/smslogger/ui/LoginActivity.kt`

2. **#46** - Implement Secure Credential Storage with Android Keystore
   - **Priority:** HIGH | **Effort:** 4 points
   - **Dependencies:** #45
   - **Tasks:** SecureStorage class, EncryptedSharedPreferences, token storage
   - **Files:** `app/src/main/java/com/example/smslogger/security/SecureStorage.kt`
   - **Dependencies:** `androidx.security:security-crypto`

3. **#47** - Create Authentication ViewModel with Login Logic
   - **Priority:** HIGH | **Effort:** 4 points
   - **Dependencies:** #45, #46
   - **Tasks:** AuthViewModel, login flow, error handling, state management
   - **Files:** `app/src/main/java/com/example/smslogger/viewmodel/AuthViewModel.kt`

4. **#48** - Implement Auto-Logout and Re-Authentication Flow
   - **Priority:** HIGH | **Effort:** 3 points
   - **Dependencies:** #47
   - **Tasks:** 401 interceptor, token expiry checks, WorkManager for background checks
   - **Files:** `app/src/main/java/com/example/smslogger/network/AuthInterceptor.kt`

---

### **Milestone 2: JWT Token Management** (3 tickets, 8 points)

**Depends on:** Milestone 1 (#46) complete

5. **#49** - Update API Client to Send JWT in Authorization Header
   - **Priority:** HIGH | **Effort:** 3 points
   - **Dependencies:** #46
   - **Tasks:** AuthorizationInterceptor, add Bearer token to all requests
   - **Files:** `app/src/main/java/com/example/smslogger/network/AuthorizationInterceptor.kt`

6. **#50** - Update Login API Models for New Authentication Format
   - **Priority:** HIGH | **Effort:** 2 points
   - **Dependencies:** None
   - **Tasks:** LoginRequest, LoginResponse, UserInfo, ErrorResponse data classes
   - **Files:** `app/src/main/java/com/example/smslogger/data/model/`

7. **#51** - Create Authentication Repository for API Calls
   - **Priority:** HIGH | **Effort:** 3 points
   - **Dependencies:** #49, #50
   - **Tasks:** AuthRepository, API error handling, error mapping
   - **Files:** `app/src/main/java/com/example/smslogger/data/repository/AuthRepository.kt`

---

### **Milestone 3: 2FA Support** (1 ticket, 2 points)

**Simplified** - No QR scanner, users use Google Authenticator

8. **#52** - Add TOTP Code Input Field to Login Screen
   - **Priority:** MEDIUM | **Effort:** 2 points
   - **Dependencies:** #45
   - **Tasks:** Optional TOTP field (6 digits), validation, help text
   - **Files:** `app/src/main/res/layout/activity_login.xml`

---

### **Milestone 4: API Integration Updates** (3 tickets, 6 points)

**Depends on:** Milestone 2 complete

9. **#53** - Update SMS Sync to Use New JWT Authentication
   - **Priority:** HIGH | **Effort:** 2 points
   - **Dependencies:** #49
   - **Tasks:** Verify JWT in sync requests, handle 401, retry logic
   - **Files:** SMS sync service/repository

10. **#54** - Create Settings Screen for Account Management
    - **Priority:** MEDIUM | **Effort:** 2 points
    - **Dependencies:** #47
    - **Tasks:** SettingsActivity, logout, account info, 2FA info
    - **Files:** `app/src/main/java/com/example/smslogger/ui/SettingsActivity.kt`

11. **#55** - Handle Account Lockout and Error Messages
    - **Priority:** MEDIUM | **Effort:** 2 points
    - **Dependencies:** #47
    - **Tasks:** Error message mapping, user-friendly messages, UI updates
    - **Files:** AuthViewModel, LoginActivity

---

### **Milestone 5: Security Enhancements** (2 tickets, 7 points)

**Important for production**

12. **#56** - Implement Certificate Pinning for API Security
    - **Priority:** HIGH | **Effort:** 3 points
    - **Dependencies:** #49
    - **Tasks:** CertificatePinner, pin server certificate, handle failures
    - **Files:** OkHttpClient configuration

13. **#57** - Add Biometric Authentication for Quick Login (Optional)
    - **Priority:** LOW | **Effort:** 4 points
    - **Dependencies:** #46
    - **Tasks:** BiometricPrompt, fingerprint/face unlock, fallback
    - **Files:** `app/src/main/java/com/example/smslogger/security/BiometricAuthManager.kt`
    - **Dependencies:** `androidx.biometric:biometric`

---

### **Milestone 6: Testing & Polish** (2 tickets, 7 points)

**Final steps**

14. **#58** - Add Unit and Integration Tests for Authentication
    - **Priority:** MEDIUM | **Effort:** 5 points
    - **Dependencies:** #51
    - **Tasks:** Unit tests for ViewModel, SecureStorage, Repository; Integration tests
    - **Files:** Test files for all components
    - **Dependencies:** `mockwebserver`, `kotlinx-coroutines-test`

15. **#59** - Polish UI/UX and Update Documentation
    - **Priority:** LOW | **Effort:** 2 points
    - **Dependencies:** #55
    - **Tasks:** Animations, accessibility, README, screenshots, CHANGELOG
    - **Files:** `README.md`, `CHANGELOG.md`

---

## **Implementation Order**

### **Phase 1: Server Foundation** (Start here)
1. Complete Server Milestone 1 (#61-#63) - Database & Models
2. Complete Server Milestone 2 (#64-#68) - Repositories & Services
3. Complete Server Milestone 3 (#69-#73) - Authentication API

### **Phase 2: Parallel Development**
**Server:**
4. Complete Server Milestone 4 (#74-#76) - User Management API
5. Complete Server Milestone 5 (#77-#79) - Group/Permission API
6. Complete Server Milestone 6 (#80-#81) - Authorization Middleware

**Android (can start after Phase 1):**
7. Complete Android Milestone 1 (#45-#48) - Auth UI & Flow
8. Complete Android Milestone 2 (#49-#51) - JWT Management
9. Complete Android Milestone 3 (#52) - 2FA Input

### **Phase 3: Integration & Polish**
**Server:**
10. Complete Server Milestone 7 (#82-#84) - Documentation
11. Complete Server Milestone 8 (#85-#86) - Testing
12. Complete Server Milestone 9 (#87-#89) - Performance & Cleanup

**Android:**
13. Complete Android Milestone 4 (#53-#55) - API Integration
14. Complete Android Milestone 5 (#56-#57) - Security
15. Complete Android Milestone 6 (#58-#59) - Testing & Polish

---

## **Critical Path**

```
Server: #61 → #62 → #63 → #64 → #67 → #69 → #70 → #80 → #81
Android: #45 → #46 → #47 → #49 → #50 → #51 → #53
```

**Minimum Viable Product (MVP):**
- Server: Issues #61-#70, #80-#81 (login with password + optional 2FA, JWT auth)
- Android: Issues #45-#53 (login UI, JWT storage, API integration)

**Full Feature Set:**
- All 44 tickets (30 server + 14 Android)

---

## **Quick Start Commands**

### **View EPIC Issues**
```bash
# Server
gh issue view 60

# Android
gh issue view 44 --repo DanyalTorabi/SmsLogger
```

### **Start First Ticket**
```bash
# Server - Start with database schema
gh issue develop 61 --checkout

# Android - Start with login UI (after server auth is done)
gh issue develop 45 --repo DanyalTorabi/SmsLogger --checkout
```

### **Track Progress**
```bash
# List all user management tickets (server)
gh issue list --label "enhancement" --search "user OR auth OR 2fa OR jwt OR permission OR group"

# List Android tickets
gh issue list --repo DanyalTorabi/SmsLogger --label "enhancement"
```

---

## **Key Dependencies to Install**

### **Server (Go)**
```bash
go get golang.org/x/crypto/bcrypt
go get github.com/pquerna/otp
go get github.com/google/uuid
go get github.com/skip2/go-qrcode
```

### **Android (Gradle)**
```gradle
// Security
implementation 'androidx.security:security-crypto:1.1.0-alpha06'

// Biometric (optional)
implementation 'androidx.biometric:biometric:1.1.0'

// Testing
testImplementation 'com.squareup.okhttp3:mockwebserver:4.11.0'
testImplementation 'org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3'
```

---

## **Environment Variables Required**

### **Server**
```bash
JWT_SECRET=<random-secret-key>  # Required
JWT_TOKEN_EXPIRY=1h
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<secure-password>  # Required on first run
TOTP_ENCRYPTION_KEY=<32-byte-hex>  # Required
SERVER_PORT=8080
DATABASE_DSN=file:sms.db?cache=shared&mode=rwc
LOG_LEVEL=info
```

---

## **Notes**

- **2FA Setup:** Users configure TOTP in Google Authenticator (no QR scanner in Android app)
- **Testing:** Maintain 80%+ code coverage on server
- **Security:** All passwords hashed with bcrypt, TOTP secrets encrypted
- **JWT:** Stateless with 1-hour expiry, contains permission UUIDs
- **Email Verification:** Flagged for future implementation (not in current scope)

Good luck with the implementation! 🚀
