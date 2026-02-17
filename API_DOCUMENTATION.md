# SMS Sync Server API Documentation

## Table of Contents
1. [Authentication](#authentication)
   - [Login](#login-endpoint)
   - [User Registration](#user-registration-endpoint)
2. [Password Management](#password-management)
   - [Change Password](#change-password-endpoint)
   - [Admin Reset Password](#admin-reset-password-endpoint)
3. [Two-Factor Authentication](#two-factor-authentication)
   - [Generate 2FA Secret](#generate-2fa-secret-endpoint)
   - [Enable 2FA](#enable-2fa-endpoint)
   - [Disable 2FA](#disable-2fa-endpoint)
4. [SMS Operations](#sms-operations)
   - [Add SMS Message](#add-sms-message-endpoint)

---

## Authentication

### Login Endpoint

#### Overview
Authenticates a user and returns a JWT token with 1-hour expiry. The token includes user information and their effective permissions.

#### Endpoint Details

**URL:** `POST /api/auth/login`  
**Content-Type:** `application/json`  
**Authentication:** Not required (public endpoint)

#### Request Schema

```json
{
  "username": "testuser",
  "password": "testpass",
  "totp_code": "123456"  // Optional: 2FA code if enabled
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | **Yes** | User's username (3-50 characters) |
| `password` | string | **Yes** | User's password (minimum 8 characters) |
| `totp_code` | string | No | 6-digit TOTP code (required if 2FA is enabled for user) |

#### Response

**Success Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "testuser"
}
```

**JWT Token Contents:**
The token contains the following claims:
- `user_id`: User's UUID
- `username`: Username
- `permissions`: Array of permission UUIDs the user has access to
- `exp`: Token expiration time (1 hour from issue)
- `iat`: Token issued at time
- `nbf`: Token not before time

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Missing credentials | `{"error": "Username and password are required"}` |
| 401 Unauthorized | Invalid credentials | `{"error": "Invalid credentials"}` |
| 403 Forbidden | Account locked | `{"error": "Account is locked due to too many failed login attempts"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to generate token"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

#### Example Response

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwidXNlcm5hbWUiOiJhZG1pbiIsInBlcm1pc3Npb25zIjpbInBlcm0tMSIsInBlcm0tMiJdLCJleHAiOjE3MDk1NjcwMDB9...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "admin"
}
```

---

### User Registration Endpoint

#### Overview
Creates a new user account. Validates username, email, and password strength. Usernames and emails must be unique.

#### Endpoint Details

**URL:** `POST /api/users`  
**Content-Type:** `application/json`  
**Authentication:** Not required (public endpoint)

#### Request Schema

```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "SecurePassword123!"
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | **Yes** | Username (3-50 characters, alphanumeric and underscores only) |
| `email` | string | **Yes** | Valid email address |
| `password` | string | **Yes** | Password (minimum 8 characters) |

#### Password Requirements
- Minimum 8 characters length
- Password is hashed using bcrypt before storage

#### Response

**Success Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "newuser",
  "email": "newuser@example.com",
  "active": true,
  "created_at": 1692864000
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Missing field | `{"error": "Username is required"}` |
| 400 Bad Request | Invalid username | `{"error": "username must be 3-50 characters..."}` |
| 400 Bad Request | Invalid email | `{"error": "invalid email format"}` |
| 400 Bad Request | Weak password | `{"error": "password must be at least 8 characters"}` |
| 400 Bad Request | Duplicate username | `{"error": "username already exists"}` |
| 400 Bad Request | Duplicate email | `{"error": "email already exists"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john.doe@example.com",
    "password": "SecurePass123!"
  }'
```

#### Example Response

```json
{
  "id": "a3f2e1d0-b9c8-47a6-8f5e-4d3c2b1a0987",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "active": true,
  "created_at": 1709500000
}
```

---

## Password Management

### Change Password Endpoint

#### Overview
Allows users to change their own password. Requires authentication and verification of the current password.

#### Endpoint Details

**URL:** `POST /api/users/:id/password`  
**Content-Type:** `application/json`  
**Authentication:** Required (Bearer token)

#### Request Parameters

| Parameter | Location | Required | Description |
|-----------|----------|----------|-------------|
| `id` | Path | **Yes** | User ID (must match authenticated user) |

#### Request Schema

```json
{
  "old_password": "currentpassword",
  "new_password": "newsecurepassword"
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `old_password` | string | **Yes** | Current password for verification |
| `new_password` | string | **Yes** | New password (minimum 8 characters) |

#### Response

**Success Response (200 OK):**
```json
{
  "message": "Password changed successfully"
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Missing required fields or weak password | `{"error": "old password and new password are required"}` or `{"error": "password must be at least 8 characters"}` |
| 401 Unauthorized | Incorrect old password | `{"error": "Incorrect old password"}` |
| 403 Forbidden | User attempting to change another user's password | `{"error": "You can only change your own password"}` |
| 404 Not Found | User not found | `{"error": "User not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to change password"}` |

#### Example Request

```bash
# Get authentication token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"oldpass"}' \
  | jq -r '.token')

# Change password
curl -X POST http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000/password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "oldpass",
    "new_password": "newsecurepass123"
  }'
```

---

### Admin Reset Password Endpoint

#### Overview
Allows administrators to reset a user's password without knowing the current password. This is an administrative function for account recovery.

#### Endpoint Details

**URL:** `POST /api/admin/users/:id/password/reset`  
**Content-Type:** `application/json`  
**Authentication:** Required (Bearer token with admin permissions)

#### Request Parameters

| Parameter | Location | Required | Description |
|-----------|----------|----------|-------------|
| `id` | Path | **Yes** | User ID to reset password for |

#### Request Schema

```json
{
  "new_password": "temporarypassword123"
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `new_password` | string | **Yes** | New password (minimum 8 characters) |

#### Response

**Success Response (200 OK):**
```json
{
  "message": "Password reset successfully"
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Missing new password or weak password | `{"error": "new password is required"}` or `{"error": "password must be at least 8 characters"}` |
| 404 Not Found | User not found | `{"error": "User not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to reset password"}` |

#### Example Request

```bash
# Admin resets user password
curl -X POST http://localhost:8080/api/admin/users/550e8400-e29b-41d4-a716-446655440000/password/reset \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "new_password": "temporarypassword123"
  }'
```

#### Security Notes

1. This endpoint bypasses old password verification
2. Requires admin permissions (enforcement to be added in #80)
3. All password changes are logged for audit purposes
4. Users should be notified when their password is reset

---

## Two-Factor Authentication

### Generate 2FA Secret Endpoint

#### Overview
Generates a new TOTP secret for the authenticated user and returns a QR code for scanning with authenticator apps.

#### Endpoint Details

**URL:** `POST /api/auth/2fa/generate`  
**Content-Type:** `application/json`  
**Authentication:** Required (Bearer token)

#### Request

No request body required.

#### Response

**Success Response (200 OK):**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "iVBORw0KGgoAAAANSUhEUgAA...",
  "qr_uri": "otpauth://totp/SMS%20Syncer:testuser?secret=JBSWY3DPEHPK3PXP&issuer=SMS%20Syncer"
}
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `secret` | string | Base32-encoded TOTP secret (for manual entry) |
| `qr_code` | string | Base64-encoded PNG image of QR code |
| `qr_uri` | string | OTPAuth URI for QR code generation |

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Not authenticated | `{"error": "Unauthorized"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to generate 2FA secret"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/auth/2fa/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

#### Usage Flow

1. Call this endpoint to generate a new TOTP secret
2. Display the QR code to the user or provide the secret for manual entry
3. User scans QR code with authenticator app (Google Authenticator, Authy, etc.)
4. User verifies setup by calling the Enable 2FA endpoint with a TOTP code

---

### Enable 2FA Endpoint

#### Overview
Enables two-factor authentication for the authenticated user after validating a TOTP code from their authenticator app.

#### Endpoint Details

**URL:** `POST /api/auth/2fa/enable`  
**Content-Type:** `application/json`  
**Authentication:** Required (Bearer token)

#### Request Schema

```json
{
  "totp_code": "123456"
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `totp_code` | string | **Yes** | 6-digit TOTP code from authenticator app |

#### Response

**Success Response (200 OK):**
```json
{
  "message": "2FA enabled successfully"
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Missing TOTP code or invalid code | `{"error": "TOTP code is required"}` or `{"error": "Invalid TOTP code"}` |
| 401 Unauthorized | Not authenticated | `{"error": "Unauthorized"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to enable 2FA"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/auth/2fa/enable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "totp_code": "123456"
  }'
```

#### Usage Notes

1. User must first generate a 2FA secret using the Generate 2FA endpoint
2. TOTP code expires every 30 seconds
3. After enabling, all future logins will require TOTP code
4. Backup codes should be stored securely (future feature)

---

### Disable 2FA Endpoint

#### Overview
Disables two-factor authentication for the authenticated user. This removes the TOTP requirement from future logins.

#### Endpoint Details

**URL:** `POST /api/auth/2fa/disable`  
**Content-Type:** `application/json`  
**Authentication:** Required (Bearer token)

#### Request

No request body required.

#### Response

**Success Response (200 OK):**
```json
{
  "message": "2FA disabled successfully"
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Not authenticated | `{"error": "Unauthorized"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to disable 2FA"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/auth/2fa/disable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

#### Security Notes

1. User must be authenticated to disable 2FA
2. Consider requiring password confirmation before disabling (future enhancement)
3. 2FA removal is logged for security audit
4. User should be notified when 2FA is disabled

---

## SMS Operations

### Add SMS Message Endpoint

### Overview
This endpoint allows you to add a new SMS message to the database. It requires authentication and validates all required fields before storing the message.

### Endpoint Details

**URL:** `POST /api/sms/add`
**Content-Type:** `application/json`
**Authentication:** Required (Bearer token in Authorization header)

### Authentication

The API requires a valid JWT token in the Authorization header:

```http
Authorization: Bearer <your-jwt-token>
```

To get a token, use the login endpoint documented above.

### Request Schema

#### JSON Payload Structure

```json
{
  "smsId": 12345,                    // Optional: Original SMS ID from Android
  "smsTimestamp": 1692864000,        // Required: Unix timestamp when SMS was sent/received
  "eventTimestamp": 1692864010,      // Optional: Unix timestamp when event occurred (auto-populated if not provided)
  "phoneNumber": "+1234567890",      // Required: Phone number (sender/recipient)
  "body": "Hello, this is a test",   // Required: SMS message content
  "eventType": "RECEIVED",           // Required: "SENT", "RECEIVED", "DRAFT", "FAILED", "QUEUED"
  "threadId": 67890,                 // Optional: SMS thread/conversation ID
  "dateSent": 1692863990,           // Optional: Unix timestamp when SMS was actually sent
  "person": "John Doe"              // Optional: Contact name associated with phone number
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `smsId` | integer | No | Original SMS ID from Android system |
| `smsTimestamp` | integer | **Yes** | Unix timestamp (seconds) when SMS was sent/received |
| `eventTimestamp` | integer | No | Unix timestamp when sync event occurred (auto-set if omitted) |
| `phoneNumber` | string | **Yes** | Phone number in any format (e.g., "+1234567890", "123-456-7890") |
| `body` | string | **Yes** | SMS message content (cannot be empty) |
| `eventType` | string | **Yes** | Type of SMS event. Valid values: "SENT", "RECEIVED", "DRAFT", "FAILED", "QUEUED" |
| `threadId` | integer | No | SMS conversation/thread identifier |
| `dateSent` | integer | No | Unix timestamp when message was actually sent (may differ from smsTimestamp) |
| `person` | string | No | Contact name or identifier |

**Note:** `userID` is automatically extracted from the JWT token and doesn't need to be included in the request.

### Request Examples

#### Minimal Required Request
```json
{
  "smsTimestamp": 1692864000,
  "phoneNumber": "+1234567890",
  "body": "Hello world!",
  "eventType": "RECEIVED"
}
```

#### Complete Request with All Fields
```json
{
  "smsId": 12345,
  "smsTimestamp": 1692864000,
  "eventTimestamp": 1692864010,
  "phoneNumber": "+1234567890",
  "body": "Hello, this is a test message from Android SMS sync",
  "eventType": "RECEIVED",
  "threadId": 67890,
  "dateSent": 1692863990,
  "person": "John Doe"
}
```

#### Sent Message Example
```json
{
  "smsTimestamp": 1692864000,
  "phoneNumber": "+0987654321",
  "body": "Thanks for your message!",
  "eventType": "SENT",
  "threadId": 67890
}
```

### Response Codes

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| **204 No Content** | SMS successfully added | *(empty)* |
| **400 Bad Request** | Invalid request data | `{"error": "description"}` |
| **401 Unauthorized** | Missing/invalid authentication | `{"error": "Unauthorized"}` |
| **415 Unsupported Media Type** | Wrong content type | `{"error": "Content-Type must be application/json"}` |
| **500 Internal Server Error** | Database or server error | `{"error": "Internal server error"}` |

### Error Response Examples

#### Missing Required Field
```json
{
  "error": "message body is required"
}
```

#### Invalid Phone Number
```json
{
  "error": "phone number is required"
}
```

#### Invalid Event Type
```json
{
  "error": "event type is required"
}
```

#### Missing Timestamp
```json
{
  "error": "SMS timestamp is required"
}
```

### Complete cURL Example

```bash
# Get authentication token first
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  | jq -r '.token')

# Add SMS message
curl -X POST http://localhost:8080/api/sms/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "smsTimestamp": 1692864000,
    "phoneNumber": "+1234567890", 
    "body": "Hello from SMS sync!",
    "eventType": "RECEIVED",
    "threadId": 12345
  }'
```

### Validation Rules

1. **Phone Number**: Must be non-empty string
2. **Message Body**: Must be non-empty string  
3. **Event Type**: Must be one of: "SENT", "RECEIVED", "DRAFT", "FAILED", "QUEUED"
4. **SMS Timestamp**: Must be positive Unix timestamp (seconds since epoch)
5. **Event Timestamp**: Auto-populated with current time if not provided
6. **Optional Fields**: Can be null/omitted (smsId, threadId, dateSent, person)

### Database Schema

The SMS message is stored with this structure:

```sql
CREATE TABLE sms_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    smsId INTEGER,
    userId TEXT NOT NULL,
    smsTimestamp INTEGER NOT NULL,
    eventTimestamp INTEGER NOT NULL,
    phoneNumber TEXT NOT NULL,
    body TEXT NOT NULL,
    eventType TEXT NOT NULL,
    threadId INTEGER,
    dateSent INTEGER,
    person TEXT
);
```

### Rate Limiting

Currently no rate limiting is implemented, but consider implementing it for production use.

### Security Notes

1. All requests must include valid JWT authentication
2. User ID is automatically extracted from token - cannot be spoofed
3. All input is validated and sanitized
4. SQL injection protection via parameterized queries

### Testing

Test the endpoint with different scenarios:

```bash
# Test missing required field
curl -X POST http://localhost:8080/api/sms/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"phoneNumber": "+1234567890"}'
  
# Expected: 400 Bad Request with validation error

# Test successful addition
curl -X POST http://localhost:8080/api/sms/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "smsTimestamp": 1692864000,
    "phoneNumber": "+1234567890",
    "body": "Test message",
    "eventType": "RECEIVED"
  }'
  
# Expected: 204 No Content (success)
```
