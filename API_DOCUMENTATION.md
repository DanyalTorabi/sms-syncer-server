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
5. [User Management](#user-management)
   - [List Users](#list-users-endpoint)
   - [Get User By ID](#get-user-by-id-endpoint)
   - [Update User By ID](#update-user-by-id-endpoint)
   - [Delete User By ID](#delete-user-by-id-endpoint)
   - [Assign User To Group](#assign-user-to-group-endpoint)
   - [Remove User From Group](#remove-user-from-group-endpoint)
   - [List User Groups](#list-user-groups-endpoint)
6. [Group Management](#group-management)
   - [Create Group](#create-group-endpoint)
   - [List Groups](#list-groups-endpoint)
   - [Get Group By ID](#get-group-by-id-endpoint)
   - [Update Group](#update-group-endpoint)
   - [Delete Group](#delete-group-endpoint)
   - [Add Permission To Group](#add-permission-to-group-endpoint)
   - [Remove Permission From Group](#remove-permission-from-group-endpoint)
7. [Permission Management](#permission-management)
   - [Create Permission](#create-permission-endpoint)
   - [List Permissions](#list-permissions-endpoint)
   - [Get Permission By ID](#get-permission-by-id-endpoint)
   - [Update Permission](#update-permission-endpoint)
   - [Delete Permission](#delete-permission-endpoint)

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
---

## User Management

### List Users Endpoint

#### Overview
Retrieves a paginated list of all users in the system. Supports filtering by active status and pagination.

#### Endpoint Details

**URL:** `GET /api/users`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `users:read`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 50 | Number of users per page (max: 100) |
| `offset` | integer | No | 0 | Number of users to skip |
| `active` | boolean | No | (all) | Filter by active status (`true` or `false`) |

#### Response

**Success Response (200 OK):**
```json
{
  "users": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "john.doe",
      "email": "john@example.com",
      "active": true,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 45,
  "limit": 50,
  "offset": 0
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to list users"}` |

#### Example Request

```bash
curl -X GET "http://localhost:8080/api/users?limit=20&offset=0&active=true" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Get User By ID Endpoint

#### Overview
Retrieves detailed information about a specific user, including their groups and permissions. Users can access their own information without special permissions, or access any user with `users:read` permission.

#### Endpoint Details

**URL:** `GET /api/users/:id`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `users:read` (or accessing own user ID)

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | User ID |

#### Response

**Success Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john.doe",
  "email": "john@example.com",
  "active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "groups": [
    {
      "id": "group-uuid-1",
      "name": "Developers",
      "description": "Development team",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "permissions": [
    {
      "id": "perm-uuid-1",
      "name": "users:read",
      "description": "Read user data",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | User not found | `{"error": "User not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to retrieve user"}` |

#### Example Request

```bash
curl -X GET http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Update User By ID Endpoint

#### Overview
Updates a user's information. Users can update their own email address without special permissions. Admin users with `users:write` permission can update any user's email and active status, but cannot deactivate the admin user.

#### Endpoint Details

**URL:** `PUT /api/users/:id`  
**Content-Type:** `application/json`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `users:write` (or updating own email only)

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | User ID to update |

#### Request Schema

```json
{
  "email": "newemail@example.com",
  "active": false
}
```

#### Field Descriptions

| Field | Type | Required | Self-Update | Admin Update | Description |
|-------|------|----------|-------------|--------------|-------------|
| `email` | string | No | ✅ | ✅ | User's email address (valid email format) |
| `active` | boolean | No | ❌ | ✅ | Active status (true/false) |

**Note:** Users updating their own record can only modify `email`. Only admins with `users:write` permission can modify `active` status.

#### Response

**Success Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john.doe",
  "email": "newemail@example.com",
  "active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-20T14:25:00Z",
  "groups": [...],
  "permissions": [...]
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Invalid request data | `{"error": "Invalid request"}` |
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions or admin protection | `{"error": "Insufficient permissions"}` / `{"error": "Cannot deactivate admin user"}` |
| 404 Not Found | User not found | `{"error": "User not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to update user"}` |

#### Example Requests

```bash
# Self-update email (no special permission needed)
curl -X PUT http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newemail@example.com"
  }'

# Admin update user status (requires users:write)
curl -X PUT http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newemail@example.com",
    "active": false
  }'
```

---

### Delete User By ID Endpoint

#### Overview
Soft-deletes a user by setting their active status to false. This is a non-destructive operation that preserves user data for audit purposes. The admin user cannot be deleted.

#### Endpoint Details

**URL:** `DELETE /api/users/:id`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `users:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | User ID to delete |

#### Response

**Success Response (204 No Content):**
No response body.

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions or admin protection | `{"error": "Insufficient permissions"}` / `{"error": "Cannot delete admin user"}` |
| 404 Not Found | User not found | `{"error": "User not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to delete user"}` |

#### Example Request

```bash
curl -X DELETE http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Assign User To Group Endpoint

#### Overview
Assigns a user to a group, granting them all permissions associated with that group. Users can belong to multiple groups, and their effective permissions are the union of all group permissions.

#### Endpoint Details

**URL:** `POST /api/users/:id/groups`  
**Content-Type:** `application/json`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `users:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | User ID |

#### Request Schema

```json
{
  "group_id": "group-uuid-123"
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `group_id` | UUID | **Yes** | Group ID to assign user to |

#### Response

**Success Response (204 No Content):**
No response body.

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Invalid request data | `{"error": "Invalid request"}` |
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | User or group not found | `{"error": "User not found"}` / `{"error": "Group not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to assign user to group"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": "group-uuid-123"
  }'
```

---

### Remove User From Group Endpoint

#### Overview
Removes a user from a group, revoking the permissions associated with that group. The admin user cannot be removed from their groups.

#### Endpoint Details

**URL:** `DELETE /api/users/:id/groups/:groupId`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `users:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | User ID |
| `groupId` | UUID | **Yes** | Group ID to remove user from |

#### Response

**Success Response (204 No Content):**
No response body.

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions or admin protection | `{"error": "Insufficient permissions"}` / `{"error": "Cannot remove admin user from groups"}` |
| 404 Not Found | User or group not found | `{"error": "User not found"}` / `{"error": "Group not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to remove user from group"}` |

#### Example Request

```bash
curl -X DELETE http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000/groups/group-uuid-123 \
  -H "Authorization: Bearer $TOKEN"
```

---

### List User Groups Endpoint

#### Overview
Retrieves a list of all groups a user belongs to. Users can access their own group memberships without special permissions, or access any user's groups with `users:read` permission.

#### Endpoint Details

**URL:** `GET /api/users/:id/groups`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `users:read` (or accessing own user ID)

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | User ID |

#### Response

**Success Response (200 OK):**
```json
{
  "groups": [
    {
      "id": "group-uuid-1",
      "name": "Developers",
      "description": "Development team",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    },
    {
      "id": "group-uuid-2",
      "name": "Admins",
      "description": "System administrators",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | User not found | `{"error": "User not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to retrieve user groups"}` |

#### Example Request

```bash
curl -X GET http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000/groups \
  -H "Authorization: Bearer $TOKEN"
```

---
---

## Group Management

### Create Group Endpoint

#### Overview
Creates a new group in the system. Groups are collections of permissions that can be assigned to users.

#### Endpoint Details

**URL:** `POST /api/groups`  
**Content-Type:** `application/json`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `groups:write`

#### Request Schema

```json
{
  "name": "Developers",
  "description": "Development team members"
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Group name (3-100 characters, must be unique) |
| `description` | string | No | Optional description of the group |

#### Response

**Success Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Developers",
  "description": "Development team members",
  "active": true,
  "created_at": 1692864000,
  "updated_at": 1692864000,
  "permissions": []
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Invalid input data | `{"error": "Invalid request format"}` |
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 409 Conflict | Group name already exists | `{"error": "group already exists"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Developers",
    "description": "Development team members"
  }'
```

---

### List Groups Endpoint

#### Overview
Retrieves a paginated list of all groups in the system.

#### Endpoint Details

**URL:** `GET /api/groups`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `groups:read`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 50 | Number of groups per page (max: 100) |
| `offset` | integer | No | 0 | Number of groups to skip |

#### Response

**Success Response (200 OK):**
```json
{
  "groups": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Developers",
      "description": "Development team",
      "active": true,
      "created_at": 1692864000,
      "updated_at": 1692864000
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "Admins",
      "description": "System administrators",
      "active": true,
      "created_at": 1692864000,
      "updated_at": 1692864000
    }
  ],
  "limit": 50,
  "offset": 0
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to list groups"}` |

#### Example Request

```bash
curl -X GET "http://localhost:8080/api/groups?limit=20&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Get Group By ID Endpoint

#### Overview
Retrieves detailed information about a specific group, including its associated permissions.

#### Endpoint Details

**URL:** `GET /api/groups/:id`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `groups:read`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | Group ID |

#### Response

**Success Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Developers",
  "description": "Development team",
  "active": true,
  "created_at": 1692864000,
  "updated_at": 1692864000,
  "permissions": [
    {
      "id": "perm-uuid-1",
      "name": "users:read",
      "resource": "users",
      "action": "read",
      "description": "Read user data",
      "active": true,
      "created_at": 1692864000
    }
  ]
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | Group not found | `{"error": "Group not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to retrieve group"}` |

#### Example Request

```bash
curl -X GET http://localhost:8080/api/groups/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Update Group Endpoint

#### Overview
Updates a group's information. Can modify name, description, and active status.

#### Endpoint Details

**URL:** `PUT /api/groups/:id`  
**Content-Type:** `application/json`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `groups:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | Group ID to update |

#### Request Schema

```json
{
  "name": "Senior Developers",
  "description": "Updated description",
  "active": true
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Group name (3-100 characters, must be unique) |
| `description` | string | No | Group description |
| `active` | boolean | No | Active status (true/false) |

**Note:** At least one field must be provided to update.

#### Response

**Success Response (200 OK):**
```json
{
  "message": "Group updated successfully"
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Invalid input or no fields to update | `{"error": "No valid fields to update"}` |
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | Group not found | `{"error": "Group not found"}` |
| 409 Conflict | Name already exists | `{"error": "group name already exists"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to update group"}` |

#### Example Request

```bash
curl -X PUT http://localhost:8080/api/groups/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Senior Developers",
    "description": "Updated description"
  }'
```

---

### Delete Group Endpoint

#### Overview
Deletes a group from the system. The admin group cannot be deleted for security reasons.

#### Endpoint Details

**URL:** `DELETE /api/groups/:id`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `groups:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | Group ID to delete |

#### Response

**Success Response (204 No Content):**
No response body.

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions or admin group | `{"error": "Insufficient permissions"}` / `{"error": "admin group cannot be deleted"}` |
| 404 Not Found | Group not found | `{"error": "Group not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to delete group"}` |

#### Example Request

```bash
curl -X DELETE http://localhost:8080/api/groups/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Add Permission To Group Endpoint

#### Overview
Assigns a permission to a group, granting all users in that group the specified permission. This enables flexible role-based access control by managing permissions at the group level.

#### Endpoint Details

**URL:** `POST /api/groups/:id/permissions`  
**Content-Type:** `application/json`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `groups:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | Group ID |

#### Request Schema

```json
{
  "permission_id": "perm-uuid-123"
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `permission_id` | UUID | **Yes** | Permission ID to assign to the group |

#### Response

**Success Response (200 OK):**
```json
{
  "message": "Permission added to group successfully"
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Invalid input data | `{"error": "Invalid request format"}` / `{"error": "Permission ID is required"}` |
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | Group or permission not found | `{"error": "Group not found"}` / `{"error": "Permission not found"}` |
| 409 Conflict | Permission already assigned | `{"error": "Permission already assigned to group"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to add permission to group"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/groups/550e8400-e29b-41d4-a716-446655440000/permissions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "permission_id": "perm-uuid-123"
  }'
```

---

### Remove Permission From Group Endpoint

#### Overview
Removes a permission from a group, revoking that permission from all users who have it through this group membership. Users may still retain the permission through other group memberships.

#### Endpoint Details

**URL:** `DELETE /api/groups/:id/permissions/:permissionId`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `groups:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | Group ID |
| `permissionId` | UUID | **Yes** | Permission ID to remove from the group |

#### Response

**Success Response (204 No Content):**
No response body.

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Missing IDs | `{"error": "Group ID is required"}` / `{"error": "Permission ID is required"}` |
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | Group, permission not found, or not assigned | `{"error": "Group not found"}` / `{"error": "Permission not found"}` / `{"error": "Permission not assigned to group"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to remove permission from group"}` |

#### Example Request

```bash
curl -X DELETE http://localhost:8080/api/groups/550e8400-e29b-41d4-a716-446655440000/permissions/perm-uuid-123 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Permission Management

### Create Permission Endpoint

#### Overview
Creates a new permission in the system. Permissions follow the `resource:action` naming convention (e.g., `users:read`, `groups:write`).

#### Endpoint Details

**URL:** `POST /api/permissions`  
**Content-Type:** `application/json`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `permissions:write`

#### Request Schema

```json
{
  "name": "users:read",
  "resource": "users",
  "action": "read",
  "description": "Permission to read user data"
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Permission name (must match `resource:action` format, 3-100 characters, unique) |
| `resource` | string | **Yes** | Resource type (e.g., "users", "groups", "sms") |
| `action` | string | **Yes** | Action type (e.g., "read", "write", "delete") |
| `description` | string | No | Optional description of what the permission allows |

**Note:** The `name` field must match the format `resource:action`. The service layer validates this requirement.

#### Response

**Success Response (201 Created):**
```json
{
  "id": "perm-uuid-1",
  "name": "users:read",
  "resource": "users",
  "action": "read",
  "description": "Permission to read user data",
  "active": true,
  "created_at": 1692864000
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | Invalid input or format | `{"error": "Invalid request format"}` / `{"error": "permission name must match format resource:action"}` |
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 409 Conflict | Permission already exists | `{"error": "permission already exists"}` |

#### Example Request

```bash
curl -X POST http://localhost:8080/api/permissions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "users:read",
    "resource": "users",
    "action": "read",
    "description": "Permission to read user data"
  }'
```

---

### List Permissions Endpoint

#### Overview
Retrieves a paginated list of all permissions in the system.

#### Endpoint Details

**URL:** `GET /api/permissions`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `permissions:read`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 50 | Number of permissions per page (max: 100) |
| `offset` | integer | No | 0 | Number of permissions to skip |

#### Response

**Success Response (200 OK):**
```json
{
  "permissions": [
    {
      "id": "perm-uuid-1",
      "name": "users:read",
      "resource": "users",
      "action": "read",
      "description": "Read user data",
      "active": true,
      "created_at": 1692864000
    },
    {
      "id": "perm-uuid-2",
      "name": "users:write",
      "resource": "users",
      "action": "write",
      "description": "Write user data",
      "active": true,
      "created_at": 1692864000
    }
  ],
  "limit": 50,
  "offset": 0
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to list permissions"}` |

#### Example Request

```bash
curl -X GET "http://localhost:8080/api/permissions?limit=20&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Get Permission By ID Endpoint

#### Overview
Retrieves detailed information about a specific permission.

#### Endpoint Details

**URL:** `GET /api/permissions/:id`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `permissions:read`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | Permission ID |

#### Response

**Success Response (200 OK):**
```json
{
  "id": "perm-uuid-1",
  "name": "users:read",
  "resource": "users",
  "action": "read",
  "description": "Permission to read user data",
  "active": true,
  "created_at": 1692864000
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | Permission not found | `{"error": "Permission not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to retrieve permission"}` |

#### Example Request

```bash
curl -X GET http://localhost:8080/api/permissions/perm-uuid-1 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Update Permission Endpoint

#### Overview
Updates a permission's information. Only description and active status can be modified. The name, resource, and action fields are immutable to maintain permission integrity.

#### Endpoint Details

**URL:** `PUT /api/permissions/:id`  
**Content-Type:** `application/json`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `permissions:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | Permission ID to update |

#### Request Schema

```json
{
  "description": "Updated description",
  "active": true
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | No | Updated description |
| `active` | boolean | No | Active status (true/false) |

**Note:** At least one field must be provided. Name, resource, and action cannot be changed after creation.

#### Response

**Success Response (200 OK):**
```json
{
  "message": "Permission updated successfully"
}
```

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 400 Bad Request | No fields to update | `{"error": "No valid fields to update"}` |
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | Permission not found | `{"error": "Permission not found"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to update permission"}` |

#### Example Request

```bash
curl -X PUT http://localhost:8080/api/permissions/perm-uuid-1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "active": true
  }'
```

---

### Delete Permission Endpoint

#### Overview
Deletes a permission from the system. Permissions that are currently assigned to groups cannot be deleted to maintain system integrity.

#### Endpoint Details

**URL:** `DELETE /api/permissions/:id`  
**Authentication:** Required (JWT Bearer token)  
**Required Permission:** `permissions:write`

#### URL Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | **Yes** | Permission ID to delete |

#### Response

**Success Response (204 No Content):**
No response body.

**Error Responses:**

| Status Code | Description | Response Body |
|-------------|-------------|---------------|
| 401 Unauthorized | Missing or invalid token | `{"error": "Unauthorized"}` |
| 403 Forbidden | Insufficient permissions | `{"error": "Insufficient permissions"}` |
| 404 Not Found | Permission not found | `{"error": "Permission not found"}` |
| 409 Conflict | Permission in use by groups | `{"error": "permission is in use by groups"}` |
| 500 Internal Server Error | Server error | `{"error": "Failed to delete permission"}` |

#### Example Request

```bash
curl -X DELETE http://localhost:8080/api/permissions/perm-uuid-1 \
  -H "Authorization: Bearer $TOKEN"
```

---
