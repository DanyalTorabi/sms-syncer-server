# SMS Sync Server API Documentation

## Table of Contents
1. [Authentication](#authentication)
   - [Login](#login-endpoint)
   - [User Registration](#user-registration-endpoint)
2. [SMS Operations](#sms-operations)
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
