# SMS Sync Server API Documentation

## Add SMS Message Endpoint

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

To get a token, use the login endpoint:
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "testuser",
  "password": "testpass"
}
```

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
