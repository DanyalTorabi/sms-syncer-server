# SMS Sync Server

The server component of the SMS Sync system, built with Go.

## Features

- REST API for receiving SMS messages
- Health check endpoint
- Configurable through environment variables
- Graceful shutdown handling

## Prerequisites

- Go 1.22 or later
- Git

## Setup

1. Clone the repository
2. Navigate to the Server directory
3. Install dependencies:
   ```bash
   go mod tidy
   ```

## Configuration

The server can be configured using environment variables:

- `SERVER_PORT`: Port to listen on (default: 8080)
- `LOG_LEVEL`: Logging level (default: info)

## Running the Server

```bash
go run cmd/server/main.go
```

## API Endpoints

### Health Check
```
GET /health
```
Returns server status and current time.

### Add SMS
```
POST /api/sms/add
Content-Type: application/json

{
  "uuid": "string",
  "sender": "string",
  "message": "string",
  "timestamp": "string",
  "retryCount": number
}
```

## Development

### Project Structure

```
Server/
├── cmd/
│   └── server/         # Main application entry point
├── internal/
│   ├── api/           # API handlers
│   ├── config/        # Configuration
│   ├── db/            # Database operations
│   ├── models/        # Data models
│   └── services/      # Business logic
└── pkg/
    ├── logger/        # Logging utilities
    └── utils/         # Shared utilities
```

## License

MIT License - See the root LICENSE file for details. 