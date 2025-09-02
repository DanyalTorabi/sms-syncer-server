# Deployment Guide

This guide covers deployment strategies and configurations for the SMS Sync Server.

## Table of Contents

- [Deployment Overview](#deployment-overview)
- [Environment Configuration](#environment-configuration)
- [Docker Deployment](#docker-deployment)
- [Production Setup](#production-setup)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Recovery](#backup-and-recovery)
- [Scaling Considerations](#scaling-considerations)

## Deployment Overview

### Deployment Environments

1. **Development**: Local development environment
2. **Staging**: Pre-production testing environment
3. **Production**: Live production environment

### Deployment Methods

- **Direct Binary**: Compile and run binary directly
- **Docker**: Containerized deployment
- **Kubernetes**: Orchestrated container deployment
- **Cloud Services**: AWS, GCP, Azure deployments

## Environment Configuration

### Environment Variables

Create environment-specific configuration files:

#### Production Environment
```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
GO_ENV=production

# Database
DATABASE_DSN=/data/sms.db

# JWT Configuration
JWT_SECRET=${JWT_SECRET}  # From secure secret management
JWT_TOKEN_EXPIRY=24h

# Logging
LOG_LEVEL=info
LOG_PATH=/var/log/sms-sync-server/server.log

# Security
CORS_ALLOWED_ORIGINS=https://your-domain.com
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60s

# Health Check
HEALTH_CHECK_ENDPOINT=/health
```

#### Staging Environment
```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
GO_ENV=staging

# Database
DATABASE_DSN=/data/staging-sms.db

# JWT Configuration
JWT_SECRET=${STAGING_JWT_SECRET}
JWT_TOKEN_EXPIRY=2h

# Logging
LOG_LEVEL=debug
LOG_PATH=/var/log/sms-sync-server/staging.log

# Security
CORS_ALLOWED_ORIGINS=https://staging.your-domain.com
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=60s
```

## Docker Deployment

### Dockerfile

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git sqlite

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o sms-sync-server cmd/server/main.go

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite

# Create app user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Create directories
RUN mkdir -p /app /data /var/log/sms-sync-server && \
    chown -R appuser:appgroup /app /data /var/log/sms-sync-server

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/sms-sync-server .

# Copy configuration files
COPY --chown=appuser:appgroup configs/ ./configs/

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./sms-sync-server"]
```

### Docker Compose

#### Development
```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  sms-sync-server:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - GO_ENV=development
      - LOG_LEVEL=debug
      - DATABASE_DSN=/data/dev-sms.db
    volumes:
      - ./data:/data
      - ./logs:/var/log/sms-sync-server
    restart: unless-stopped

  # Optional: Add reverse proxy for SSL termination
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - sms-sync-server
    restart: unless-stopped
```

#### Production
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  sms-sync-server:
    image: sms-sync-server:latest
    ports:
      - "8080:8080"
    environment:
      - GO_ENV=production
      - LOG_LEVEL=info
      - DATABASE_DSN=/data/sms.db
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - sms_data:/data
      - sms_logs:/var/log/sms-sync-server
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.prod.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
      - sms_logs:/var/log/nginx
    depends_on:
      - sms-sync-server
    restart: unless-stopped

volumes:
  sms_data:
  sms_logs:
```

### Docker Commands

```bash
# Build image
docker build -t sms-sync-server:latest .

# Run container
docker run -d \
  --name sms-sync-server \
  -p 8080:8080 \
  -e GO_ENV=production \
  -v sms_data:/data \
  sms-sync-server:latest

# View logs
docker logs -f sms-sync-server

# Execute commands in container
docker exec -it sms-sync-server sh

# Stop and remove
docker stop sms-sync-server
docker rm sms-sync-server
```

## Production Setup

### System Requirements

#### Minimum Requirements
- CPU: 1 vCPU
- RAM: 512 MB
- Storage: 10 GB SSD
- Network: 100 Mbps

#### Recommended Requirements
- CPU: 2 vCPUs
- RAM: 2 GB
- Storage: 50 GB SSD
- Network: 1 Gbps

### Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y wget curl unzip sqlite3

# Create application user
sudo useradd -r -s /bin/false sms-sync-server

# Create directories
sudo mkdir -p /opt/sms-sync-server
sudo mkdir -p /var/log/sms-sync-server
sudo mkdir -p /etc/sms-sync-server

# Set permissions
sudo chown sms-sync-server:sms-sync-server /opt/sms-sync-server
sudo chown sms-sync-server:sms-sync-server /var/log/sms-sync-server
sudo chown sms-sync-server:sms-sync-server /etc/sms-sync-server
```

### Binary Deployment

```bash
# Download and install binary
wget https://github.com/your-org/sms-syncer-server/releases/latest/download/sms-sync-server
chmod +x sms-sync-server
sudo mv sms-sync-server /opt/sms-sync-server/

# Create configuration
sudo tee /etc/sms-sync-server/config.env > /dev/null << 'EOF'
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
GO_ENV=production
DATABASE_DSN=/opt/sms-sync-server/data/sms.db
LOG_LEVEL=info
LOG_PATH=/var/log/sms-sync-server/server.log
EOF

# Create systemd service
sudo tee /etc/systemd/system/sms-sync-server.service > /dev/null << 'EOF'
[Unit]
Description=SMS Sync Server
After=network.target

[Service]
Type=simple
User=sms-sync-server
Group=sms-sync-server
WorkingDirectory=/opt/sms-sync-server
ExecStart=/opt/sms-sync-server/sms-sync-server
EnvironmentFile=/etc/sms-sync-server/config.env
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/sms-sync-server/data /var/log/sms-sync-server

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable sms-sync-server
sudo systemctl start sms-sync-server

# Check status
sudo systemctl status sms-sync-server
```

### Nginx Reverse Proxy

```nginx
# /etc/nginx/sites-available/sms-sync-server
upstream sms_sync_server {
    server localhost:8080;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/your-domain.crt;
    ssl_certificate_key /etc/ssl/private/your-domain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    # Logging
    access_log /var/log/nginx/sms-sync-server.access.log;
    error_log /var/log/nginx/sms-sync-server.error.log;

    location / {
        proxy_pass http://sms_sync_server;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    location /health {
        proxy_pass http://sms_sync_server;
        access_log off;
    }
}
```

## Monitoring and Logging

### Application Monitoring

#### Health Check Endpoint
```bash
# Basic health check
curl -f http://localhost:8080/health

# Detailed health check with monitoring
curl -s http://localhost:8080/health | jq '.status'
```

#### Metrics Collection
Consider implementing Prometheus metrics:

```go
// Add to your application
import "github.com/prometheus/client_golang/prometheus/promhttp"

// Register metrics endpoint
router.GET("/metrics", gin.WrapH(promhttp.Handler()))
```

### Log Management

#### Log Rotation
```bash
# /etc/logrotate.d/sms-sync-server
/var/log/sms-sync-server/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    postrotate
        systemctl reload sms-sync-server
    endscript
}
```

#### Centralized Logging
For production environments, consider:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Fluentd
- Grafana Loki

### System Monitoring

#### Basic Monitoring Script
```bash
#!/bin/bash
# monitor.sh

# Check if service is running
if ! systemctl is-active --quiet sms-sync-server; then
    echo "SMS Sync Server is not running!"
    # Send alert (email, Slack, etc.)
fi

# Check disk space
DISK_USAGE=$(df /opt/sms-sync-server | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "Disk usage is above 80%: ${DISK_USAGE}%"
fi

# Check memory usage
MEMORY_USAGE=$(free | awk 'NR==2{printf "%.2f%%", $3*100/$2}')
echo "Memory usage: $MEMORY_USAGE"

# Check API health
if ! curl -f -s http://localhost:8080/health > /dev/null; then
    echo "Health check failed!"
fi
```

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup/sms-sync-server"
DB_PATH="/opt/sms-sync-server/data/sms.db"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
sqlite3 $DB_PATH ".backup $BACKUP_DIR/sms_backup_$DATE.db"

# Compress backup
gzip "$BACKUP_DIR/sms_backup_$DATE.db"

# Keep only last 7 days of backups
find $BACKUP_DIR -name "sms_backup_*.db.gz" -mtime +7 -delete

echo "Backup completed: sms_backup_$DATE.db.gz"
```

### Automated Backup

```bash
# Add to crontab (run daily at 2 AM)
crontab -e
0 2 * * * /opt/sms-sync-server/scripts/backup.sh
```

### Recovery Process

```bash
#!/bin/bash
# restore.sh

BACKUP_FILE=$1
DB_PATH="/opt/sms-sync-server/data/sms.db"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file.db.gz>"
    exit 1
fi

# Stop service
sudo systemctl stop sms-sync-server

# Backup current database
cp $DB_PATH "$DB_PATH.backup.$(date +%Y%m%d_%H%M%S)"

# Restore from backup
gunzip -c $BACKUP_FILE > $DB_PATH

# Fix permissions
chown sms-sync-server:sms-sync-server $DB_PATH

# Start service
sudo systemctl start sms-sync-server

echo "Database restored from $BACKUP_FILE"
```

## Scaling Considerations

### Horizontal Scaling

#### Load Balancer Configuration
```nginx
upstream sms_sync_servers {
    least_conn;
    server 10.0.1.10:8080 weight=1 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8080 weight=1 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8080 weight=1 max_fails=3 fail_timeout=30s;
}
```

#### Database Considerations
- SQLite limitations for concurrent writes
- Consider PostgreSQL or MySQL for high concurrency
- Implement read replicas for read-heavy workloads

### Vertical Scaling

#### Performance Tuning
```go
// Increase GOMAXPROCS for multi-core systems
runtime.GOMAXPROCS(runtime.NumCPU())

// Configure database connection pool
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(25)
db.SetConnMaxLifetime(5 * time.Minute)
```

### Auto-scaling

#### Docker Swarm Example
```yaml
version: '3.8'
services:
  sms-sync-server:
    image: sms-sync-server:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
```

Remember to test all deployment configurations in staging before applying to production!
