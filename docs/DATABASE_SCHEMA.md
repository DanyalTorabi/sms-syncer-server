# SMS Sync Server - Database Schema

## Overview

This document describes the complete database schema for the SMS Sync Server, including all tables, columns, relationships, indexes, and constraints.

**Database Type:** SQLite  
**ORM:** GORM with auto-migration support

## Table of Contents

1. [Tables](#tables)
2. [Entity Relationships](#entity-relationships)
3. [Indexes and Constraints](#indexes-and-constraints)
4. [Data Type Mapping](#data-type-mapping)
5. [Migration Strategy](#migration-strategy)

---

## Tables

### 1. Users Table

**Purpose:** Stores user authentication and profile information.

**Table Name:** `users`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | TEXT | PRIMARY KEY | UUID identifier for the user |
| `username` | TEXT | UNIQUE, NOT NULL | Unique username for login (3-50 characters) |
| `email` | TEXT | NOT NULL | User email address |
| `password_hash` | TEXT | NOT NULL | Bcrypt hashed password |
| `totp_secret` | TEXT | NULL | Encrypted TOTP secret for 2FA |
| `totp_enabled` | BOOLEAN | DEFAULT 0 | Flag indicating if 2FA is enabled |
| `active` | BOOLEAN | DEFAULT 1 | Account active status |
| `failed_login_attempts` | INTEGER | DEFAULT 0 | Counter for failed login attempts |
| `locked_until` | INTEGER | NULL | Unix timestamp until account is locked |
| `last_login` | INTEGER | NULL | Unix timestamp of last successful login |
| `created_at` | INTEGER | NOT NULL | Account creation timestamp (Unix) |
| `updated_at` | INTEGER | NOT NULL | Last account update timestamp (Unix) |

**Indexes:**
- `idx_users_username` - UNIQUE index on `username` for fast login lookups
- `idx_users_email` - Index on `email` for duplicate detection

**Constraints:**
- Primary key on `id`
- Unique constraint on `username`
- NOT NULL on required fields

**Sample Record:**
```sql
INSERT INTO users (id, username, email, password_hash, totp_enabled, active, created_at, updated_at)
VALUES (
  '550e8400-e29b-41d4-a716-446655440000',
  'admin',
  'admin@example.com',
  '$2a$10$...',  -- bcrypt hash
  0,
  1,
  1692864000,
  1692864000
);
```

---

### 2. Groups Table

**Purpose:** Stores user groups for Role-Based Access Control (RBAC).

**Table Name:** `groups`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | TEXT | PRIMARY KEY | UUID identifier for the group |
| `name` | TEXT | UNIQUE, NOT NULL | Group name (e.g., "Administrators", "Users") |
| `description` | TEXT | NULL | Optional group description |
| `active` | BOOLEAN | DEFAULT 1 | Group active status |
| `created_at` | INTEGER | NOT NULL | Creation timestamp (Unix) |
| `updated_at` | INTEGER | NOT NULL | Last update timestamp (Unix) |

**Indexes:**
- `idx_groups_name` - UNIQUE index on `name`

**Default Groups:**
- `Administrators` - Full system access
- `Users` - Basic SMS and user operations

**Sample Record:**
```sql
INSERT INTO groups (id, name, description, active, created_at, updated_at)
VALUES (
  'group-admin-uuid',
  'Administrators',
  'Full system access',
  1,
  1692864000,
  1692864000
);
```

---

### 3. Permissions Table

**Purpose:** Defines system permissions for RBAC using resource:action format.

**Table Name:** `permissions`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | TEXT | PRIMARY KEY | UUID identifier for the permission |
| `name` | TEXT | UNIQUE, NOT NULL | Permission name in `resource:action` format (3-100 characters) |
| `resource` | TEXT | NOT NULL | Resource type (e.g., "sms", "users", "groups") |
| `action` | TEXT | NOT NULL | Action type (e.g., "read", "write", "delete") |
| `description` | TEXT | NULL | Human-readable description of the permission |
| `active` | BOOLEAN | DEFAULT 1 | Permission active status |
| `created_at` | INTEGER | NOT NULL | Creation timestamp (Unix) |

**Indexes:**
- `idx_permissions_name` - UNIQUE index on `name`

**Default Permissions:**

| Name | Resource | Action | Description |
|------|----------|--------|-------------|
| `sms:read` | sms | read | Read SMS messages |
| `sms:write` | sms | write | Create and update SMS messages |
| `sms:delete` | sms | delete | Delete SMS messages |
| `users:read` | users | read | View user information |
| `users:write` | users | write | Create and update users |
| `users:delete` | users | delete | Delete users |
| `groups:read` | groups | read | View group information |
| `groups:write` | groups | write | Manage groups and assignments |
| `permissions:read` | permissions | read | View permissions |
| `permissions:write` | permissions | write | Create and update permissions |

**Sample Record:**
```sql
INSERT INTO permissions (id, name, resource, action, description, active, created_at)
VALUES (
  'perm-sms-read',
  'sms:read',
  'sms',
  'read',
  'Permission to read SMS messages',
  1,
  1692864000
);
```

---

### 4. User Groups Junction Table

**Purpose:** Many-to-many relationship between users and groups.

**Table Name:** `user_groups`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `user_id` | TEXT | PRIMARY KEY, FOREIGN KEY | Reference to `users(id)` with CASCADE delete |
| `group_id` | TEXT | PRIMARY KEY, FOREIGN KEY | Reference to `groups(id)` with CASCADE delete |
| `assigned_at` | INTEGER | NOT NULL | Assignment timestamp (Unix) |

**Indexes:**
- `idx_user_groups_user_id` - Index on `user_id` for fast lookups
- `idx_user_groups_group_id` - Index on `group_id` for fast lookups

**Composite Primary Key:** (`user_id`, `group_id`)

**Foreign Key Relationships:**
- `user_id` → `users(id)` with ON DELETE CASCADE
- `group_id` → `groups(id)` with ON DELETE CASCADE

**Sample Record:**
```sql
INSERT INTO user_groups (user_id, group_id, assigned_at)
VALUES (
  '550e8400-e29b-41d4-a716-446655440000',  -- user id
  'group-admin-uuid',                        -- group id
  1692864000                                 -- assignment time
);
```

---

### 5. Group Permissions Junction Table

**Purpose:** Many-to-many relationship between groups and permissions.

**Table Name:** `group_permissions`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `group_id` | TEXT | PRIMARY KEY, FOREIGN KEY | Reference to `groups(id)` with CASCADE delete |
| `permission_id` | TEXT | PRIMARY KEY, FOREIGN KEY | Reference to `permissions(id)` with CASCADE delete |
| `assigned_at` | INTEGER | NOT NULL | Assignment timestamp (Unix) |

**Indexes:**
- `idx_group_permissions_group_id` - Index on `group_id`
- `idx_group_permissions_permission_id` - Index on `permission_id`

**Composite Primary Key:** (`group_id`, `permission_id`)

**Foreign Key Relationships:**
- `group_id` → `groups(id)` with ON DELETE CASCADE
- `permission_id` → `permissions(id)` with ON DELETE CASCADE

**Sample Record:**
```sql
INSERT INTO group_permissions (group_id, permission_id, assigned_at)
VALUES (
  'group-admin-uuid',  -- group id
  'perm-sms-read',     -- permission id
  1692864000           -- assignment time
);
```

---

### 6. Messages Table

**Purpose:** Stores SMS messages synced from Android devices.

**Table Name:** `messages`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Auto-incremented message ID |
| `smsId` | INTEGER | NULL | Android system SMS ID |
| `user_id` | TEXT | NOT NULL | Owner's user ID |
| `smsTimestamp` | INTEGER | NOT NULL | Timestamp when SMS was sent/received (Unix) |
| `eventTimestamp` | INTEGER | NOT NULL | Timestamp when event was recorded (Unix) |
| `phoneNumber` | TEXT | NOT NULL | Sender or recipient phone number (E.164 format) |
| `body` | TEXT | NOT NULL | Message content (max 2048 characters) |
| `eventType` | TEXT | NOT NULL | Event type: RECEIVED or SENT |
| `threadId` | INTEGER | NULL | Android message thread ID |
| `dateSent` | INTEGER | NULL | Android date_sent field (Unix timestamp) |
| `person` | TEXT | NULL | Contact name or person identifier |

**Indexes:**
- Index on `user_id` for fast per-user queries
- Index on `smsTimestamp` for time-range queries

**Constraints:**
- Primary key on `id`
- NOT NULL on required fields

**Sample Record:**
```sql
INSERT INTO messages (user_id, smsTimestamp, eventTimestamp, phoneNumber, body, eventType)
VALUES (
  '550e8400-e29b-41d4-a716-446655440000',
  1692864000,     -- when SMS was sent
  1692864120,     -- when we synced it
  '+1234567890',  -- phone number
  'Hello, World!',
  'RECEIVED'
);
```

---

## Entity Relationships

### ER Diagram (ASCII)

```
┌─────────────┐
│   Users     │
├─────────────┤
│ id (PK)     │
│ username    │────────┐
│ email       │        │
│ password    │        │
│ totp_secret │        │
│ ...         │        │
└─────────────┘        │
       │               │ FK
       │               ▼
       │         ┌────────────────┐
       │         │  User_Groups   │
       │         ├────────────────┤
       │         │ user_id (PK/FK)├─────────┐
       │         │ group_id (PK)  │         │
       │         │ assigned_at    │         │ FK
       │         └────────────────┘         │
       │                                    ▼
       │                          ┌──────────────────┐
       │                          │   Groups         │
       │                          ├──────────────────┤
       │                          │ id (PK)          │
       │                          │ name (UNIQUE)    │
       │                          │ description      │
       │                          │ active           │
       │                          │ created_at       │
       │                          │ updated_at       │
       │                          └──────────────────┘
       │                                    │
       │                                    │ FK
       │                                    ▼
       │                          ┌──────────────────────┐
       │                          │Group_Permissions    │
       │                          ├──────────────────────┤
       │                          │group_id (PK/FK)     │
       │                          │permission_id (PK/FK)│
       │                          │assigned_at          │
       │                          └──────────────────────┘
       │                                    │
       │                                    │ FK
       │                                    ▼
       │                          ┌──────────────────┐
       │                          │ Permissions      │
       │                          ├──────────────────┤
       │                          │ id (PK)          │
       │                          │ name (UNIQUE)    │
       │                          │ resource         │
       │                          │ action           │
       │                          │ description      │
       │                          │ active           │
       │                          │ created_at       │
       │                          └──────────────────┘
       │
       │ user_id
       ▼
┌─────────────────┐
│   Messages      │
├─────────────────┤
│ id (PK)         │
│ user_id (FK)    │
│ phoneNumber     │
│ body            │
│ smsTimestamp    │
│ eventType       │
│ ...             │
└─────────────────┘
```

### Relationships Summary

1. **User → Groups** (Many-to-Many)
   - Users can belong to multiple groups
   - Groups can contain multiple users
   - Junction table: `user_groups`
   - Cascade delete: When a user is deleted, all their group memberships are removed

2. **Groups → Permissions** (Many-to-Many)
   - Groups can have multiple permissions
   - Permissions can be assigned to multiple groups
   - Junction table: `group_permissions`
   - Cascade delete: When a group is deleted, all its permission assignments are removed

3. **Users → Messages** (One-to-Many)
   - A user can have many SMS messages
   - Each message belongs to exactly one user
   - Foreign key: `messages.user_id` → `users.id`

### Permission Inheritance

Users inherit permissions from all their assigned groups:
- User A is in Group 1 and Group 2
- Group 1 has permissions: sms:read, sms:write
- Group 2 has permissions: users:read
- User A's effective permissions: sms:read, sms:write, users:read

---

## Indexes and Constraints

### Indexes

| Table | Column(s) | Type | Purpose |
|-------|-----------|------|---------|
| users | username | UNIQUE | Fast login lookups, ensure uniqueness |
| users | email | INDEX | Duplicate detection |
| groups | name | UNIQUE | Prevent duplicate group names |
| permissions | name | UNIQUE | Prevent duplicate permission names |
| user_groups | user_id | INDEX | Fast group lookup by user |
| user_groups | group_id | INDEX | Fast user lookup by group |
| group_permissions | group_id | INDEX | Fast permission lookup by group |
| group_permissions | permission_id | INDEX | Fast group lookup by permission |
| messages | user_id | INDEX | Fast message lookup by user |
| messages | smsTimestamp | INDEX | Time-range queries |

### Constraints

**Primary Key Constraints:**
- All main tables have single-column UUID primary keys
- Junction tables have composite primary keys to prevent duplicates

**Foreign Key Constraints:**
- All foreign keys have CASCADE delete enabled
- Foreign keys maintain referential integrity

**Unique Constraints:**
- Username in users table
- Group name in groups table
- Permission name in permissions table

**NOT NULL Constraints:**
- Applied to all required fields
- See individual table descriptions for details

**Check Constraints:**
- Boolean fields default to 0 (false) or 1 (true)

---

## Data Type Mapping

### Go ↔ SQLite Type Mapping

| Go Type | SQLite Type | Notes |
|---------|-------------|-------|
| string | TEXT | Used for IDs, usernames, phone numbers, text content |
| int | INTEGER | Used for counters and auto-increment IDs |
| int64 | INTEGER | Used for Unix timestamps (seconds since epoch) |
| bool | INTEGER | Stored as 0 (false) or 1 (true) |
| []byte | BLOB | Not currently used |
| time.Time | INTEGER | Converted to Unix timestamp before storage |

### ID Generation

- **User IDs**: UUID v4 generated by Go using `github.com/google/uuid`
- **Group IDs**: UUID v4
- **Permission IDs**: UUID v4
- **Message IDs**: Auto-incremented INTEGER (SQLite AUTOINCREMENT)

### Timestamps

All timestamps are stored as **Unix timestamps (seconds since epoch)**:
- Easier for calculations
- Language-agnostic
- Compact storage
- Consistent across the codebase

### Encryption

- **Password**: Bcrypt hashing with salt (stored in `password_hash`)
- **TOTP Secret**: Encrypted with AES-256-GCM using `TOTP_ENCRYPTION_KEY` environment variable

---

## Migration Strategy

### Auto-Migration with GORM

The application uses GORM's auto-migration feature to create and update tables:

```go
// Tables are auto-migrated in the correct order
db.AutoMigrate(
    &models.User{},
    &models.Group{},
    &models.Permission{},
    &models.UserGroup{},
    &models.GroupPermission{},
    &models.SMSMessage{},
)
```

**Migration Order:**
1. Users
2. Groups
3. Permissions
4. UserGroups (depends on Users and Groups)
5. GroupPermissions (depends on Groups and Permissions)
6. Messages (depends on Users)

### Initial Data Seeding

Upon first run, the database is seeded with:

**Users:**
- Admin user (credentials from environment variables)

**Groups:**
- Administrators
- Users

**Permissions:**
- sms:read, sms:write, sms:delete
- users:read, users:write, users:delete
- groups:read, groups:write
- permissions:read, permissions:write

**Assignments:**
- Admin user → Administrators group
- Administrators group → All permissions

---

## Backup and Recovery

### Backup

SQLite database file: `sms.db` (configured via `DATABASE_DSN`)

**Backup strategy:**
```bash
# Simple file copy
cp sms.db sms.db.backup

# Or use SQLite backup command
sqlite3 sms.db ".backup sms.db.backup"
```

### Recovery

```bash
# Restore from backup
sqlite3 sms.db ".restore sms.db.backup"

# Or copy file back
cp sms.db.backup sms.db
```

### Maintenance

**Vacuum** (reclaim disk space):
```bash
sqlite3 sms.db "VACUUM;"
```

**Analyze** (update statistics for query optimizer):
```bash
sqlite3 sms.db "ANALYZE;"
```

---

## Performance Considerations

1. **Indexes are created on**:
   - All foreign key columns for join performance
   - Unique fields (username, group name, permission name)
   - Frequently queried columns (user_id in messages)
   - Time-based fields (smsTimestamp in messages)

2. **Connection pooling**:
   - Max open connections: 25
   - Max idle connections: 5
   - Connection max lifetime: 5 minutes

3. **Query optimization**:
   - Always select specific columns when possible
   - Use pagination for large result sets
   - Leverage indexes for WHERE and JOIN clauses

---

## Related Documentation

- [API Documentation](../API_DOCUMENTATION.md) - API endpoints and request/response examples
- [Deployment Guide](DEPLOYMENT.md) - Database setup for production
- [Development Guide](DEVELOPMENT.md) - Database setup for development

