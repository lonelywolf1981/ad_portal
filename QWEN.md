# AD Portal - Web Portal for Active Directory Infrastructure

## Project Overview

AD Portal is a web application designed for Active Directory infrastructure management, providing reference tasks and access control monitoring. It offers a convenient interface for working with Active Directory, allowing users to search for users, determine who is logged into hosts, and perform background network scanning to track user locations.

### Key Features

- **Authentication & Access Control**:
  - LOCAL: Local application users (SQLite)
  - AD: Active Directory authentication (LDAP/LDAPS)
  - Separate access groups for application access and settings access
  - Break-glass functionality for local admin access even when AD mode is enabled

- **Active Directory User Search**:
  - Search by part of name/surname/login
  - Display basic info (full name, login, email)
  - Detailed user information view with human-friendly group names

- **Host Login Detection**:
  - Determine who is logged into a host by hostname or IP
  - Multiple methods: WinRM, WMI/DCOM, SMB/RPC (tried sequentially)
  - Configurable timeouts for each method

- **Background Network Scanning**:
  - Periodic scanning of CIDR ranges to track user locations
  - Background scanning using Celery workers and scheduled tasks
  - Stores last known host for each user

### Technology Stack

- **Backend**: FastAPI, SQLAlchemy, SQLite
- **Frontend**: Jinja2 Templates, HTMX, Bootstrap
- **AD/LDAP**: ldap3
- **Remote logon detection**: pywinrm, requests-ntlm, impacket
- **Reverse Proxy**: Nginx
- **Runtime**: Docker Compose
- **Background Tasks**: Celery with Redis

## Building and Running

### Prerequisites

- Docker
- Docker Compose
- Git

### Quick Start (Docker Compose)

1. **Clone and Prepare**
   ```bash
   git clone https://github.com/lonelywolf1981/ad-portal.git
   cd ad-portal
   cp .env.example .env
   mkdir -p data
   # If container cannot write to SQLite:
   sudo chmod 777 data
   ```

2. **Configure DNS** (Important!)
   In `docker-compose.yml`, specify your AD DNS (usually domain controller):
   ```yaml
   dns:
     - 192.168.66.11  # Replace with your AD controller IP
   ```

3. **Start Services**
   ```bash
   docker compose up -d --build
   ```

4. **Access the Application**
   - Open browser to: `http://<IP_HOST>:8484/login`
   - Default port 8484 can be changed in `docker-compose.yml`

### Environment Variables

Key variables in `.env`:
- `APP_SECRET_KEY`: Required long random secret for cookie signing and password encryption
- `APP_COOKIE_SECURE`: Set to `true` if using HTTPS
- `SQLITE_PATH`: Path to SQLite database (default: `/app/data/app.db`)
- `BOOTSTRAP_ADMIN_USER`/`BOOTSTRAP_ADMIN_PASSWORD`: Initial admin credentials
- `REDIS_URL`: Redis connection string for Celery

## Architecture and Structure

### Main Components

- **Web Service**: FastAPI application serving the main interface
- **Redis**: Message broker for Celery tasks
- **Worker**: Celery worker processing background tasks
- **Beat**: Celery scheduler for periodic tasks (network scanning)
- **Nginx**: Reverse proxy and load balancer

### Project Structure

```
ad_portal/
├── app/                    # Main application code
│   ├── __init__.py
│   ├── ad_utils.py         # Active Directory utilities
│   ├── celery_app.py       # Celery configuration
│   ├── crypto.py           # Encryption/decryption functions
│   ├── db.py               # Database setup
│   ├── deps.py             # Dependencies
│   ├── env_settings.py     # Environment configuration
│   ├── main.py             # FastAPI application entry point
│   ├── models.py           # SQLAlchemy models
│   ├── repo.py             # Database operations
│   ├── schema.py           # Schema initialization
│   ├── security.py         # Security functions
│   ├── session.py          # Session management
│   ├── timezone_utils.py   # Timezone utilities
│   ├── utils/              # Utility functions
│   ├── viewmodels/         # View models
│   ├── ad/                 # Active Directory integration
│   ├── host_query/         # Host query functionality
│   ├── net_scan.py         # Network scanning
│   ├── routers/            # API route definitions
│   ├── services/           # Business logic services
│   ├── static/             # Static assets
│   ├── tasks.py            # Celery tasks
│   └── templates/          # Jinja2 templates
├── nginx/                  # Nginx configuration
├── docker-compose.yml      # Docker Compose configuration
├── Dockerfile              # Docker build configuration
├── README.md               # Project documentation
├── requirements.txt        # Python dependencies
└── data/                   # Persistent data storage
```

### Background Tasks

The application uses Celery for background processing:
- **Network Scanning**: Periodically scans CIDR ranges to detect user presence
- **Scheduled Tasks**: Managed by Celery Beat with configurable intervals
- **Task Processing**: Handled by Celery Workers with Redis as message broker

## Development Conventions

### Code Style

- Follows PEP 8 Python coding standards
- Uses type hints for better code documentation and IDE support
- Modular architecture with clear separation of concerns

### Security Practices

- Password encryption using Fernet (symmetric encryption)
- Secure session management with signed cookies
- Input validation and sanitization
- SQL injection prevention through SQLAlchemy ORM

### Configuration Management

- Environment variables for configuration
- Centralized settings in AppSettings model
- Encrypted storage for sensitive data (passwords)
- Bootstrap admin creation for initial setup

## First-Time Setup

1. **Initial Access**: After startup, use bootstrap admin credentials from `.env` to access `/settings`
2. **AD Configuration**: Configure Active Directory parameters:
   - Domain Controller (DC)
   - Domain name
   - Connection method (LDAPS or LDAP + StartTLS)
   - Bind user and password
3. **Group Selection**: Choose groups for application access and settings access
4. **Authentication Mode**: Switch to AD authentication mode

## Key Models

- `LoginAudit`: Tracks authentication attempts
- `LocalUser`: Stores local application users
- `AppSettings`: Application-wide configuration
- `UserPresence`: Tracks user location on hosts
- `HostUserMap`: Maps users to hosts with timestamps

## Background Scanning

The network scanning feature periodically scans CIDR ranges to detect user presence:
- Configured through the settings UI
- Uses the same credentials as host query functionality
- Stores results in `UserPresence` and `HostUserMap` tables
- Includes optimizations like port probing to skip non-Windows hosts