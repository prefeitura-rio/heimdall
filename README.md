# Heimdall Admin Service

A comprehensive admin service for group and role management with Cerbos authorization integration. Built with FastAPI, PostgreSQL, Redis, and OpenTelemetry tracing.

## 🚀 Quick Start

### Prerequisites

- [Nix](https://nixos.org/download.html) with flakes enabled
- [direnv](https://direnv.net/)
- Docker and Docker Compose

### Development Setup

1. **Clone and enter the project**:
   ```bash
   git clone <repository-url>
   cd heimdall
   direnv allow  # This will automatically set up the development environment
   ```

2. **Start services**:
   ```bash
   docker-compose up -d  # Start PostgreSQL, Redis, OpenTelemetry stack
   ```

3. **Initialize database**:
   ```bash
   alembic upgrade head
   ```

4. **Start the API service**:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

5. **Start background tasks** (in another terminal):
   ```bash
   python app/background_tasks.py
   ```

6. **Access the API**:
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/healthz
   - Readiness Check: http://localhost:8000/readyz

## 📋 Features

### Core Functionality
- **User Management**: Auto-creation from JWT tokens with Keycloak integration
- **Group Management**: Create, delete, and manage groups with hierarchical permissions
- **Role-Based Access Control**: Assign roles to users and groups with fine-grained permissions
- **Membership Management**: Add/remove users from groups with audit trails
- **Endpoint Mapping**: Dynamic API endpoint to action mapping with regex patterns
- **Permission Checking**: Real-time authorization via Cerbos integration

### Technical Features
- **Optional OpenTelemetry Tracing**: Full distributed tracing with Jaeger integration (enabled when configured)
- **Structured Logging**: JSON-formatted logs with optional trace correlation
- **Redis Caching**: High-performance caching for mappings, roles, and JWKS
- **Database Monitoring**: Real-time query performance monitoring and optimization
- **Health Monitoring**: Comprehensive health checks for all dependencies
- **Background Tasks**: Automated reconciliation and retry mechanisms
- **Security**: JWT verification, static API tokens, input validation

## 🏗️ Architecture

### Services
- **API Service**: FastAPI application handling HTTP requests
- **Background Tasks**: APScheduler-based background processing
- **Database**: PostgreSQL with comprehensive indexing
- **Cache**: Redis for high-performance caching
- **Authorization**: Cerbos for policy-based access control
- **Observability**: OpenTelemetry + Jaeger for tracing

### Components
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI App   │────│   PostgreSQL    │────│   Background    │
│                 │    │                 │    │     Tasks       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ├──────────────┬────────┴────────┬──────────────┤
         │              │                 │              │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Redis       │    │     Cerbos      │    │  OpenTelemetry  │
│    (Cache)      │    │ (Authorization) │    │   (Tracing)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔧 Configuration

### Environment Variables

All configuration is done via environment variables. Copy [`.env.example`](.env.example) to `.env` and configure for your environment.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| **Database** |
| `DB_DSN` | ✅ | - | PostgreSQL database connection string |
| **Authentication** |
| `KEYCLOAK_JWKS_URL` | ✅ | - | Keycloak JWKS endpoint URL for JWT verification |
| `KEYCLOAK_CLIENT_ID` | ✅ | - | Keycloak client ID for role extraction |
| `KEYCLOAK_ADMIN_ROLE` | ❌ | `heimdall-admin` | Keycloak client role name that grants superadmin privileges |
| `JWT_ALGORITHM` | ✅ | - | JWT signature algorithm (typically `RS256`) |
| `JWT_AUDIENCE` | ✅ | - | JWT audience claim (typically `account`) |
| `STATIC_API_TOKEN` | ✅ | - | Static API token for service-to-service communication |
| **Authorization** |
| `CERBOS_BASE_URL` | ✅ | - | Cerbos Base URL |
| `CERBOS_ADMIN_USER` | ✅ | - | Cerbos Admin API username |
| `CERBOS_ADMIN_PASSWORD` | ✅ | - | Cerbos Admin API password |
| **Caching** |
| `REDIS_URL` | ❌ | `redis://redis:6379/0` | Redis connection URL |
| `REDIS_MAPPING_TTL` | ❌ | `60` | Mapping cache TTL in seconds |
| `REDIS_USER_ROLES_TTL` | ❌ | `30` | User roles cache TTL in seconds |
| `REDIS_JWKS_TTL` | ❌ | `300` | JWKS cache TTL in seconds |
| **Background Tasks** |
| `RECONCILE_INTERVAL_SECONDS` | ❌ | `300` | Cerbos policy reconciliation interval |
| `SYNC_RETRY_INTERVAL_SECONDS` | ❌ | `60` | Failed sync retry interval |
| **Server** |
| `HOST` | ❌ | `0.0.0.0` | Server bind address |
| `PORT` | ❌ | `8080` | Server port |
| **Observability (Optional)** |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | ❌ | `""` | OpenTelemetry OTLP exporter endpoint (enables tracing when set) |
| `OTEL_SERVICE_NAME` | ❌ | `heimdall-admin-service` | OpenTelemetry service name |
| `OTEL_RESOURCE_ATTRIBUTES` | ❌ | `""` | OpenTelemetry resource attributes (key=value pairs) |

#### Quick Setup Example
```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your specific values

# For local development with default services:
DB_DSN=postgresql://heimdall:heimdall@localhost:5432/heimdall
CERBOS_BASE_URL=http://localhost:3593
CERBOS_ADMIN_USER=admin
CERBOS_ADMIN_PASSWORD=password
KEYCLOAK_JWKS_URL=https://your-keycloak.com/realms/your-realm/protocol/openid-connect/certs
KEYCLOAK_CLIENT_ID=heimdall-admin
JWT_ALGORITHM=RS256
JWT_AUDIENCE=account
STATIC_API_TOKEN=your-secure-static-token

# Optional: Enable tracing
# OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

**Note**: All environment variables have sensible defaults where possible. Only the variables marked as Required (✅) need to be set for the service to start.

### Docker Deployment

The service includes multi-stage Dockerfiles for production deployment:

```bash
# Build API service
docker build --target api -t heimdall-admin-api .

# Build background tasks service
docker build --target background -t heimdall-admin-background .

# Run with docker-compose
docker-compose -f docker-compose.production.yml up -d
```

## 📖 API Documentation

### Authentication

The service supports two authentication methods:

1. **JWT Authentication**: Extract user from Keycloak JWT tokens
2. **Static API Token**: Use `STATIC_API_TOKEN` for service-to-service communication

Include authentication in requests:
```bash
# JWT Authentication
curl -H "Authorization: Bearer <jwt-token>" http://localhost:8000/api/v1/users/user123

# Static Token Authentication  
curl -H "Authorization: Bearer <static-token>" http://localhost:8000/api/v1/mappings?path=/example&method=GET
```

### Core Endpoints

#### Users
- `GET /api/v1/users/{subject}` - Get user information with roles and groups

#### Groups
- `POST /api/v1/groups` - Create a new group
- `GET /api/v1/groups` - List groups (with optional prefix filtering)
- `DELETE /api/v1/groups/{groupName}` - Delete a group

#### Memberships
- `POST /api/v1/groups/{groupName}/members` - Add user to group
- `DELETE /api/v1/groups/{groupName}/members/{subject}` - Remove user from group

#### Roles
- `POST /api/v1/roles` - Create a new role
- `GET /api/v1/roles` - List all roles
- `POST /api/v1/groups/{groupName}/roles` - Assign role to group
- `DELETE /api/v1/groups/{groupName}/roles/{roleName}` - Remove role from group

#### Mappings
- `GET /api/v1/mappings` - Resolve path/method to action
- `POST /api/v1/mappings` - Create endpoint mapping
- `PUT /api/v1/mappings/{id}` - Update endpoint mapping
- `DELETE /api/v1/mappings/{id}` - Delete endpoint mapping
- `GET /api/v1/mappings/list` - List all mappings

#### Health & Monitoring
- `GET /api/v1/healthz` - Basic health check
- `GET /api/v1/readyz` - Readiness check with dependency validation
- `GET /api/v1/version` - Service version information
- `GET /api/v1/metrics` - System and cache metrics
- `GET /api/v1/config` - Configuration summary (safe)
- `GET /api/v1/database` - Database performance metrics

### Interactive Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🔒 Security

### Authentication & Authorization
- **JWT Validation**: Full JWT signature and claims validation against Keycloak
- **Auto-User Creation**: Users automatically created on first valid JWT access
- **Role-Based Access**: Fine-grained permissions via Cerbos policy engine
- **API Token Security**: Secure static tokens for service-to-service communication

### Data Protection
- **Input Validation**: Comprehensive Pydantic validation on all endpoints
- **SQL Injection Prevention**: Parameterized queries via SQLAlchemy
- **Sensitive Data Handling**: No secrets in logs, safe error messages
- **Audit Logging**: Complete audit trail for all administrative operations

### Security Best Practices
- Environment-based configuration (no hardcoded secrets)
- Proper CORS configuration
- Structured error handling without information leakage
- Database connection security with connection pooling

## 🔍 Monitoring & Observability

### OpenTelemetry Tracing (Optional)
- **Automatic Instrumentation**: FastAPI and SQLAlchemy auto-instrumented when enabled
- **Custom Spans**: Business logic operations traced
- **Trace Correlation**: Trace IDs included in all log entries when tracing is enabled
- **Jaeger Integration**: Visual trace analysis at http://localhost:16686
- **Easy Enable/Disable**: Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable, leave unset to disable

### Structured Logging
- **JSON Format**: Machine-readable logs with structured fields
- **Trace Correlation**: Every log entry includes trace_id and span_id when tracing is enabled
- **Operation Logging**: Detailed logging for all admin operations
- **Performance Logging**: Database query and cache operation metrics

### Health Monitoring
- **Dependency Checks**: Real-time health checks for PostgreSQL, Redis, Cerbos
- **Performance Metrics**: System resource utilization monitoring
- **Database Performance**: Query performance tracking and optimization suggestions
- **Cache Statistics**: Redis performance and hit rate monitoring

## 🔄 Background Tasks

The background service runs automated maintenance tasks:

### Reconciliation
- **Policy Sync**: Ensures Cerbos policies match database state
- **Configurable Interval**: Default every 5 minutes, configurable via environment
- **Error Handling**: Comprehensive error tracking and retry logic

### Retry Mechanisms
- **Failed Operations**: Automatic retry of failed Cerbos operations
- **Exponential Backoff**: Smart retry timing to avoid overwhelming services
- **Alert Generation**: Logging for permanently failed operations

## 🧪 Development

### Code Quality
- **Linting**: `ruff check app/` for code quality
- **Formatting**: `ruff format app/` for consistent style  
- **Type Hints**: Comprehensive type annotations throughout
- **Testing**: Run tests with `pytest` (test suite not included)

### Database Operations
```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations  
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

### Development Tools
```bash
# Run linting
ruff check app/

# Format code
ruff format app/

# Start development server with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 📁 Project Structure

```
heimdall/
├── app/                          # Main application package
│   ├── __init__.py
│   ├── main.py                   # FastAPI application entry point
│   ├── background_tasks.py       # Background task scheduler
│   ├── config.py                 # Environment configuration validation
│   ├── database.py               # Database connection and session management
│   ├── dependencies.py           # FastAPI dependency injection
│   ├── logging_config.py         # Structured logging configuration
│   ├── tracing.py                # OpenTelemetry tracing setup
│   ├── models/                   # SQLAlchemy database models
│   │   ├── __init__.py
│   │   ├── base.py               # Base model class
│   │   └── models.py             # All database table models
│   ├── routers/                  # FastAPI route handlers
│   │   ├── __init__.py
│   │   ├── groups.py             # Group management endpoints
│   │   ├── health.py             # Health and monitoring endpoints
│   │   ├── mappings.py           # Endpoint mapping management
│   │   ├── memberships.py        # Group membership management
│   │   ├── roles.py              # Role management endpoints
│   │   └── users.py              # User information endpoints
│   └── services/                 # Business logic services
│       ├── __init__.py
│       ├── audit.py              # Audit logging service
│       ├── auth.py               # Authentication and JWT handling
│       ├── base.py               # Base service with tracing
│       ├── cache.py              # Redis caching service
│       ├── cerbos.py             # Cerbos authorization client
│       ├── database_monitor.py   # Database performance monitoring
│       ├── group.py              # Group management business logic
│       ├── mapping.py            # Endpoint mapping business logic
│       ├── membership.py         # Membership management business logic
│       ├── role.py               # Role management business logic
│       └── user.py               # User management business logic
├── migrations/                   # Alembic database migrations
├── docker-compose.yml            # Development environment services
├── Dockerfile                    # Multi-stage container build
├── flake.nix                     # Nix development environment
├── pyproject.toml                # Python project configuration
├── alembic.ini                   # Alembic migration configuration
├── .envrc                        # direnv environment setup
├── .gitignore                    # Git ignore patterns
├── SPEC.md                       # Technical specification
├── TODO.md                       # Implementation progress tracking
└── README.md                     # This file
```

## 🚨 Troubleshooting

### Common Issues

**Database Connection Errors**
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check database URL format
echo $POSTGRES_URL

# Test connection manually
psql $POSTGRES_URL -c "SELECT 1;"
```

**Cerbos Connection Issues**
```bash
# Verify Cerbos is accessible
curl $CERBOS_BASE_URL/api/healthz

# Check admin credentials
curl -u $CERBOS_ADMIN_USER:$CERBOS_ADMIN_PASSWORD $CERBOS_BASE_URL/api/admin/policies
```

**JWT Authentication Problems**
```bash
# Verify JWKS endpoint is accessible
curl $KEYCLOAK_JWKS_URL

# Check JWT claims match configuration
# - iss (issuer) should match KEYCLOAK_ISSUER
# - aud (audience) should match KEYCLOAK_AUDIENCE
```

**Cache/Redis Issues**
```bash
# Check Redis connectivity
redis-cli -u $REDIS_URL ping

# Monitor Redis in real-time
redis-cli -u $REDIS_URL monitor
```

### Performance Optimization

**Database Performance**
- Monitor slow queries via `/api/v1/database` endpoint
- Review optimization suggestions provided by the monitoring service
- Use database indexes added for common query patterns

**Cache Performance**  
- Monitor cache hit rates via `/api/v1/metrics` endpoint
- Adjust TTL values via environment variables if needed
- Monitor Redis memory usage

**Tracing Analysis**
- Use Jaeger UI (http://localhost:16686) to analyze request flows
- Look for slow operations and bottlenecks in trace spans
- Correlate logs with traces using trace_id

### Log Analysis

**Finding Specific Operations**
```bash
# Search logs for specific user operations
grep "actor_subject.*user123" logs/

# Find failed operations
grep "success.*false" logs/

# Monitor real-time operations
tail -f logs/ | grep "operation.*group_create"
```

## 📄 License

[Add your license information here]

## 🤝 Contributing

[Add contribution guidelines here]

## 📞 Support

For issues and support:
- Check the troubleshooting section above
- Review logs for detailed error information
- Use health endpoints to verify system status
- Check the technical specification in [`SPEC.md`](SPEC.md)