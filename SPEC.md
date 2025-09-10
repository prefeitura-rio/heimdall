# Admin Service — Full Specification

A complete, developer-ready spec for a self-hosted Admin Service built with **FastAPI** and **PostgreSQL** that manages groups, memberships, mappings (endpoint→action), and automatically pushes principal policies to Cerbos. The service does not replace Keycloak/RH SSO for authentication — it relies on JWTs issued by Keycloak for operator identity. The service does enforce who is allowed to perform administrative operations by calling Cerbos Check API before making mutations.

## This spec contains:

- Responsibilities & high-level flow
- Data model (DDL + notes)
- FastAPI HTTP API (endpoints, request/response examples)
- Cerbos interactions (transparent to users)
- Background tasks (reconciliation, sync)
- Environment configuration
- OpenTelemetry tracing setup
- Code examples

## 1. Responsibilities & high-level flow

### Responsibilities

Provide a secured REST API consumed by your Admin UI and trusted automation for:

- Create / update / delete groups and roles (logical group entities)
- Manage group ↔ role relations (what roles a group grants)
- Manage memberships (add/remove users to/from groups)
- Manage endpoint → action mappings (for adapter mapping service)
- Manage group-management rights (which manager-groups can manage which target-groups)
- Audit all admin operations (who, what, when, request metadata)
- Push principal policies to Cerbos Admin API (optional; see modes)
- Provide a mapping lookup endpoint (adapter uses it, with caching on adapter)
- Enforce Authorization for admin actions by consulting Cerbos Check API (e.g., "can caller do group:add_member on group:go:authenticated?")
- Provide reconciliation endpoints / utilities (re-sync membership state to Cerbos principal policies)
- Provide health, metrics, and logs.

### Operation mode

The service operates in **DB-first + push-to-Cerbos** mode: DB is source-of-truth for membership/mappings; when a membership changes, the Admin Service automatically writes corresponding principal policies to Cerbos Admin API so Cerbos can evaluate roles without adapter querying DB every request.

## 2. Data model (PostgreSQL DDL)

Below are the core PostgreSQL tables. This mostly repeats the model we agreed upon, with additional audit & change-tracking tables.

```sql
-- actions
CREATE TABLE actions (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT
);

-- endpoints (mapping: many endpoint patterns -> one action)
CREATE TABLE endpoints (
  id SERIAL PRIMARY KEY,
  path_pattern TEXT NOT NULL,   -- e.g. '/courses', '/courses/*', '/courses/:id/enroll'
  method TEXT NOT NULL,         -- 'GET','POST',... or 'ANY'
  action_id INT NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
  description TEXT,
  created_by INT NULL REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(path_pattern, method)
);

-- roles
CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT
);

-- groups
CREATE TABLE groups (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,  -- e.g. 'go:admin'
  description TEXT,
  created_by INT NULL REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- group_roles (group -> role)
CREATE TABLE group_roles (
  group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, role_id)
);

-- users (Keycloak subject storage)
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  subject TEXT UNIQUE NOT NULL,   -- User CPF from JWT 'preferred_username' field
  display_name TEXT,              -- Extracted from JWT 'name' field
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- memberships (group membership)
CREATE TABLE memberships (
  group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  granted_by INT NULL REFERENCES users(id),
  granted_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  PRIMARY KEY (group_id, user_id)
);

-- user_roles (direct user -> role assignments if needed)
CREATE TABLE user_roles (
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  granted_by INT NULL REFERENCES users(id),
  granted_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

-- group_management_rights
CREATE TABLE group_management_rights (
  id SERIAL PRIMARY KEY,
  manager_group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  target_group_pattern TEXT NOT NULL,  -- SQL pattern e.g. 'go:%' or exact 'rmi:public'
  created_by INT NULL REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(manager_group_id, target_group_pattern)
);

-- audit log for admin operations
CREATE TABLE admin_audit (
  id SERIAL PRIMARY KEY,
  actor_user_id INT NULL REFERENCES users(id),
  actor_subject TEXT,            -- store sub for ease
  operation TEXT NOT NULL,       -- e.g. 'add_member', 'create_mapping'
  target_type TEXT,              -- 'group','mapping','role', etc.
  target_id TEXT,                -- e.g. 'group:go:authenticated' or mapping id
  request_payload JSONB,
  result JSONB,
  success BOOLEAN,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```

### Notes

- Keep users array in DB to map Keycloak subject to internal ID. On first action by a subject the service can create the users row (idempotent).
- endpoints.path_pattern uses regex syntax for flexible pattern matching.
- Index important columns: memberships(user_id), group_roles(group_id), endpoints(method), etc.

## 3. FastAPI HTTP API

All endpoints require authentication:
- **Admin endpoints**: JWT (Keycloak) in `Authorization: Bearer <token>`
- **Mapping lookup endpoint**: JWT or static API token in `Authorization: Bearer <token>`

The Admin Service verifies the JWT, automatically creates user entries, and calls Cerbos Check to verify privileges. All responses are JSON.

**Base URL**: `/api/v1`

### Authentication & tracing

- `Authorization: Bearer <JWT_or_API_TOKEN>`
- OpenTelemetry traces are automatically generated for all requests

### Error model

- `401` for missing/invalid token
- `403` for not authorized (either by Cerbos or internal rules)
- `400` for bad requests
- `409` for conflicts (idempotency)
- `500` for server errors

### 3.1 User endpoints

**Note:** Users are automatically created when they access any endpoint with a valid JWT. No manual import is needed. The user's subject (CPF) is extracted from the JWT `preferred_username` field, and display_name from the `name` field.

#### GET /users/{subject}

Return user, groups, roles.

**Response:**
```json
{
 "id": 123,
 "subject": "alice",
 "display_name": "Alice",
 "groups": ["go:authenticated", "go:course:editor"],
 "roles": ["go:course:editor"]
}
```

**Implementation:**
- Query memberships + group_roles + user_roles.

### 3.2 Group endpoints

#### POST /groups

Create a group.

**Request:**
```json
{ "name": "go:authenticated", "description": "Authenticated users of GO API" }
```

**Before DB write:**
- Admin service calls Cerbos Check to verify caller has permission group:create (or group:manage) on that target group. (We require that only people with superadmin or go:admin or group-management rights create go:* groups.)

**Cerbos check example payload:**
```json
{
  "requestId": "req-123",
  "principal": { "id": "caller", "roles": ["go:admin"], "attr": {} },
  "resources": [
    { "resource": { "id": "group:go:authenticated", "attr": { "groupId": "go:authenticated" } }, "actions": ["group:create"] }
  ]
}
```

**Response:** 201 with group object.

#### GET /groups

List groups (supports query filters `?prefix=go:`).

#### DELETE /groups/{groupName}

Deletes group. Before deletion, call Cerbos Check for group:delete. Remove group_roles and memberships in a transaction. Push reconciliation to Cerbos (delete principal policies for members if used).

### 3.3 Membership endpoints (core)

#### POST /groups/{groupName}/members

Add member to group (delegation operation).

**Request:**
```json
{ "subject": "bob" }
```

**Flow:**
1. Ensure caller user row exists (create if necessary).
2. Build Cerbos check request asking if caller can group:add_member on group:{groupName}.
3. If config uses group-management-rights DB table, you may enforce local checks too, but always call Cerbos to make the final decision.
4. If allowed, create memberships row inside a DB transaction (upsert).
5. If Admin Service is operating in push-to-Cerbos mode: create or update principal policy for bob in Cerbos Admin API to include the group's roles (or add role to existing principal policy). Wait for Admin API 200; on failure, roll back DB change or retry with backoff. Record in admin_audit.

**Response:**
- 201 (created) or 200 (already member)
- Response body:
```json
{ "status": "member_added", "group": "go:authenticated", "subject": "bob" }
```

**Idempotency / concurrency:** This endpoint must be idempotent: if memberships row already exists, treat as success. Use DB constraints and ON CONFLICT DO NOTHING.

#### DELETE /groups/{groupName}/members/{subject}

Remove a member.
Flow similar: check group:remove_member, delete membership row, update Cerbos principal policy (remove role) and audit.

### 3.4 Role / group_roles endpoints

- **POST /roles** — create role (admin-only)
- **GET /roles**
- **POST /groups/{groupName}/roles** — assign a role to a group (check caller allowed to manage roles for that group)
- **DELETE /groups/{groupName}/roles/{roleName}**

When a role is added to a group, for each member in that group optionally push an updated principal policy for that user (if pushing to Cerbos).

### 3.5 Mapping endpoints (endpoint → action)

#### GET /mappings?path=/courses/123&method=POST

Return the action and mapping id (used by adapter)

#### POST /mappings

Create mapping:
```json
{
  "path_pattern": "/courses/*",
  "method": "POST",
  "action": "course:create",
  "owner_group": "go:admin"
}
```

**Before write:**
- Check caller via Cerbos Check for mapping:create or group:manage on the owner_group. (You can define a Cerbos resource mapping and an action mapping:create or re-use group:manage).

**Response:** created mapping id.

#### PUT /mappings/{id}

Update mapping (check permissions)

#### DELETE /mappings/{id}

Delete mapping (check permissions)

**Adapter usage:** adapters call GET /mappings to resolve path+method -> action. Adapter must include Authorization using JWT or static API token. For performance, adapter caches mapping results locally with TTL.

### 3.6 Background tasks

Reconciliation and sync operations run as background tasks:

- **Reconciliation task**: Periodically walks memberships, retrieves group→role mapping, and ensures Cerbos principal policies reflect DB state
- **Sync task**: Handles any failed Cerbos Admin API calls with retry logic
- Both tasks run automatically in the background (no manual endpoints)

### 3.7 Health and meta endpoints

- **GET /healthz**
- **GET /readyz**
- **GET /version**

## 4. Cerbos interactions — Check API & Admin API

### 4.1 When to call Cerbos Check API

Always before making an administrative mutation that affects permissions or groups. Typical actions:

- group:add_member, group:remove_member
- group:create, group:delete
- group:assign_role, group:remove_role
- mapping:create, mapping:update, mapping:delete (if you model mapping as resource)
- reconcile (optional: require superadmin)

For any operation where the caller must be explicitly authorized, do a Cerbos Check.

**Example Cerbos Check payload (group:add_member):**
```json
{
  "requestId": "admin-add-member-<uuid>",
  "principal": {
    "id": "alice",
    "roles": ["go:admin"],              // derived from caller's JWT or DB lookup
    "policyVersion": "default",
    "attr": { "userId": "alice" }
  },
  "resources": [
    {
      "resource": {
        "id": "group:go:authenticated",
        "attr": { "groupId": "go:authenticated" }
      },
      "actions": ["group:add_member"]
    }
  ]
}
```

**Interpretation:**
- If Cerbos returns EFFECT_ALLOW → proceed.
- If EFFECT_DENY → return 403 to the caller and audit the attempt.

**How to derive principal.roles for the caller:**

**Option A (simple):** Use the caller's JWT roles claim (Keycloak realm roles or group claims). If Keycloak already encodes go:admin in token, pass them through.

**Option B (authoritative):** If Keycloak tokens do not include all group roles, perform a DB lookup of the caller's memberships and group_roles to build P.roles before calling Cerbos Check. This is more authoritative and required if you keep DB as source-of-truth.

I recommend Option B for admin operations (make sure the admin service can read DB quickly).

### 4.2 Cerbos Admin API Integration

The service automatically pushes principal policies to Cerbos Admin API. This is transparent to API users - they work with simple REST operations and the service handles Cerbos policy management internally.

**Admin service logic when adding membership:**

1. Insert membership row into DB (within DB transaction)
2. Automatically build and push principal policy for the user that aggregates all roles
3. On success: commit DB transaction and return success to caller
4. On failure: use background retry job to ensure eventual consistency

**Policy management is completely transparent** - users never see or manipulate Cerbos policy formats.

## 5. Implementation details — flows & sample code

### 5.1 Add member flow (detailed)

1. Admin UI POST /groups/go:authenticated/members with body {"subject":"bob"}, Authorization header contains caller JWT.
2. Admin Service extracts subject of caller from JWT (caller_sub).
3. Ensure users row exists for caller_sub. Create or fetch actor_user_id.
4. Build principal for caller: fetch caller's roles from DB (memberships -> group_roles -> roles). This will be used to check permission to add members.
5. Call Cerbos Check (see 4.1 payload) to verify caller can group:add_member on group go:authenticated.
6. If Cerbos denies -> return 403 and write audit with success=false.
7. If Cerbos allows:
   - Start DB transaction
   - Upsert users row for bob
   - Insert memberships (group_id, user_id, granted_by)
   - Optionally compute aggregated roles for bob and build principal policy JSON
   - Call Cerbos Admin API POST /admin/policy with principal policy
   - On success: commit DB transaction, return 201, write audit success.
   - On failure: roll back DB transaction and return 500 (or commit DB and mark pending sync per pattern chosen). Write audit failure.
8. Adapter will observe new roles (because we pushed to Cerbos). If using DB-only mode, adapter sees membership on next lookup.

### 5.2 Remove member flow

Symmetric: call Cerbos group:remove_member for caller; if allow, delete membership row, call Cerbos Admin API to remove role or rebuild principal policy for user without removed group roles.

### 5.3 Create mapping flow

1. Caller POST /mappings (owner_group in body).
2. Build principal from caller (DB).
3. Cerbos Check: ask caller can mapping:create or group:manage on owner_group.
4. If allow, create endpoints row in DB. Audit.

**Adapter caching:**

Mapping endpoints (adapter) should use TTL cache. On create/update/delete mapping, Admin Service should optionally POST a small event to an internal pub/sub / ConfigMap / Kubernetes event or call adapter invalidation endpoint to cause adapters to refresh cache. Simpler: adapters poll mapping service periodically (e.g., TTL 30s).

### 5.4 Reconciliation

Batch job that iterates users and recreates principal policies for each user:

1. Query user -> collect roles from memberships and user_roles.
2. Build principalPolicy JSON and call Cerbos Admin API.
3. Run periodically or on-demand. Expose POST /reconcile/push-to-cerbos.

## 6. Caching, performance & adapter contract

### Adapter contract

Adapter will call GET /mappings?path=/courses/123&method=POST to resolve action. Admin Service returns:

```json
{
  "mapping_id": 10,
  "action": "course:create",
  "path_pattern": "/courses/*",
  "owner_group": "go:admin"
}
```

Admin Service protects this endpoint with JWT or static API token. Adapter must be allowed only to read mappings (no mapping modification).

### Caching

**Admin Service Server-Side Caching (Redis)**

Admin Service implements Redis caching for high-performance mapping resolution:

- **Mapping resolution cache**: Cache mapping lookup results with TTL (60s)
- **User role aggregation cache**: Cache user roles from database queries with TTL (30s)  
- **Keycloak JWKS cache**: Cache JWKS keys with TTL (300s) and automatic refresh
- **Cache invalidation**: Automatic cache invalidation on mapping/membership changes

**Adapter Client-Side Caching**

Adapter caches mapping resolution locally for TTL (e.g., 30s). Cache key: (method, path) or pattern match result (cache by mapping_id).

On mapping update, Admin Service can optionally POST an invalidation to a webhook URL configured for adapters (optional). If not implemented, adapter uses TTL.

### Role aggregation caching

When using DB-first + push-to-Cerbos, adapters need not query DB for user roles. They only pass JWT subject and Cerbos holds principal policies.

If using DB-only, the adapter must call Admin Service /users/{subject} to obtain roles. Cache results short (e.g., 10s) and invalidate on membership change (by admin service sending event).

## 4. Environment Configuration

All configuration is done through environment variables:

```bash
# PostgreSQL Database (shared by both containers)
DB_DSN=postgresql://user:pass@postgres:5432/heimdall

# Redis Cache (shared by both containers)
REDIS_URL=redis://redis:6379/0
REDIS_MAPPING_TTL=60  # seconds
REDIS_USER_ROLES_TTL=30  # seconds  
REDIS_JWKS_TTL=300  # seconds

# Cerbos
CERBOS_CHECK_URL=http://cerbos:3593/api/check/resources
CERBOS_ADMIN_URL=http://cerbos:3592/admin/policy
CERBOS_ADMIN_USER=admin
CERBOS_ADMIN_PASSWORD=password

# JWT
KEYCLOAK_JWKS_URL=https://keycloak.example.com/auth/realms/realm/protocol/openid-connect/certs
JWT_ALGORITHM=RS256
JWT_AUDIENCE=your-audience

# API Authentication
STATIC_API_TOKEN=your-static-token-for-adapters

# OpenTelemetry
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
OTEL_SERVICE_NAME=heimdall-admin-service  # or heimdall-background-tasks
OTEL_RESOURCE_ATTRIBUTES=service.name=heimdall-admin-service,service.version=1.0.0

# Background Tasks (for background container only)
RECONCILE_INTERVAL_SECONDS=300  # 5 minutes
SYNC_RETRY_INTERVAL_SECONDS=60  # 1 minute

# Server (for API container only)
HOST=0.0.0.0
PORT=8080
```

## 5. Docker Architecture

The service consists of **two separate Docker containers**:

### Container 1: API Service
- **Purpose**: Serves the FastAPI REST API
- **Base image**: `python:3.11-slim`
- **Exposed port**: 8080
- **Entry point**: FastAPI application with uvicorn
- **Environment**: All above variables except background task intervals

### Container 2: Background Tasks
- **Purpose**: Runs reconciliation and sync tasks
- **Base image**: `python:3.11-slim`
- **No exposed ports**: Internal service only
- **Entry point**: Python script with APScheduler
- **Environment**: All above variables except server host/port
- **Dependencies**: Same codebase as API, different entry point

### Dockerfile Structure
```dockerfile
# Multi-stage Dockerfile
FROM python:3.11-slim as base
# Install dependencies, copy code

FROM base as api
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]

FROM base as background
CMD ["python", "app/background_tasks.py"]
```

### Authentication

- **Admin endpoints**: Require JWT verification (Keycloak). Verify signature (JWKs), exp, aud, iss.
- **Mapping endpoint**: Accept either JWT or static API token.
- Users are automatically created in DB when they access endpoints with valid JWT.

### Auditing

- Audit every admin operation to admin_audit table: actor, timestamp, target, request body, result, success.

## 6. OpenTelemetry Tracing

The service implements distributed tracing using OpenTelemetry:

- **gRPC OTLP Exporter**: Sends traces to OTEL collector configured via `OTEL_EXPORTER_OTLP_ENDPOINT`
- **Automatic instrumentation**: All HTTP requests, database operations, and Cerbos API calls are traced
- **Custom spans**: Add spans for business logic operations (membership changes, policy updates)
- **Trace context propagation**: Maintains trace context across service boundaries

### Logs

- Structured JSON logs with trace_id, span_id, actor_subject, operation, target, result
- Do not log raw JWTs or sensitive data



## 7. FastAPI Implementation Examples

### Build Cerbos Check (Python)

```python
def build_cerbos_check(caller_sub, caller_roles, action, resource_type, resource_attrs):
    return {
      "requestId": f"admin-{uuid4()}",
      "principal": {
         "id": caller_sub,
         "roles": caller_roles,
         "policyVersion": "default",
         "attr": {}
      },
      "resources": [
         {
           "resource": {"id": resource_type, "attr": resource_attrs},
           "actions": [action]
         }
      ]
    }

def cerbos_check(session, cerbos_url, check_payload):
    r = session.post(cerbos_url + "/api/check/resources", json=check_payload, timeout=2)
    r.raise_for_status()
    resp = r.json()
    # examine result
    action = check_payload["resources"][0]["actions"][0]
    result = resp["responses"][0]["actions"][action]["result"]
    return result == "EFFECT_ALLOW"
```

### Push principal policy to Cerbos Admin API (Python)

```python
def push_principal_policy(session, admin_url, admin_auth, principal, roles):
    payload = {
      "policies": [
        {
          "apiVersion": "api.cerbos.dev/v1",
          "principalPolicy": {
            "principal": principal,
            "version": "default",
            "roles": roles
          }
        }
      ]
    }
    r = session.post(admin_url + "/admin/policy", json=payload, auth=admin_auth, timeout=5)
    r.raise_for_status()
    return r.json()
```

### Add member handler (outline)

```python
def add_member_handler(request):
    caller_token = request.headers["Authorization"].split()[1]
    caller_sub = extract_sub(caller_token)   # verify token in prod
    # fetch caller roles from DB
    caller_roles = db_get_roles_for_user(caller_sub)
    # cerbos check
    payload = build_cerbos_check(caller_sub, caller_roles, "group:add_member",
                                 "group:go:authenticated", {"groupId":"go:authenticated"})
    if not cerbos_check(session, CERBOS_URL, payload):
        return 403
    # upsert membership in DB (transaction)
    with db.transaction:
        bob = upsert_user(subject="bob")
        insert_membership(group_id, bob.id, granted_by=caller.id)
        # recompute bob roles
        bob_roles = db_get_roles_for_user(bob.subject)
        # push principal policy
        push_principal_policy(session, CERBOS_ADMIN_URL, admin_auth, bob.subject, bob_roles)
    audit.log(...)
    return 201
```

## 8. Development Environment Setup

### Required Tools
- **Nix** with flakes enabled
- **direnv** for automatic environment loading
- **uv** for Python package management
- **ruff** for Python linting and formatting
- **Docker** for containerization

### Project Structure
```
heimdall/
├── flake.nix              # Nix flake for system dependencies
├── .envrc                 # direnv configuration
├── .gitignore             # Git ignore file
├── pyproject.toml         # uv/Python project configuration
├── uv.lock               # uv lockfile
├── Dockerfile            # Multi-stage container build
├── docker-compose.yml    # Local development setup
├── app/
│   ├── main.py           # FastAPI application
│   ├── background_tasks.py # Background tasks entry point
│   ├── models/           # SQLAlchemy models
│   ├── routers/          # FastAPI route handlers
│   └── services/         # Business logic
└── migrations/           # Alembic migrations
```

### Development Setup Files

#### flake.nix
```nix
{
  description = "Heimdall Admin Service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            python311
            uv
            ruff
            docker
            docker-compose
            postgresql
            git
          ];

          shellHook = ''
            echo "Heimdall development environment loaded"
            echo "Python: $(python --version)"
            echo "uv: $(uv --version)"
            echo "ruff: $(ruff --version)"
          '';
        };
      });
}
```

#### .envrc
```bash
use flake

# Load environment variables for development
export DB_DSN="postgresql://postgres:postgres@localhost:5432/heimdall_dev"
export CERBOS_CHECK_URL="http://localhost:3593/api/check/resources"
export CERBOS_ADMIN_URL="http://localhost:3592/admin/policy"
export KEYCLOAK_JWKS_URL="https://your-keycloak/auth/realms/realm/protocol/openid-connect/certs"
export STATIC_API_TOKEN="dev-api-token"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"
```

#### .gitignore
```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Environment
.env
.env.local
.env.*.local

# direnv
.direnv/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Database
*.db
*.sqlite
*.sqlite3

# Logs
*.log
logs/

# Docker
.docker/

# OS
.DS_Store
Thumbs.db

# Temporary files
*.tmp
*.temp
```

## 9. Developer Checklist

### Environment Setup
- [ ] Install Nix with flakes enabled
- [ ] Install and configure direnv
- [ ] Create flake.nix with system dependencies
- [ ] Set up .envrc for environment loading
- [ ] Create comprehensive .gitignore

### Python Project Setup
- [ ] Initialize project with uv (`uv init`)
- [ ] Configure pyproject.toml with FastAPI, SQLAlchemy, Alembic dependencies
- [ ] Set up ruff for linting and formatting
- [ ] Create multi-stage Dockerfile for API and background containers
- [ ] Set up docker-compose.yml for local development

### Application Development
- [ ] Set up FastAPI project with PostgreSQL, SQLAlchemy and Alembic
- [ ] Implement environment configuration loading
- [ ] Set up OpenTelemetry tracing with gRPC OTLP exporter
- [ ] Implement JWT verification with auto-user creation
- [ ] Implement static API token authentication for mapping endpoint
- [ ] Create database models and migrations
- [ ] Implement Cerbos client wrapper (transparent to users)
- [ ] Implement all REST endpoints with proper validation
- [ ] Create separate background tasks container with APScheduler
- [ ] Add regex pattern matching for path_pattern
- [ ] Implement audit logging
- [ ] Add structured JSON logging with trace context
- [ ] Set up automatic Cerbos policy pushing on membership changes

## 10. Key Implementation Notes

### Tech Stack
- **FastAPI** with **PostgreSQL**, **SQLAlchemy** and **Alembic** for migrations
- **uv** for Python package management (faster than pip)
- **ruff** for linting and code formatting
- **Nix flakes** for reproducible development environment
- **direnv** for automatic environment loading

### Architecture
- **Two Docker containers**: API service and background tasks service
- All configuration via environment variables
- OpenTelemetry with gRPC OTLP exporter for distributed tracing
- Users auto-created on first JWT-authenticated request
- Cerbos policy management completely transparent to API users
- Background tasks run in separate container with APScheduler
- Regex support for flexible path pattern matching
- No manual user import - JWT access automatically creates users
- Multi-stage Dockerfile for efficient container builds

### Development Workflow
1. `direnv allow` to load development environment
2. `uv sync` to install Python dependencies
3. `ruff check` and `ruff format` for code quality
4. `docker-compose up` for local development stack
5. `alembic upgrade head` for database migrations
