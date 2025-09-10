# Heimdall Admin Service - Implementation TODO

This document contains a comprehensive list of tasks to implement the Heimdall Admin Service according to `SPEC.md`. Follow the tasks in order as they have dependencies.

## 📋 Policies

### ❌ No Mock Policy
- **No behavior is meant to be mocked** - all functionality must be fully implemented
- Integration with external services (Cerbos, Keycloak, PostgreSQL) must be real
- All API endpoints must have complete business logic, not placeholder responses

### ❌ No Ignore Policy  
- **If something is failing/erroring, you must fix it** - do not remove features or ignore errors
- All lint errors from ruff must be resolved
- All database connection issues must be properly handled
- All Cerbos API call failures must be properly handled with retry logic

## 🏗️ Phase 1: Development Environment Setup

### Task 1.1: Initialize Project Structure ✅
- [x] Create project directory: `heimdall/`
- [x] Initialize git repository: `git init`
- [x] Create directory structure as specified in SPEC.md Section 8:
  ```
  heimdall/
  ├── app/
  │   ├── __init__.py
  │   ├── main.py
  │   ├── background_tasks.py
  │   ├── models/
  │   │   └── __init__.py
  │   ├── routers/
  │   │   └── __init__.py
  │   ├── services/
  │   │   └── __init__.py
  │   └── database.py
  └── migrations/
  ```

### Task 1.2: Create Nix Flake Configuration ✅
- [x] Create `flake.nix` exactly as specified in SPEC.md Section 8
- [x] Ensure flake includes: python311, uv, ruff, docker, docker-compose, postgresql, git
- [x] Test flake works: `nix develop`
- [x] Verify all tools are available and display versions in shell hook

### Task 1.3: Setup direnv Configuration ✅
- [x] Create `.envrc` file exactly as specified in SPEC.md Section 8
- [x] Configure development environment variables for local development
- [x] Test direnv works: `direnv allow` and verify environment loads

### Task 1.4: Create Git Configuration ✅
- [x] Create `.gitignore` file exactly as specified in SPEC.md Section 8
- [x] Ensure `.direnv/` directory is excluded
- [x] Commit initial project structure
- [x] Verify no sensitive files are tracked

### Task 1.5: Initialize Python Project with uv ✅
- [x] Run `uv init` to initialize Python project
- [x] Create `pyproject.toml` with dependencies:
  - fastapi
  - uvicorn[standard]
  - sqlalchemy
  - alembic
  - psycopg2-binary
  - pydantic
  - python-jose[cryptography]
  - requests
  - opentelemetry-api
  - opentelemetry-sdk
  - opentelemetry-exporter-otlp-proto-grpc
  - opentelemetry-instrumentation-fastapi
  - opentelemetry-instrumentation-sqlalchemy
  - apscheduler
- [x] Configure ruff in pyproject.toml with strict linting rules
- [x] Run `uv sync` to install dependencies
- [x] Verify all packages install correctly

## 🐳 Phase 2: Containerization Setup

### Task 2.1: Create Multi-Stage Dockerfile ✅
- [x] Create `Dockerfile` with multi-stage build as specified in SPEC.md Section 5
- [x] Stage 1: Base image with Python 3.11-slim and dependencies
- [x] Stage 2: API service with FastAPI entry point
- [x] Stage 3: Background tasks with APScheduler entry point
- [x] Test both stages build successfully
- [x] Optimize image size and build time

### Task 2.2: Create Docker Compose for Development ✅
- [x] Create `docker-compose.yml` for local development with:
  - PostgreSQL service (heimdall database)
  - OpenTelemetry collector
  - Jaeger for trace visualization
- [x] Configure service networking and environment variables
- [x] Test services start and communicate correctly

## 🗄️ Phase 3: Database Layer Implementation

### Task 3.1: Create SQLAlchemy Models ✅
- [x] Implement all tables from SPEC.md Section 2 in `app/models/`:
  - `actions` table model
  - `endpoints` table model  
  - `roles` table model
  - `groups` table model
  - `group_roles` table model
  - `users` table model
  - `memberships` table model
  - `user_roles` table model
  - `group_management_rights` table model
  - `admin_audit` table model
- [x] Ensure all foreign key relationships are correctly defined
- [x] Add proper indexes as mentioned in SPEC.md Section 2 Notes
- [x] Follow PostgreSQL DDL exactly as specified

### Task 3.2: Setup Alembic Migrations ✅
- [x] Initialize Alembic: `alembic init migrations`
- [x] Configure `alembic.ini` to use environment variables for database URL
- [x] Create initial migration with all tables: `alembic revision --autogenerate -m "Initial tables"`
- [x] Test migration works: `alembic upgrade head`
- [x] Verify all tables created correctly in PostgreSQL

### Task 3.3: Create Database Connection Layer ✅
- [x] Implement `app/database.py` with:
  - SQLAlchemy engine configuration from environment variables
  - Session management with proper async support
  - Connection testing utilities
  - Error handling for database failures
- [x] Follow environment configuration from SPEC.md Section 4
- [x] Implement `get_db_session()` function for dependency injection

## 📡 Phase 4: OpenTelemetry Tracing Setup

### Task 4.1: Configure OpenTelemetry ✅
- [x] Implement OpenTelemetry setup exactly as shown in SPEC.md Section 6
- [x] Configure gRPC OTLP exporter using `OTEL_EXPORTER_OTLP_ENDPOINT`
- [x] Set up FastAPI instrumentation for automatic HTTP tracing
- [x] Set up SQLAlchemy instrumentation for database query tracing
- [x] Configure trace context propagation

### Task 4.2: Add Custom Spans for Business Logic ✅
- [x] Add tracing spans for all Cerbos API calls
- [x] Add tracing spans for membership operations
- [x] Add tracing spans for policy management
- [x] Add tracing spans for authentication operations
- [x] Ensure trace_id and span_id are included in structured logging

## 🔐 Phase 5: Authentication System

### Task 5.1: Implement JWT Verification ✅
- [x] Create JWT verification service in `app/services/auth.py`:
  - Fetch and cache Keycloak JWKS from `KEYCLOAK_JWKS_URL`
  - Verify JWT signature, expiration, audience, issuer
  - Extract user subject and claims
  - Handle token refresh and JWKS rotation
- [x] Follow JWT configuration from SPEC.md Section 4
- [x] Implement proper error handling for invalid tokens

### Task 5.2: Implement Auto-User Creation ✅
- [x] Create user service in `app/services/user.py`:
  - Auto-create user record on first JWT access (as specified in SPEC.md Section 3.1)
  - Upsert logic for user records
  - Use JWT 'preferred_username' field (CPF) as user subject/identifier
  - Extract display_name from JWT 'name' field for display purposes
- [x] Integrate with authentication dependency
- [x] Ensure idempotent user creation

### Task 5.3: Implement Static API Token Authentication ✅
- [x] Add static API token verification using `STATIC_API_TOKEN` environment variable
- [x] Create authentication dependency that accepts both JWT and static token
- [x] Implement token type detection and appropriate handling
- [x] Apply to mapping endpoints as specified in SPEC.md Section 3.5

## 🎯 Phase 6: Cerbos Integration

### Task 6.1: Create Cerbos Client Service ✅
- [x] Implement `app/services/cerbos.py` with:
  - Cerbos Check API client using `CERBOS_CHECK_URL`
  - Cerbos Admin API client using `CERBOS_ADMIN_URL` and credentials
  - Request payload builders as shown in SPEC.md Section 4.1
  - Response parsing and error handling
  - Retry logic with exponential backoff for failed calls

### Task 6.2: Implement Permission Checking ✅
- [x] Create permission checking functions for all admin operations:
  - `group:create`, `group:delete`, `group:add_member`, `group:remove_member`
  - `group:assign_role`, `group:remove_role`
  - `mapping:create`, `mapping:update`, `mapping:delete`
- [x] Follow Cerbos Check examples from SPEC.md Section 4.1
- [x] Implement proper role aggregation from database for principal.roles

### Task 6.3: Implement Transparent Policy Management ✅
- [x] Create policy management functions that:
  - Build principal policies from user roles (group_roles + user_roles)
  - Push policies to Cerbos Admin API automatically on membership changes
  - Handle policy updates transparently (users never see policy formats)
  - Implement retry logic for failed policy pushes
- [x] Follow policy examples from SPEC.md Section 4.2
- [x] Ensure policy management is completely transparent to API users

## 🛣️ Phase 7: FastAPI Application Structure

### Task 7.1: Create FastAPI Main Application ✅
- [x] Implement `app/main.py` with:
  - FastAPI app initialization
  - OpenTelemetry instrumentation setup
  - Router registration preparation for all endpoint groups
  - Global exception handlers with OpenTelemetry tracing
  - CORS configuration
  - Health, readiness, and version endpoints

### Task 7.2: Create Authentication Dependencies ✅
- [x] Implement authentication dependencies in `app/dependencies.py`:
  - `get_current_user()` for JWT authentication
  - `get_api_user()` for JWT or static token authentication  
  - User auto-creation integration
  - Proper error responses for authentication failures

## 👥 Phase 8: User Management API

### Task 8.1: Implement User Endpoints ✅
- [x] Create `app/routers/users.py` with:
  - `GET /users/{subject}` endpoint as specified in SPEC.md Section 3.1
  - Return user info with groups and roles
  - Proper authentication and error handling
  - Error handling for non-existent users

### Task 8.2: User Service Implementation ✅
- [x] Implement complete user service functions:
  - `get_user_by_subject()` with role aggregation
  - `get_user_roles()` from both group_roles and user_roles
  - `get_user_groups()` from memberships
  - Efficient database queries with proper joins

## 🏘️ Phase 9: Group Management API

### Task 9.1: Implement Group Endpoints
- [ ] Create `app/routers/groups.py` with all endpoints from SPEC.md Section 3.2:
  - `POST /groups` - create group with Cerbos permission check
  - `GET /groups` - list groups with optional prefix filtering
  - `DELETE /groups/{groupName}` - delete group with cleanup
- [ ] Implement proper request/response models with Pydantic
- [ ] Add comprehensive error handling and validation

### Task 9.2: Group Service Implementation
- [ ] Implement group service functions:
  - `create_group()` with Cerbos permission checking
  - `delete_group()` with cascading cleanup of memberships and roles
  - `list_groups()` with filtering support
  - Transaction management for consistency

## 👤 Phase 10: Membership Management API

### Task 10.1: Implement Membership Endpoints
- [ ] Create `app/routers/memberships.py` with endpoints from SPEC.md Section 3.3:
  - `POST /groups/{groupName}/members` - add member with full flow
  - `DELETE /groups/{groupName}/members/{subject}` - remove member
- [ ] Implement complete add member flow as detailed in SPEC.md Section 5.1:
  1. Caller authentication and user creation
  2. Cerbos permission check for group:add_member
  3. Database transaction with membership insertion
  4. Automatic Cerbos policy push
  5. Audit logging
- [ ] Ensure idempotent operations with proper conflict handling

### Task 10.2: Membership Service Implementation
- [ ] Implement membership service functions:
  - `add_member_to_group()` with complete transaction and policy management
  - `remove_member_from_group()` with policy updates
  - Proper role aggregation after membership changes
  - Automatic Cerbos policy synchronization
  - Comprehensive audit logging

## 🎭 Phase 11: Role Management API

### Task 11.1: Implement Role Endpoints
- [ ] Create `app/routers/roles.py` with endpoints from SPEC.md Section 3.4:
  - `POST /roles` - create role (admin-only)
  - `GET /roles` - list all roles
  - `POST /groups/{groupName}/roles` - assign role to group
  - `DELETE /groups/{groupName}/roles/{roleName}` - remove role from group

### Task 11.2: Role Service Implementation
- [ ] Implement role service functions:
  - `create_role()` with proper validation
  - `assign_role_to_group()` with member policy updates
  - `remove_role_from_group()` with policy cleanup
  - Batch policy updates for all group members when roles change

## 🗺️ Phase 12: Mapping Management API

### Task 12.1: Implement Mapping Endpoints
- [ ] Create `app/routers/mappings.py` with endpoints from SPEC.md Section 3.5:
  - `GET /mappings?path=/example&method=POST` - resolve path/method to action
  - `POST /mappings` - create new mapping
  - `PUT /mappings/{id}` - update existing mapping
  - `DELETE /mappings/{id}` - delete mapping
- [ ] Implement regex pattern matching for `path_pattern` as specified in SPEC.md Section 2
- [ ] Support for method matching including 'ANY' wildcard

### Task 12.2: Mapping Service Implementation
- [ ] Implement mapping service functions:
  - `resolve_mapping()` with regex pattern matching
  - `create_mapping()` with owner_group permission checking
  - `update_mapping()` and `delete_mapping()` with proper authorization
  - Efficient pattern matching algorithm for path resolution
  - Integration with Redis caching layer

### Task 12.3: Redis Caching Integration
- [ ] Add Redis to docker-compose.yml with appropriate configuration
- [ ] Add redis dependency to pyproject.toml
- [ ] Create Redis cache service in `app/services/cache.py`:
  - Redis connection with connection pooling
  - Cache key utilities and TTL management
  - Error handling and fallback to database
- [ ] Implement mapping resolution caching:
  - Cache GET /mappings results with 60s TTL
  - Cache invalidation on mapping CRUD operations
  - Tracing integration for cache hits/misses
- [ ] Add cache monitoring and metrics via OpenTelemetry

## 📋 Phase 13: Audit System

### Task 13.1: Implement Audit Logging
- [ ] Create audit service in `app/services/audit.py`:
  - Log all admin operations to `admin_audit` table
  - Include actor, timestamp, operation, target, request payload, result, success
  - Structured logging with trace context
  - Async audit logging to avoid blocking main operations

### Task 13.2: Add Audit to All Operations
- [ ] Add audit logging to all admin operations:
  - Group creation, deletion, modification
  - Membership additions and removals
  - Role assignments and removals  
  - Mapping creation, updates, deletions
  - Authentication failures and permission denials
- [ ] Ensure audit entries are created even when operations fail

## 🔄 Phase 14: Background Tasks Implementation

### Task 14.1: Create Background Tasks Container
- [ ] Implement `app/background_tasks.py` exactly as specified in SPEC.md Section 7:
  - APScheduler setup with AsyncIOScheduler
  - Reconciliation task with configurable interval
  - Sync retry task for failed operations
  - Proper logging and error handling
  - Graceful shutdown handling

### Task 14.2: Implement Reconciliation Logic
- [ ] Create reconciliation functions:
  - `reconcile_cerbos_policies()` - sync all user policies with Cerbos
  - Walk all users and rebuild their complete policy from database
  - Handle large numbers of users efficiently
  - Proper error handling and retry logic
  - Progress tracking and logging

### Task 14.3: Implement Sync Retry Logic
- [ ] Create sync retry functions:
  - `retry_failed_syncs()` - retry failed Cerbos operations
  - Exponential backoff for retries
  - Maximum retry limits
  - Failed operation tracking in database
  - Alert logging for permanently failed operations

## 🏥 Phase 15: Health and Monitoring

### Task 15.1: Implement Health Endpoints
- [ ] Create `app/routers/health.py` with endpoints from SPEC.md Section 3.7:
  - `GET /healthz` - basic health check
  - `GET /readyz` - readiness check (database connectivity)
  - `GET /version` - service version information

### Task 15.2: Implement Health Checks
- [ ] Create health check functions:
  - Database connectivity test
  - Cerbos API connectivity test
  - OpenTelemetry exporter health
  - Memory and resource utilization checks

## 📝 Phase 16: Structured Logging

### Task 16.1: Configure Structured Logging
- [ ] Set up JSON structured logging throughout the application:
  - Include trace_id, span_id in all log entries
  - Log actor_subject, operation, target for all admin operations
  - Use consistent log levels and message formats
  - Never log raw JWTs or sensitive data

### Task 16.2: Add Request/Response Logging
- [ ] Add structured logging for:
  - All HTTP requests with method, path, status_code, duration
  - All database operations with query type and execution time
  - All Cerbos API calls with operation type and response status
  - Authentication events and failures

## 🧪 Phase 17: Integration and End-to-End Testing

### Task 17.1: Create Integration Test Environment
- [ ] Set up test environment with:
  - Test PostgreSQL database
  - Test Cerbos instance with test policies
  - Mock Keycloak JWKS endpoint for test tokens
  - Test OpenTelemetry collector

### Task 17.2: Test Complete Workflows
- [ ] Test complete user workflows as described in SPEC.md:
  - User with admin role adds member to group
  - New member can access resources (verify with Cerbos)
  - User without permissions gets 403 errors
  - Mapping resolution works for adapters
  - Background tasks run and reconcile policies
- [ ] Test error scenarios and recovery
- [ ] Test concurrent operations and data consistency

## 🔧 Phase 18: Configuration and Environment

### Task 18.1: Environment Configuration Validation
- [ ] Implement environment variable validation:
  - Check all required variables from SPEC.md Section 4 are present
  - Validate database connection string format
  - Validate URL formats for Cerbos and Keycloak
  - Provide clear error messages for invalid configuration

### Task 18.2: Configuration Documentation
- [ ] Document all environment variables:
  - Required vs optional variables
  - Default values where applicable
  - Format examples and validation rules
  - Security considerations for sensitive values

## 🚀 Phase 19: Performance and Optimization

### Task 19.1: Database Performance
- [ ] Optimize database queries:
  - Add appropriate indexes for all frequently queried columns
  - Optimize joins for user role aggregation
  - Use query batching where appropriate
  - Monitor and log slow queries

### Task 19.2: Redis Caching Implementation
- [ ] Set up Redis service in docker-compose.yml
- [ ] Add redis dependency to pyproject.toml
- [ ] Create Redis connection layer in `app/cache.py`:
  - Redis client configuration with connection pooling
  - Cache key management and TTL utilities
  - Error handling for Redis failures
- [ ] Implement server-side caching for:
  - **Mapping resolution cache**: Cache GET /mappings results (60s TTL)
  - **User role aggregation cache**: Cache user roles from DB queries (30s TTL)
  - **Keycloak JWKS cache**: Cache JWKS keys (300s TTL) with refresh
  - **Cerbos permission cache**: Cache permission check results (10s TTL)
- [ ] Add cache invalidation logic:
  - Invalidate mapping cache on mapping create/update/delete
  - Invalidate user role cache on membership/role changes
  - Manual cache clearing endpoint for debugging
- [ ] Add caching metrics and monitoring via OpenTelemetry

## ✅ Phase 20: Final Validation and Deployment Preparation

### Task 20.1: Code Quality and Linting
- [ ] Run `ruff check` and fix all linting issues (No Ignore Policy)
- [ ] Run `ruff format` to ensure consistent code formatting
- [ ] Review all TODO/FIXME comments and resolve them
- [ ] Ensure all functions have proper type hints

### Task 20.2: Documentation and README
- [ ] Create comprehensive README.md with:
  - Quick start guide using docker-compose
  - Development setup instructions
  - API documentation links
  - Environment variable reference
  - Troubleshooting guide

### Task 20.3: Security Review
- [ ] Security checklist:
  - No secrets in code or logs
  - Proper JWT validation
  - SQL injection prevention (using SQLAlchemy parameters)
  - Input validation on all endpoints
  - Proper error messages that don't leak information

### Task 20.4: Final Testing
- [ ] Complete end-to-end testing:
  - All API endpoints work correctly
  - Background tasks run successfully
  - Cerbos integration works in both directions
  - OpenTelemetry traces are generated
  - Database migrations work correctly
  - Docker containers build and run properly

## 📚 Reference Guidelines

Throughout implementation, always refer to:
- **SPEC.md** for detailed requirements and implementation examples
- **No Mock Policy**: Implement all functionality completely
- **No Ignore Policy**: Fix all errors and issues, don't ignore or remove features
- **Environment Configuration**: SPEC.md Section 4 for all configuration requirements
- **Docker Architecture**: SPEC.md Section 5 for containerization details
- **API Specifications**: SPEC.md Section 3 for exact endpoint implementations
- **Database Schema**: SPEC.md Section 2 for exact table structures

## ⚠️ Critical Success Factors

1. **Follow SPEC.md exactly** - don't deviate from specified requirements
2. **Implement everything** - no mocking, no placeholders, no ignored features
3. **Fix all issues** - no ignoring lint errors, build failures, or runtime errors
4. **Test thoroughly** - verify each phase works before moving to the next
5. **Document clearly** - ensure setup and usage instructions are complete