# Heimdall Admin Service - Development Commands
# Run with: just <command>

# Default recipe - show available commands
default:
    @just --list

# Development commands
# ===================

# Install dependencies with uv
install:
    uv sync

# Run the API server locally for development
run:
    uv run uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

# Run background tasks locally
background:
    uv run python app/background_tasks.py

# Code quality commands
# ====================

# Run linting with ruff
lint:
    ruff check app/

# Fix linting issues automatically
lint-fix:
    ruff check --fix app/

# Format code with ruff
format:
    ruff format app/

# Run both linting and formatting
check: lint format

# Database commands
# ================

# Generate new database migration
migrate-create name:
    uv run alembic revision --autogenerate -m "{{name}}"

# Apply database migrations
migrate-up:
    uv run alembic upgrade head

# Rollback database migration
migrate-down:
    uv run alembic downgrade -1

# Show migration history
migrate-history:
    uv run alembic history

# Docker commands
# ===============

# Build docker images
docker-build:
    docker build --target api -t heimdall-api .
    docker build --target background -t heimdall-background .

# Run local development stack with docker-compose
docker-up:
    docker-compose up -d

# Stop local development stack
docker-down:
    docker-compose down

# View logs from docker-compose services
docker-logs service="":
    @if [ "{{service}}" = "" ]; then \
        docker-compose logs -f; \
    else \
        docker-compose logs -f {{service}}; \
    fi

# Testing commands
# ===============

# Run all tests (when implemented)
test:
    @echo "Tests not yet implemented - will be added in later phases"

# Run tests with coverage (when implemented)
test-coverage:
    @echo "Test coverage not yet implemented - will be added in later phases"

# Development utilities
# ====================

# Check if development environment is properly set up
check-env:
    @echo "Checking development environment..."
    @python --version
    @uv --version
    @ruff --version
    @docker --version
    @echo "Environment check complete!"

# Clean up generated files
clean:
    find . -type d -name "__pycache__" -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete
    find . -type f -name "*.pyo" -delete
    find . -type d -name "*.egg-info" -exec rm -rf {} +

# Show project structure
tree:
    @if command -v tree >/dev/null 2>&1; then \
        tree -I '.git|__pycache__|*.pyc|.venv|.direnv'; \
    else \
        find . -type f -not -path './.git/*' -not -path './__pycache__/*' -not -path './.venv/*' -not -path './.direnv/*' | sort; \
    fi

# Development workflow commands
# ============================

# Complete development setup (run after git clone)
setup: install migrate-up
    @echo "Development setup complete!"
    @echo "Run 'just run' to start the API server"

# Pre-commit checks (run before committing)
pre-commit: check lint
    @echo "Pre-commit checks passed!"

# Full development stack startup
dev: docker-up
    @echo "Waiting for services to start..."
    @sleep 5
    just run

# Quick restart of API during development
restart:
    @pkill -f "uvicorn app.main:app" || true
    @sleep 1
    just run