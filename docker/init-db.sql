-- PostgreSQL initialization script for Heimdall development
-- This script runs when the PostgreSQL container starts for the first time

-- Create the main database (already created by POSTGRES_DB env var)
-- CREATE DATABASE heimdall_dev;

-- Create a test database for integration tests
CREATE DATABASE heimdall_test;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE heimdall_dev TO postgres;
GRANT ALL PRIVILEGES ON DATABASE heimdall_test TO postgres;

-- Connect to the main database and create any initial data if needed
\c heimdall_dev;

-- Tables will be created by Alembic migrations
-- This script is just for database initialization