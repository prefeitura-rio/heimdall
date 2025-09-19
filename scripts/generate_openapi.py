#!/usr/bin/env python3
"""
Script to generate OpenAPI specification from FastAPI app.
This script is used by GitHub Actions to auto-generate API documentation.
"""

import json
import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Also add the app directory
app_dir = project_root / "app" 
sys.path.insert(0, str(app_dir))

# Set required environment variables with defaults for OpenAPI generation
os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost:5432/heimdall")
os.environ.setdefault("CERBOS_BASE_URL", "http://localhost:3592")
os.environ.setdefault("CERBOS_ADMIN_USER", "cerbos")
os.environ.setdefault("CERBOS_ADMIN_PASSWORD", "cerbos")
os.environ.setdefault("KEYCLOAK_JWKS_URL", "http://localhost:8080/realms/master/protocol/openid-connect/certs")
os.environ.setdefault("JWT_ALGORITHM", "RS256")
os.environ.setdefault("JWT_AUDIENCE", "superapp")
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "superapp")
os.environ.setdefault("STATIC_API_TOKEN", "static-token-for-openapi-generation")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

def generate_openapi_spec(server_url: str = None, path_prefix: str = ""):
    """
    Generate OpenAPI specification with optional server URL and path prefix.
    
    Args:
        server_url: Base server URL (e.g., "https://api.yourcompany.com")
        path_prefix: API path prefix (e.g., "/v1" or "/heimdall")
    """
    try:
        # Import FastAPI app
        from app.main import app
        
        # Get the OpenAPI schema
        openapi_schema = app.openapi()
        
        # Customize server URL if provided
        if server_url:
            openapi_schema["servers"] = [
                {
                    "url": f"{server_url.rstrip('/')}{path_prefix}",
                    "description": "Production server"
                }
            ]
        elif path_prefix:
            # If only path prefix is provided, use relative URL
            openapi_schema["servers"] = [
                {
                    "url": path_prefix,
                    "description": "API server with path prefix"
                }
            ]
        
        # Update paths with prefix if needed (FastAPI handles this automatically with root_path)
        if path_prefix and not server_url:
            # Only modify paths if we're using relative URLs
            new_paths = {}
            for path, methods in openapi_schema.get("paths", {}).items():
                new_path = f"{path_prefix.rstrip('/')}{path}"
                new_paths[new_path] = methods
            if new_paths:
                openapi_schema["paths"] = new_paths
        
        return openapi_schema
        
    except Exception as e:
        print(f"Error generating OpenAPI spec: {e}")
        sys.exit(1)

def main():
    """Main function to generate and save OpenAPI specification."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate OpenAPI specification")
    parser.add_argument(
        "--server-url", 
        type=str, 
        help="Base server URL (e.g., https://api.yourcompany.com)"
    )
    parser.add_argument(
        "--path-prefix", 
        type=str, 
        default="", 
        help="API path prefix (e.g., /v1 or /heimdall)"
    )
    parser.add_argument(
        "--output", 
        type=str, 
        default="openapi.json", 
        help="Output file path (default: openapi.json)"
    )
    parser.add_argument(
        "--format", 
        choices=["json", "yaml"], 
        default="json", 
        help="Output format (default: json)"
    )
    
    args = parser.parse_args()
    
    # Generate the OpenAPI spec
    print("Generating OpenAPI specification...")
    openapi_spec = generate_openapi_spec(
        server_url=args.server_url,
        path_prefix=args.path_prefix
    )
    
    # Prepare output content
    if args.format == "yaml":
        try:
            import yaml
            content = yaml.dump(openapi_spec, default_flow_style=False, sort_keys=False)
        except ImportError:
            print("PyYAML not available, falling back to JSON format")
            content = json.dumps(openapi_spec, indent=2)
            args.output = args.output.replace('.yaml', '.json').replace('.yml', '.json')
    else:
        content = json.dumps(openapi_spec, indent=2)
    
    # Write to file
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write(content)
    
    print(f"OpenAPI specification generated: {output_path}")
    
    # Print some info about the generated spec
    paths_count = len(openapi_spec.get("paths", {}))
    servers = openapi_spec.get("servers", [])
    
    print(f"API Title: {openapi_spec.get('info', {}).get('title', 'Unknown')}")
    print(f"API Version: {openapi_spec.get('info', {}).get('version', 'Unknown')}")
    print(f"Endpoints: {paths_count}")
    
    if servers:
        print("Servers:")
        for server in servers:
            print(f"  - {server.get('url', 'Unknown')} ({server.get('description', 'No description')})")
    
    return output_path

if __name__ == "__main__":
    main()