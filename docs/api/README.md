# Heimdall Admin Service API Documentation

This directory contains the auto-generated OpenAPI specification for the Heimdall Admin Service.

## Files

- `openapi.json` - OpenAPI 3.0 specification in JSON format
- `openapi.yaml` - OpenAPI 3.0 specification in YAML format (if available)

## Usage

You can use these files with various tools:

### Swagger UI
Visit [Swagger Editor](https://editor.swagger.io/) and import the `openapi.json` or `openapi.yaml` file.

### Postman
Import the `openapi.json` file into Postman to generate a collection.

### Code Generation
Use tools like `openapi-generator` to generate client SDKs:

```bash
# Generate Python client
openapi-generator generate -i openapi.json -g python -o clients/python

# Generate TypeScript client
openapi-generator generate -i openapi.json -g typescript-fetch -o clients/typescript

# Generate Go client
openapi-generator generate -i openapi.json -g go -o clients/go
```

## Live Documentation

When the service is running, you can access the interactive documentation at:
- Swagger UI: `/docs`
- ReDoc: `/redoc`

## Last Updated

This specification was last updated on: 2025-09-19 18:02:52 UTC
Generated from commit: 75b079f64da0c8be6ab6d45a7a77a7b1dabb3816

## Servers

- **Production**: https://services.pref.rio/heimdall-admin
- **Staging**: https://services.staging.app.dados.rio/heimdall-admin