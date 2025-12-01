# Integration Tests Examples

This directory contains example scripts for testing the Symfony Bundle with a real Auth Service instance.

## Overview

| Script | Description |
|--------|-------------|
| `test-client-integration.php` | Tests direct communication with Auth Service (no Symfony) |
| `test-http-integration.php` | Tests full Symfony authentication flow via HTTP |

## Quick Start

### 1. Start Auth Service (without TLS)

```bash
cd /path/to/services/auth-service
./auth-service --config config/config.test.local.json
```

### 2. Run Client Integration Test

```bash
cd /path/to/your/symfony-project
php vendor/kabiroman/octawire-auth-service-php-client-bundle/examples/integration-tests/test-client-integration.php
```

Expected output:
```
=== Auth Service Client Integration Test ===
✓ AuthClient created
--- Test 1: Health Check ---
✓ Health check passed
--- Test 2: Issue Token ---
✓ Token issued successfully
--- Test 3: Validate Token ---
✓ Token validated successfully
=== All tests passed! ===
```

### 3. Run HTTP Integration Test

First, start your Symfony application:

```bash
cd /path/to/your/symfony-project
symfony server:start --port=8000
# Or: php -S localhost:8000 -t public
```

Then run the HTTP test:

```bash
php vendor/kabiroman/octawire-auth-service-php-client-bundle/examples/integration-tests/test-http-integration.php http://localhost:8000
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_SERVICE_HOST` | `localhost` | Auth Service hostname |
| `AUTH_SERVICE_PORT` | `50052` | Auth Service TCP port |
| `AUTH_SERVICE_TLS` | `false` | Enable TLS (`true`/`false`) |
| `AUTH_SERVICE_PROJECT_ID` | `test-project-id` | Project ID for tokens |
| `SYMFONY_URL` | `http://localhost:8000` | Symfony app URL (for HTTP tests) |

### Example Usage with Environment Variables

```bash
AUTH_SERVICE_HOST=auth.example.com \
AUTH_SERVICE_PORT=50052 \
AUTH_SERVICE_PROJECT_ID=my-project \
php test-client-integration.php
```

## Test Configurations

### Without TLS (Development)

Use `config/octawire_auth_no_tls.yaml` as a template.

Auth Service config (`config/config.test.local.json`):
- `tcp.tls.enabled: false`
- `security.auth_required: false`

### With TLS (Production-like)

Use `config/octawire_auth_with_tls.yaml` as a template.

Auth Service config (`config/config.prod.service_auth_true.json`):
- `tcp.tls.enabled: true`
- `security.auth_required: true`
- `security.service_auth.enabled: true`

## Required Symfony Endpoints

For HTTP integration tests, your Symfony app should have these test endpoints:

| Route | Access | Description |
|-------|--------|-------------|
| `/test/public` | Public | Returns message without auth |
| `/test/protected` | `ROLE_USER` | Returns user info, requires auth |
| `/test/admin` | `ROLE_ADMIN` | Admin-only endpoint |
| `/test/user-info` | `ROLE_USER` | Returns detailed claims |

See `examples/symfony-app/` for a complete example controller.

## Troubleshooting

### "Failed to connect to localhost:50052"

- Check that Auth Service is running: `ps aux | grep auth-service`
- Verify port is not blocked: `nc -zv localhost 50052`

### "Health check failed: Status is unhealthy"

- Check Redis connection: Auth Service requires Redis for blacklist/cache
- Check Auth Service logs: `cat /tmp/auth-service.log`

### "Token validation failed: project not found"

- Ensure `projectId` matches Auth Service configuration
- Check `projects` section in Auth Service config

### "Missing protocolVersion in response"

- Update Auth Service to v0.9.4+ (camelCase JSON fields)
- Or update PHP client to v0.9.4+

## Version Compatibility

| Bundle Version | Auth Service | Protocol | Notes |
|---------------|--------------|----------|-------|
| 0.9.4+ | v0.8.0+ | v1.0 | camelCase JSON fields |
| 0.9.3 | v0.7.x | v0.9 | snake_case JSON fields |

## See Also

- [TESTING.md](../../TESTING.md) - Full testing guide
- [README.md](../../README.md) - Bundle documentation
- [CHANGELOG.md](../../CHANGELOG.md) - Version history

