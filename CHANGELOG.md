# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **BREAKING**: Migrated to typed DTO API (requires PHP client v0.9.1+)
  - `TokenValidator::validateToken()` now returns `ValidateTokenResponse` instead of `array`
  - `OctowireTokenAuthenticator` now works with `ValidateTokenResponse` and `TokenClaims` DTOs
  - Improved type safety and IDE autocompletion
- Updated configuration to support TCP/JATP transport (replaces gRPC)
- Configuration now uses `tcp.host` and `tcp.port` instead of `address`
- TLS configuration moved to `tcp.tls` section
- Updated examples to use TCP transport (port 50052)
- `octawire_auth.config.*` и `octawire_auth.client.*` сервисы объявлены публичными для корректной работы в тестовых контейнерах Symfony

### Added
- Support for `service_auth` configuration (service_name/service_secret) и автоматическая выдача service-token с кешированием до истечения `exp`
- Integration tests on otus_project2 ядре с real Auth Service (remote/local/hybrid)
- README clarifications: `project_id`/`default_project` - UUID из Auth Service, примеры TLS/mTLS + service auth
- TESTING_PLAN.md с покрытием: service tokens, local cache, multi-project, TLS/mTLS
- Support for `ValidateTokenRequest` and `ValidateTokenResponse` DTOs
- Support for `TokenClaims` DTO for type-safe claims handling
- Improved error messages with error codes from `ValidateTokenResponse`
- **Local token validation** - Local JWT signature verification using public keys
  - `LocalTokenValidator` service for local signature verification
  - Support for three validation modes: `remote`, `local`, `hybrid`
  - Configuration options: `validation_mode` and `check_blacklist`
  - Public key caching for performance
- **Project ID whitelist** - Enhanced security with project_id whitelist validation
  - Tokens with project_id not in configuration are rejected before validation
  - Improved error messages reflecting whitelist concept
  - Support for multiple project_id with different algorithms
- Dependency on `firebase/php-jwt` ^6.0 for local JWT validation

## [0.9.1] - 2025-11-25

### Added
- Initial release of Octawire Auth Service Symfony Bundle
- Support for Symfony 7.x
- Integration with Symfony Security Component
- Custom authenticator for JWT token validation via TCP/JATP
- Support for multiple projects (project_id)
- Automatic token validation from Authorization header
- Configuration support for TCP transport, TLS/mTLS, retry logic, key caching
- User Provider for compatibility with Symfony Security
- XSD schema for IDE autocompletion
- Examples and documentation

### Features
- `OctowireTokenAuthenticator` - Custom authenticator for JWT tokens via TCP/JATP
- `OctowireToken` - Security token with JWT claims
- `OctowireUser` - User representation from JWT claims
- `AuthClientFactory` - Factory for managing multiple AuthClient instances
- `TokenValidator` - Service for validating tokens through AuthClient
- Multi-project support with automatic project ID detection
- Full configuration support for all PHP client options
- TCP/JATP transport (no gRPC extension required)

[Unreleased]: https://github.com/kabiroman/octawire-auth-service-php-client-bundle




