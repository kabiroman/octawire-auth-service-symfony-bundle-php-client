# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Updated configuration to support TCP/JATP transport (replaces gRPC)
- Configuration now uses `tcp.host` and `tcp.port` instead of `address`
- TLS configuration moved to `tcp.tls` section
- Updated examples to use TCP transport (port 50052)

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




