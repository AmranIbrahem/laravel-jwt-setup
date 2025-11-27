# Changelog

All notable changes to this project will be documented in this file.

## [2.1.3] - 2025-11-27

### Added
- Initial release of Laravel JWT Auto Setup
- `jwt:auto-setup` Artisan command
- Automatic JWT package installation
- Configuration file publishing
- User model enhancement with JWTSubject
- Complete authentication file structure generation
    - AuthController with register, login, logout, refresh methods
    - Form Request classes (RegisterRequest, LoginRequest)
    - Response class for standardized JSON responses
    - API routes configuration
- Error handling and rollback mechanisms
