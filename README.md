# Auth DSL

A domain-specific language for authentication systems in Haskell. Define auth once. Use it anywhere.

## Overview

Auth DSL allows developers to define their entire authentication system in a single declarative file (`auth.dl`) and then either serve it directly as a REST API or generate code for multiple target languages. The system supports OAuth2 providers, password authentication, multiple database backends, and production-ready security features.

## Quick Start

1. **Initialize a new project:**
   ```bash
   auth-dsl init
   ```

2. **Edit your `auth.dl` file:**
   ```
   provider google {
     client_id = "${GOOGLE_CLIENT_ID}"
     client_secret = "${GOOGLE_CLIENT_SECRET}"
     scopes = ["email", "profile"]
   }

   provider password {
     min_length = 8
     require_special = true
   }

   session {
     strategy = "jwt"
     expiration = "1h"
     secure = true
   }

   database {
     type = "sqlite"
     connection = "auth.db"
   }

   protect "/api/admin" {
     roles = ["admin"]
   }
   ```

3. **Start the development server:**
   ```bash
   auth-dsl serve
   ```

4. **Or generate code for your target language:**
   ```bash
   auth-dsl compile --target typescript
   ```

## Features

### ✅ Implemented
- **DSL Parser**: Complete Megaparsec-based parser for auth.dl syntax
- **Authentication Providers**: Google OAuth2 and password-based authentication
- **Session Management**: JWT and cookie-based sessions with configurable expiration
- **Database Support**: SQLite, PostgreSQL, and Supabase adapters
- **HTTP Server**: Production-ready Warp server with authentication endpoints
- **Security Features**: CORS, CSRF protection, rate limiting, secure headers
- **CLI Tools**: Full command-line interface with init, serve, compile, and build commands
- **Configuration Engine**: Environment variable resolution and validation

### 🚧 In Progress
- **Code Generation**: TypeScript generator (partial implementation)
- **Monitoring**: Health checks and metrics endpoints

### 📋 Planned
- **Multi-language Support**: Python and Go code generators
- **SDK Generation**: Client libraries with automatic token management
- **OpenAPI Export**: Automatic API documentation generation
- **Middleware Templates**: Route guards for popular frameworks
- **Container Support**: Docker and Kubernetes deployment

## Project Structure

```
src/AuthDSL/
├── Types.hs              # Core AST data types
├── Parser.hs             # Complete DSL parser implementation
├── Config.hs             # Configuration validation and transformation
├── Server.hs             # HTTP server with authentication endpoints
├── Codegen.hs            # Code generation engine
├── Security.hs           # Security middleware and utilities
├── Session.hs            # Session management (JWT/Cookie)
├── Cookie.hs             # Cookie handling utilities
├── Database.hs           # Database abstraction layer
├── Database/
│   ├── Adapters.hs       # Database adapter interface
│   ├── SQLite.hs         # SQLite implementation
│   ├── PostgreSQL.hs     # PostgreSQL implementation
│   └── Supabase.hs       # Supabase integration
└── Auth/
    └── Providers.hs      # Authentication provider implementations
```

## API Endpoints

When running `auth-dsl serve`, the following endpoints are available:

- `POST /login/:provider` - Initiate authentication with specified provider
- `GET /callback/:provider` - OAuth2 callback handling
- `GET /session` - Get current session information
- `POST /logout` - End user session
- `POST /register` - Register new user (password provider)
- `POST /refresh` - Refresh JWT tokens

## Database Schema

The system automatically creates the following tables based on your configuration:

- **users**: User accounts with provider-specific data
- **sessions**: Session storage (when using cookie strategy)
- **oauth_states**: OAuth2 state management for security

## Configuration Options

### Providers
- **Google OAuth2**: `client_id`, `client_secret`, `scopes`
- **Password Auth**: `min_length`, `require_special`, `require_numbers`, `require_uppercase`

### Session Strategies
- **JWT**: Stateless tokens with configurable expiration
- **Cookie**: Server-side sessions with database storage

### Database Types
- **SQLite**: Local file storage, perfect for development
- **PostgreSQL**: Production database with connection pooling
- **Supabase**: Managed PostgreSQL with built-in auth features

### Security Features
- HTTPS enforcement in production mode
- CSRF token protection
- Rate limiting per endpoint
- Secure cookie configuration
- CORS policy management

## Building and Development

```bash
# Build the project
stack build

# Run tests
stack test

# Start development server
stack exec auth-dsl -- serve

# Generate code
stack exec auth-dsl -- compile --target typescript

# Run with production settings
stack exec auth-dsl -- serve --env prod
```

## Environment Variables

Set these environment variables for OAuth2 providers:

```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
```

## Testing

The project includes comprehensive test coverage:

- **Unit Tests**: Parser, configuration validation, database adapters
- **Integration Tests**: Complete authentication flows, database operations
- **Security Tests**: CSRF protection, rate limiting, injection prevention
- **Property Tests**: Parser correctness with QuickCheck

Run tests with:
```bash
stack test
```

## Contributing

This project follows the implementation plan outlined in `.kiro/specs/auth-dsl/tasks.md`. Current focus areas:

1. Completing TypeScript code generation
2. Adding Python and Go generators
3. Implementing SDK generation with state management
4. Adding monitoring and deployment features
