# Auth DSL

A domain-specific language for authentication systems in Haskell.

## Project Structure

```
src/
├── AuthDSL/
│   ├── Types.hs      # Core AST data types
│   ├── Parser.hs     # DSL parser (placeholder)
│   ├── Config.hs     # Configuration validation and transformation
│   ├── Server.hs     # HTTP server implementation
│   └── Codegen.hs    # Code generation engine
app/
└── Main.hs           # CLI entry point
```

## Core Types

- `AuthConfig`: Main configuration representing the entire auth.dl file
- `AuthProvider`: Authentication provider configuration (Google OAuth, Password)
- `SessionConfig`: Session management configuration
- `DatabaseConfig`: Database connection configuration
- `ProtectRule`: Route protection rules

## CLI Commands

- `auth-dsl init`: Initialize a new auth.dl template file
- `auth-dsl serve`: Start the authentication server
- `auth-dsl compile`: Generate code for target languages
- `auth-dsl build`: Build SDKs and artifacts

## Building

```bash
stack build
```

## Running

```bash
stack exec auth-dsl -- --help
```

## Status

This is the initial project structure setup (Task 1). The parser, server, and code generation components contain placeholder implementations that will be expanded in subsequent tasks.