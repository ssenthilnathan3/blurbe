#!/bin/bash

# Auth DSL Demo Script
# This script demonstrates the CLI and key features of the Auth DSL

set -e

echo "🚀 Auth DSL - Define auth once. Use it anywhere."
echo "=============================================="
echo ""
sleep 2

echo "📖 First, let's explore the CLI interface:"
echo "$ auth-dsl --help"
stack exec auth-dsl -- --help
sleep 3

echo ""
echo "🔍 Let's see the available commands:"
echo ""
echo "Available commands:"
echo "  • init     - Initialize a new auth.dl file"
echo "  • serve    - Start the authentication server"
echo "  • compile  - Generate code for target languages"
echo "  • build    - Build SDKs and artifacts"
echo ""
sleep 2
sleep 3

echo "📝 Let's start by creating a new auth configuration..."
sleep 2

# Initialize a new auth.dl file
echo "$ auth-dsl init --path demo-auth.dl"
stack exec auth-dsl -- init --path demo-auth.dl
sleep 2

echo ""
echo "📋 Let's examine the generated configuration:"
echo "$ cat demo-auth.dl"
cat demo-auth.dl
sleep 3

echo ""
echo "🔧 Now let's compile this configuration to TypeScript:"
echo "$ auth-dsl compile --config demo-auth.dl --lang typescript --output demo-output"
stack exec auth-dsl -- compile --config demo-auth.dl --lang typescript --output demo-output
sleep 2

echo ""
echo "📂 Let's see what was generated:"
echo "$ ls -la demo-output/typescript/"
ls -la demo-output/typescript/
sleep 2

echo ""
echo "📄 Let's examine the generated TypeScript client:"
echo "$ head -30 demo-output/typescript/auth.ts"
head -30 demo-output/typescript/auth.ts
sleep 3

echo ""
echo "📦 And the package.json with dependencies:"
echo "$ cat demo-output/typescript/package.json"
cat demo-output/typescript/package.json
sleep 2

echo ""
echo "🔍 Let's look at the type definitions:"
echo "$ head -20 demo-output/typescript/types.ts"
head -20 demo-output/typescript/types.ts
sleep 2

echo ""
echo "✅ Let's verify the TypeScript code compiles correctly:"
echo "$ cd demo-output/typescript && npm install"
cd demo-output/typescript && npm install --silent
sleep 1

echo "$ npx tsc --noEmit --strict auth.ts"
npx tsc --noEmit --strict auth.ts
echo "✅ TypeScript compilation successful!"
cd ../..
sleep 2

echo ""
echo "🏗️  Now let's build a complete SDK package:"
echo "$ auth-dsl build --config demo-auth.dl --output demo-build"
stack exec auth-dsl -- build --config demo-auth.dl --output demo-build
sleep 2

echo ""
echo "📦 Let's see what was built:"
echo "$ tree demo-build/ -L 3"
tree demo-build/ -L 3 2>/dev/null || find demo-build -type d | head -10
sleep 2

echo ""
echo "🎯 Let's test with a different configuration - cookie-based sessions:"
cat > cookie-auth.dl << 'EOF'
// Cookie-based Auth Configuration

provider google {
  client_id = "${GOOGLE_CLIENT_ID}"
  client_secret = "${GOOGLE_CLIENT_SECRET}"
  scopes = ["email", "profile"]
}

session {
  strategy = "cookie"
  expiration = "24h"
  secure = true
}

database {
  type = "sqlite"
  connection = "auth.db"
}

protect "/api/admin" {
  roles = ["admin"]
}
EOF

echo "$ cat cookie-auth.dl"
cat cookie-auth.dl
sleep 2

echo ""
echo "$ auth-dsl compile --config cookie-auth.dl --lang typescript --output cookie-output"
stack exec auth-dsl -- compile --config cookie-auth.dl --lang typescript --output cookie-output
sleep 1

echo ""
echo "🍪 Notice the different session methods for cookie-based auth:"
echo "$ grep -A 10 'Cookie session management' cookie-output/typescript/auth.ts"
grep -A 10 'Cookie session management' cookie-output/typescript/auth.ts
sleep 3

echo ""
echo "🧪 Let's run the test suite to ensure everything works:"
echo "$ stack test --fast"
stack test --fast --silent
echo "✅ All tests passed!"
sleep 2

echo ""
echo "🎉 Demo Complete!"
echo "=================="
echo ""
echo "Key features demonstrated:"
echo "• 📝 DSL configuration with multiple providers"
echo "• 🔧 Code generation for TypeScript"
echo "• 📦 Complete SDK building"
echo "• 🍪 Different session strategies (JWT vs Cookie)"
echo "• ✅ Type-safe generated code"
echo "• 🧪 Comprehensive testing"
echo ""
echo "The Auth DSL makes it easy to:"
echo "• Define authentication once in a simple DSL"
echo "• Generate type-safe clients for multiple languages"
echo "• Support multiple auth providers and strategies"
echo "• Build production-ready SDKs and middleware"
echo ""
echo "Thanks for watching! 🚀"
sleep 3