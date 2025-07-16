{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Options.Applicative
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import System.Directory (createDirectoryIfMissing, doesFileExist)
import System.Exit (exitFailure)

import AuthDSL.Types
import AuthDSL.Parser
import AuthDSL.Config
import AuthDSL.Server (TLSConfig(..), ServerConfig(..), runAuthServer)
import AuthDSL.Codegen
import AuthDSL.Security (defaultSecurityConfig)

-- | CLI command data type
data Command
  = Init InitOptions
  | Serve ServeOptions
  | Compile CompileOptions
  | Build BuildOptions
  deriving (Show)

-- | Init command options
data InitOptions = InitOptions
  { initPath :: FilePath
  } deriving (Show)

-- | Serve command options
data ServeOptions = ServeOptions
  { serveConfigFile :: FilePath
  , servePort :: Int
  , serveEnv :: Text
  } deriving (Show)

-- | Compile command options
data CompileOptions = CompileOptions
  { compileConfigFile :: FilePath
  , compileLanguages :: [Text]
  , compileOutputDir :: FilePath
  } deriving (Show)

-- | Build command options
data BuildOptions = BuildOptions
  { buildConfigFile :: FilePath
  , buildOutputDir :: FilePath
  } deriving (Show)

-- | Main entry point
main :: IO ()
main = do
  cmd <- execParser opts
  case cmd of
    Init initOpts -> runInit initOpts
    Serve serveOpts -> runServe serveOpts
    Compile compileOpts -> runCompile compileOpts
    Build buildOpts -> runBuild buildOpts
  where
    opts = info (commandParser <**> helper)
      ( fullDesc
     <> progDesc "Auth DSL - Define auth once. Use it anywhere."
     <> header "auth-dsl - Domain-specific language for authentication systems" )

-- | Command parser
commandParser :: Parser Command
commandParser = subparser
  ( command "init" (info initParser (progDesc "Initialize a new auth.dl file"))
 <> command "serve" (info serveParser (progDesc "Start the authentication server"))
 <> command "compile" (info compileParser (progDesc "Generate code for target languages"))
 <> command "build" (info buildParser (progDesc "Build SDKs and artifacts"))
  )

-- | Init command parser
initParser :: Parser Command
initParser = Init <$> (InitOptions <$> strOption
  ( long "path"
 <> short 'p'
 <> metavar "PATH"
 <> value "auth.dl"
 <> help "Path for the new auth.dl file" ))

-- | Serve command parser
serveParser :: Parser Command
serveParser = Serve <$> (ServeOptions
  <$> strOption
      ( long "config"
     <> short 'c'
     <> metavar "FILE"
     <> value "auth.dl"
     <> help "Auth configuration file" )
  <*> option auto
      ( long "port"
     <> short 'p'
     <> metavar "PORT"
     <> value 8080
     <> help "Server port" )
  <*> strOption
      ( long "env"
     <> short 'e'
     <> metavar "ENV"
     <> value "dev"
     <> help "Environment (dev/prod)" ))

-- | Compile command parser
compileParser :: Parser Command
compileParser = Compile <$> (CompileOptions
  <$> strOption
      ( long "config"
     <> short 'c'
     <> metavar "FILE"
     <> value "auth.dl"
     <> help "Auth configuration file" )
  <*> many (strOption
      ( long "lang"
     <> short 'l'
     <> metavar "LANG"
     <> help "Target language (typescript, python, go)" ))
  <*> strOption
      ( long "output"
     <> short 'o'
     <> metavar "DIR"
     <> value "generated"
     <> help "Output directory" ))

-- | Build command parser
buildParser :: Parser Command
buildParser = Build <$> (BuildOptions
  <$> strOption
      ( long "config"
     <> short 'c'
     <> metavar "FILE"
     <> value "auth.dl"
     <> help "Auth configuration file" )
  <*> strOption
      ( long "output"
     <> short 'o'
     <> metavar "DIR"
     <> value "build"
     <> help "Build output directory" ))

-- | Run init command
runInit :: InitOptions -> IO ()
runInit opts = do
  let template = defaultAuthTemplate
  T.writeFile (initPath opts) template
  putStrLn $ "Created auth.dl template at " ++ initPath opts

-- | Run serve command
runServe :: ServeOptions -> IO ()
runServe opts = do
  result <- parseAuthConfigFile (serveConfigFile opts)
  case result of
    Left err -> putStrLn $ "Parse error: " ++ show err
    Right config -> do
      case validateConfig config of
        Left validationErr -> putStrLn $ "Validation error: " ++ show validationErr
        Right validatedConfig -> do
          runtimeResult <- transformToRuntime validatedConfig
          case runtimeResult of
            Left runtimeErr -> putStrLn $ "Runtime configuration error: " ++ show runtimeErr
            Right runtimeConfig -> do
              let tlsConfig = if serveEnv opts == "prod" 
                    then Just $ TLSConfig True (Just "cert.pem") (Just "key.pem") 443
                    else Nothing
                  serverConfig = ServerConfig (servePort opts) "localhost" runtimeConfig True True defaultSecurityConfig tlsConfig
              runAuthServer serverConfig

-- | Run compile command
runCompile :: CompileOptions -> IO ()
runCompile opts = do
  putStrLn "🔧 Compiling auth configuration..."
  
  -- Validate input file exists
  result <- parseAuthConfigFile (compileConfigFile opts)
  case result of
    Left err -> do
      putStrLn $ "❌ Parse error: " ++ show err
      putStrLn "💡 Tip: Check your auth.dl file syntax"
    Right config -> do
      case validateConfig config of
        Left validationErr -> do
          putStrLn $ "❌ Validation error: " ++ show validationErr
          putStrLn "💡 Tip: Ensure all required fields are provided and environment variables are set"
        Right validatedConfig -> do
          let languages = if null (compileLanguages opts) 
                         then ["typescript"] -- Default to TypeScript if no languages specified
                         else compileLanguages opts
          
          putStrLn $ "📝 Generating code for languages: " ++ show languages
          putStrLn $ "📁 Output directory: " ++ compileOutputDir opts
          
          -- Create output directory if it doesn't exist
          createDirectoryIfMissing True (compileOutputDir opts)
          
          -- Generate code for each language (placeholder for now)
          mapM_ (generateCodeForLanguage validatedConfig (compileOutputDir opts)) languages
          
          putStrLn "✅ Code generation completed successfully!"
          putStrLn $ "📂 Generated files are in: " ++ compileOutputDir opts

-- | Generate code for a specific language using the actual code generator
generateCodeForLanguage :: AuthConfig -> FilePath -> Text -> IO ()
generateCodeForLanguage config outputDir lang = do
  putStrLn $ "  🔨 Generating " ++ T.unpack lang ++ " code..."
  let langDir = outputDir ++ "/" ++ T.unpack lang
  createDirectoryIfMissing True langDir
  
  case T.toLower lang of
    "typescript" -> do
      -- Use the actual TypeScript code generator
      generatedCode <- generateAuth config TypeScript
      typeDefinitions <- generateTypes config TypeScript
      
      -- Write the generated files
      mapM_ (\(filePath, content) -> T.writeFile (langDir ++ "/" ++ filePath) content) (sourceFiles generatedCode)
      mapM_ (\(filePath, content) -> T.writeFile (langDir ++ "/" ++ filePath) content) (typeFiles typeDefinitions)
      
      -- Write package.json with dependencies
      let packageJson = generatePackageJson (dependencies generatedCode)
      T.writeFile (langDir ++ "/package.json") packageJson
      
      putStrLn "    ✓ Generated TypeScript client"
    "python" -> do
      T.writeFile (langDir ++ "/auth_client.py") pythonPlaceholder
      putStrLn "    ✓ Generated Python client (placeholder)"
    "go" -> do
      T.writeFile (langDir ++ "/auth_client.go") goPlaceholder
      putStrLn "    ✓ Generated Go client (placeholder)"
    _ -> putStrLn $ "    ⚠️  Language '" ++ T.unpack lang ++ "' not yet supported"

-- Placeholder code templates
typescriptPlaceholder :: Text
typescriptPlaceholder = T.unlines
  [ "// Generated TypeScript Auth Client"
  , "// This is a placeholder - full implementation coming in task 10.1"
  , ""
  , "export interface AuthConfig {"
  , "  // Configuration types will be generated here"
  , "}"
  , ""
  , "export class AuthClient {"
  , "  // Client implementation will be generated here"
  , "}"
  ]

pythonPlaceholder :: Text
pythonPlaceholder = T.unlines
  [ "# Generated Python Auth Client"
  , "# This is a placeholder - full implementation coming in task 10.2"
  , ""
  , "class AuthConfig:"
  , "    # Configuration types will be generated here"
  , "    pass"
  , ""
  , "class AuthClient:"
  , "    # Client implementation will be generated here"
  , "    pass"
  ]

goPlaceholder :: Text
goPlaceholder = T.unlines
  [ "// Generated Go Auth Client"
  , "// This is a placeholder - full implementation coming in task 10.2"
  , ""
  , "package auth"
  , ""
  , "type AuthConfig struct {"
  , "    // Configuration types will be generated here"
  , "}"
  , ""
  , "type AuthClient struct {"
  , "    // Client implementation will be generated here"
  , "}"
  ]

-- | Run build command
runBuild :: BuildOptions -> IO ()
runBuild opts = do
  putStrLn "🏗️  Building SDKs and artifacts..."
  
  -- Check if config file exists
  configExists <- doesFileExist (buildConfigFile opts)
  if not configExists
    then do
      putStrLn $ "❌ Configuration file not found: " ++ buildConfigFile opts
      putStrLn "💡 Tip: Run 'auth-dsl init' to create a new auth.dl file"
      exitFailure
    else do
      result <- parseAuthConfigFile (buildConfigFile opts)
      case result of
        Left err -> do
          putStrLn $ "❌ Parse error: " ++ show err
          putStrLn "💡 Tip: Check your auth.dl file syntax"
          exitFailure
        Right config -> do
          case validateConfig config of
            Left validationErr -> do
              putStrLn $ "❌ Validation error: " ++ show validationErr
              putStrLn "💡 Tip: Ensure all required fields are provided and environment variables are set"
              exitFailure
            Right validatedConfig -> do
              putStrLn $ "📁 Build output directory: " ++ buildOutputDir opts
              
              -- Create build directory if it doesn't exist
              createDirectoryIfMissing True (buildOutputDir opts)
              
              -- Build SDKs and artifacts (placeholder for now)
              buildSDKs validatedConfig (buildOutputDir opts)
              buildOpenAPISpec validatedConfig (buildOutputDir opts)
              buildMiddlewareTemplates validatedConfig (buildOutputDir opts)
              
              putStrLn "✅ Build completed successfully!"
              putStrLn $ "📂 Build artifacts are in: " ++ buildOutputDir opts
              putStrLn "📋 Generated artifacts:"
              putStrLn "   • TypeScript SDK"
              putStrLn "   • Python SDK" 
              putStrLn "   • Go SDK"
              putStrLn "   • OpenAPI specification"
              putStrLn "   • Middleware templates"

-- | Build SDKs for all supported languages (placeholder implementation)
buildSDKs :: AuthConfig -> FilePath -> IO ()
buildSDKs config outputDir = do
  putStrLn "📦 Building SDKs..."
  let sdkDir = outputDir ++ "/sdks"
  createDirectoryIfMissing True sdkDir
  
  -- Generate SDKs for each language
  mapM_ (buildSDKForLanguage config sdkDir) ["typescript", "python", "go"]

-- | Build SDK for a specific language (placeholder implementation)
buildSDKForLanguage :: AuthConfig -> FilePath -> Text -> IO ()
buildSDKForLanguage config outputDir lang = do
  putStrLn $ "  🔨 Building " ++ T.unpack lang ++ " SDK..."
  let langDir = outputDir ++ "/" ++ T.unpack lang
  createDirectoryIfMissing True langDir
  
  case T.toLower lang of
    "typescript" -> do
      T.writeFile (langDir ++ "/package.json") typescriptPackageJson
      T.writeFile (langDir ++ "/index.ts") typescriptSDK
      T.writeFile (langDir ++ "/README.md") (typescriptReadme lang)
      putStrLn "    ✓ Generated TypeScript SDK"
    "python" -> do
      T.writeFile (langDir ++ "/setup.py") pythonSetup
      T.writeFile (langDir ++ "/__init__.py") pythonSDK
      T.writeFile (langDir ++ "/README.md") (pythonReadme lang)
      putStrLn "    ✓ Generated Python SDK"
    "go" -> do
      T.writeFile (langDir ++ "/go.mod") goMod
      T.writeFile (langDir ++ "/auth.go") goSDK
      T.writeFile (langDir ++ "/README.md") (goReadme lang)
      putStrLn "    ✓ Generated Go SDK"
    _ -> putStrLn $ "    ⚠️  Language '" ++ T.unpack lang ++ "' not yet supported"

-- | Build OpenAPI specification (placeholder implementation)
buildOpenAPISpec :: AuthConfig -> FilePath -> IO ()
buildOpenAPISpec config outputDir = do
  putStrLn "📋 Building OpenAPI specification..."
  T.writeFile (outputDir ++ "/openapi.yaml") openAPISpec
  putStrLn "    ✓ Generated OpenAPI specification"

-- | Build middleware templates (placeholder implementation)
buildMiddlewareTemplates :: AuthConfig -> FilePath -> IO ()
buildMiddlewareTemplates config outputDir = do
  putStrLn "🔧 Building middleware templates..."
  let middlewareDir = outputDir ++ "/middleware"
  createDirectoryIfMissing True middlewareDir
  
  T.writeFile (middlewareDir ++ "/express.js") expressMiddleware
  T.writeFile (middlewareDir ++ "/fastapi.py") fastapiMiddleware
  T.writeFile (middlewareDir ++ "/gin.go") ginMiddleware
  putStrLn "    ✓ Generated middleware templates"

-- SDK Templates (placeholders)
typescriptPackageJson :: Text
typescriptPackageJson = T.unlines
  [ "{"
  , "  \"name\": \"auth-dsl-client\","
  , "  \"version\": \"1.0.0\","
  , "  \"description\": \"Generated TypeScript SDK for Auth DSL\","
  , "  \"main\": \"index.js\","
  , "  \"types\": \"index.d.ts\","
  , "  \"dependencies\": {"
  , "    \"axios\": \"^1.0.0\""
  , "  }"
  , "}"
  ]

typescriptSDK :: Text
typescriptSDK = T.unlines
  [ "// Generated TypeScript SDK"
  , "// This is a placeholder - full implementation coming in task 11.1"
  , ""
  , "export class AuthDSLClient {"
  , "  constructor(private baseUrl: string) {}"
  , "  // SDK implementation will be generated here"
  , "}"
  ]

pythonSetup :: Text
pythonSetup = T.unlines
  [ "from setuptools import setup, find_packages"
  , ""
  , "setup("
  , "    name='auth-dsl-client',"
  , "    version='1.0.0',"
  , "    description='Generated Python SDK for Auth DSL',"
  , "    packages=find_packages(),"
  , "    install_requires=['requests']"
  , ")"
  ]

pythonSDK :: Text
pythonSDK = T.unlines
  [ "# Generated Python SDK"
  , "# This is a placeholder - full implementation coming in task 11.1"
  , ""
  , "class AuthDSLClient:"
  , "    def __init__(self, base_url: str):"
  , "        self.base_url = base_url"
  , "        # SDK implementation will be generated here"
  ]

goMod :: Text
goMod = T.unlines
  [ "module auth-dsl-client"
  , ""
  , "go 1.19"
  , ""
  , "require ("
  , "    // Dependencies will be added here"
  , ")"
  ]

goSDK :: Text
goSDK = T.unlines
  [ "// Generated Go SDK"
  , "// This is a placeholder - full implementation coming in task 11.1"
  , ""
  , "package auth"
  , ""
  , "type Client struct {"
  , "    BaseURL string"
  , "    // SDK implementation will be generated here"
  , "}"
  ]

-- README templates
typescriptReadme :: Text -> Text
typescriptReadme lang = T.unlines
  [ "# Auth DSL TypeScript SDK"
  , ""
  , "Generated SDK for Auth DSL authentication system."
  , ""
  , "## Installation"
  , ""
  , "```bash"
  , "npm install"
  , "```"
  , ""
  , "## Usage"
  , ""
  , "```typescript"
  , "import { AuthDSLClient } from './index';"
  , ""
  , "const client = new AuthDSLClient('http://localhost:8080');"
  , "// Usage examples will be generated here"
  , "```"
  ]

pythonReadme :: Text -> Text
pythonReadme lang = T.unlines
  [ "# Auth DSL Python SDK"
  , ""
  , "Generated SDK for Auth DSL authentication system."
  , ""
  , "## Installation"
  , ""
  , "```bash"
  , "pip install -e ."
  , "```"
  , ""
  , "## Usage"
  , ""
  , "```python"
  , "from auth_dsl_client import AuthDSLClient"
  , ""
  , "client = AuthDSLClient('http://localhost:8080')"
  , "# Usage examples will be generated here"
  , "```"
  ]

goReadme :: Text -> Text
goReadme lang = T.unlines
  [ "# Auth DSL Go SDK"
  , ""
  , "Generated SDK for Auth DSL authentication system."
  , ""
  , "## Installation"
  , ""
  , "```bash"
  , "go mod tidy"
  , "```"
  , ""
  , "## Usage"
  , ""
  , "```go"
  , "package main"
  , ""
  , "import \"auth-dsl-client\""
  , ""
  , "func main() {"
  , "    client := auth.Client{BaseURL: \"http://localhost:8080\"}"
  , "    // Usage examples will be generated here"
  , "}"
  , "```"
  ]

-- OpenAPI specification template
openAPISpec :: Text
openAPISpec = T.unlines
  [ "openapi: 3.0.0"
  , "info:"
  , "  title: Auth DSL API"
  , "  version: 1.0.0"
  , "  description: Generated API specification for Auth DSL"
  , "paths:"
  , "  /login/{provider}:"
  , "    post:"
  , "      summary: Initiate authentication with provider"
  , "      # Full specification will be generated in task 11.2"
  , "  /session:"
  , "    get:"
  , "      summary: Get current session information"
  , "      # Full specification will be generated in task 11.2"
  ]

-- Middleware templates
expressMiddleware :: Text
expressMiddleware = T.unlines
  [ "// Express.js Middleware Template"
  , "// This is a placeholder - full implementation coming in task 12.1"
  , ""
  , "const authMiddleware = (req, res, next) => {"
  , "  // Authentication middleware will be generated here"
  , "  next();"
  , "};"
  , ""
  , "module.exports = authMiddleware;"
  ]

fastapiMiddleware :: Text
fastapiMiddleware = T.unlines
  [ "# FastAPI Middleware Template"
  , "# This is a placeholder - full implementation coming in task 12.1"
  , ""
  , "from fastapi import Request, HTTPException"
  , ""
  , "async def auth_middleware(request: Request, call_next):"
  , "    # Authentication middleware will be generated here"
  , "    response = await call_next(request)"
  , "    return response"
  ]

ginMiddleware :: Text
ginMiddleware = T.unlines
  [ "// Gin Middleware Template"
  , "// This is a placeholder - full implementation coming in task 12.1"
  , ""
  , "package middleware"
  , ""
  , "import \"github.com/gin-gonic/gin\""
  , ""
  , "func AuthMiddleware() gin.HandlerFunc {"
  , "    return func(c *gin.Context) {"
  , "        // Authentication middleware will be generated here"
  , "        c.Next()"
  , "    }"
  , "}"
  ]

-- | Generate package.json for TypeScript projects
generatePackageJson :: [Dependency] -> Text
generatePackageJson deps = T.unlines $
  [ "{"
  , "  \"name\": \"auth-dsl-client\","
  , "  \"version\": \"1.0.0\","
  , "  \"description\": \"Generated TypeScript client for Auth DSL\","
  , "  \"main\": \"auth.js\","
  , "  \"types\": \"types.d.ts\","
  , "  \"scripts\": {"
  , "    \"build\": \"tsc\","
  , "    \"test\": \"jest\""
  , "  },"
  , "  \"dependencies\": {"
  ] ++ generateDependencyEntries deps ++
  [ "  },"
  , "  \"devDependencies\": {"
  , "    \"typescript\": \"^4.9.0\","
  , "    \"@types/node\": \"^18.0.0\","
  , "    \"jest\": \"^29.0.0\","
  , "    \"@types/jest\": \"^29.0.0\""
  , "  }"
  , "}"
  ]

-- | Generate dependency entries for package.json
generateDependencyEntries :: [Dependency] -> [Text]
generateDependencyEntries [] = ["    \"axios\": \"^1.0.0\""]
generateDependencyEntries deps = 
  let depEntries = map (\dep -> "    \"" <> depName dep <> "\": \"" <> depVersion dep <> "\"") deps
      lastEntry = init depEntries ++ [last depEntries]
  in map (<> ",") (init lastEntry) ++ [last lastEntry]

-- | Default auth.dl template
defaultAuthTemplate :: Text
defaultAuthTemplate = T.unlines
  [ "// Auth DSL Configuration"
  , ""
  , "provider google {"
  , "  client_id = \"${GOOGLE_CLIENT_ID}\""
  , "  client_secret = \"${GOOGLE_CLIENT_SECRET}\""
  , "  scopes = [\"email\", \"profile\"]"
  , "}"
  , ""
  , "provider password {"
  , "  min_length = 8"
  , "  require_special = true"
  , "  require_numbers = true"
  , "  require_uppercase = true"
  , "}"
  , ""
  , "session {"
  , "  strategy = \"jwt\""
  , "  expiration = \"1h\""
  , "  secure = true"
  , "}"
  , ""
  , "database {"
  , "  type = \"sqlite\""
  , "  connection = \"auth.db\""
  , "}"
  , ""
  , "protect \"/api/admin\" {"
  , "  roles = [\"admin\"]"
  , "}"
  ]