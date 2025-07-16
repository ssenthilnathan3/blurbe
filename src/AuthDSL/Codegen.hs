{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.Codegen
  ( CodeGenerator(..)
  , GeneratedCode(..)
  , TypeDefinitions(..)
  , ClientSDK(..)
  , BuildConfig(..)
  , Dependency(..)
  , TargetLanguage(..)
  , generateForLanguage
  ) where

import Data.Text (Text)
import qualified Data.Text as T

import AuthDSL.Types

-- | Target programming languages for code generation
data TargetLanguage
  = TypeScript
  | Python
  | Go
  deriving (Show, Eq)

-- | Generated code output
data GeneratedCode = GeneratedCode
  { sourceFiles :: [(FilePath, Text)]
  , dependencies :: [Dependency]
  , buildInstructions :: BuildConfig
  } deriving (Show, Eq)

-- | Type definitions for target language
data TypeDefinitions = TypeDefinitions
  { typeFiles :: [(FilePath, Text)]
  , typeImports :: [Text]
  } deriving (Show, Eq)

-- | Client SDK output
data ClientSDK = ClientSDK
  { sdkFiles :: [(FilePath, Text)]
  , sdkDependencies :: [Dependency]
  , sdkDocumentation :: Text
  } deriving (Show, Eq)

-- | Build configuration
data BuildConfig = BuildConfig
  { buildCommands :: [Text]
  , buildOutputDirectory :: FilePath
  , buildArtifacts :: [FilePath]
  } deriving (Show, Eq)

-- | Dependency specification
data Dependency = Dependency
  { depName :: Text
  , depVersion :: Text
  , depType :: Text -- "npm", "pip", "go mod"
  } deriving (Show, Eq)

-- | Code generator typeclass
class CodeGenerator lang where
  generateAuth :: AuthConfig -> lang -> IO GeneratedCode
  generateTypes :: AuthConfig -> lang -> IO TypeDefinitions
  generateClient :: AuthConfig -> lang -> IO ClientSDK

-- | TypeScript code generator
instance CodeGenerator TargetLanguage where
  generateAuth config TypeScript = do
    -- Placeholder implementation - will be expanded in task 10.1
    let authFile = ("auth.ts", generateTypeScriptAuth config)
    return $ GeneratedCode
      { sourceFiles = [authFile]
      , dependencies = [Dependency "axios" "^1.0.0" "npm"]
      , buildInstructions = BuildConfig ["npm install", "npm run build"] "dist" ["dist/auth.js"]
      }
  
  generateAuth config Python = do
    -- Placeholder implementation - will be expanded in task 10.2
    let authFile = ("auth.py", generatePythonAuth config)
    return $ GeneratedCode
      { sourceFiles = [authFile]
      , dependencies = [Dependency "requests" "^2.28.0" "pip"]
      , buildInstructions = BuildConfig ["pip install -r requirements.txt"] "dist" ["auth.py"]
      }
  
  generateAuth config Go = do
    -- Placeholder implementation - will be expanded in task 10.2
    let authFile = ("auth.go", generateGoAuth config)
    return $ GeneratedCode
      { sourceFiles = [authFile]
      , dependencies = [Dependency "github.com/go-resty/resty/v2" "v2.7.0" "go"]
      , buildInstructions = BuildConfig ["go mod tidy", "go build"] "." ["auth"]
      }
  
  generateTypes config TypeScript = do
    -- Placeholder implementation - will be expanded in task 10.1
    let typesFile = ("types.ts", generateTypeScriptTypes config)
    return $ TypeDefinitions
      { typeFiles = [typesFile]
      , typeImports = ["export * from './types'"]
      }
  
  generateTypes config Python = do
    -- Placeholder implementation - will be expanded in task 10.2
    let typesFile = ("types.py", generatePythonTypes config)
    return $ TypeDefinitions
      { typeFiles = [typesFile]
      , typeImports = ["from .types import *"]
      }
  
  generateTypes config Go = do
    -- Placeholder implementation - will be expanded in task 10.2
    let typesFile = ("types.go", generateGoTypes config)
    return $ TypeDefinitions
      { typeFiles = [typesFile]
      , typeImports = []
      }
  
  generateClient config TypeScript = do
    -- Placeholder implementation - will be expanded in task 11.1
    let clientFile = ("client.ts", generateTypeScriptClient config)
    return $ ClientSDK
      { sdkFiles = [clientFile]
      , sdkDependencies = [Dependency "axios" "^1.0.0" "npm"]
      , sdkDocumentation = "TypeScript Auth Client SDK"
      }
  
  generateClient config Python = do
    -- Placeholder implementation - will be expanded in task 11.1
    let clientFile = ("client.py", generatePythonClient config)
    return $ ClientSDK
      { sdkFiles = [clientFile]
      , sdkDependencies = [Dependency "requests" "^2.28.0" "pip"]
      , sdkDocumentation = "Python Auth Client SDK"
      }
  
  generateClient config Go = do
    -- Placeholder implementation - will be expanded in task 11.1
    let clientFile = ("client.go", generateGoClient config)
    return $ ClientSDK
      { sdkFiles = [clientFile]
      , sdkDependencies = [Dependency "github.com/go-resty/resty/v2" "v2.7.0" "go"]
      , sdkDocumentation = "Go Auth Client SDK"
      }

-- | Generate code for specified language
generateForLanguage :: AuthConfig -> TargetLanguage -> IO GeneratedCode
generateForLanguage config lang = generateAuth config lang

-- | Generate TypeScript authentication client code
generateTypeScriptAuth :: AuthConfig -> Text
generateTypeScriptAuth config = T.unlines $
  [ "// Generated TypeScript Auth Code"
  , "// Auto-generated from auth.dl configuration"
  , ""
  , "import axios, { AxiosInstance, AxiosResponse } from 'axios';"
  , ""
  ] ++ generateTypeScriptTypes' config ++
  [ ""
  , "export interface AuthClientConfig {"
  , "  baseUrl: string;"
  , "  timeout?: number;"
  , "  headers?: Record<string, string>;"
  , "}"
  , ""
  , "export interface AuthState {"
  , "  isAuthenticated: boolean;"
  , "  user?: UserInfo;"
  , "  token?: string;"
  , "  refreshToken?: string;"
  , "  expiresAt?: Date;"
  , "}"
  , ""
  , "export class AuthClient {"
  , "  private client: AxiosInstance;"
  , "  private authState: AuthState = { isAuthenticated: false };"
  , "  private tokenRefreshPromise?: Promise<AuthResponse>;"
  , ""
  , "  constructor(private config: AuthClientConfig) {"
  , "    this.client = axios.create({"
  , "      baseURL: config.baseUrl,"
  , "      timeout: config.timeout || 10000,"
  , "      headers: {"
  , "        'Content-Type': 'application/json',"
  , "        ...config.headers"
  , "      }"
  , "    });"
  , ""
  , "    // Add request interceptor for automatic token handling"
  , "    this.client.interceptors.request.use((config) => {"
  , "      if (this.authState.token) {"
  , "        config.headers.Authorization = `Bearer ${this.authState.token}`;"
  , "      }"
  , "      return config;"
  , "    });"
  , ""
  , "    // Add response interceptor for token refresh"
  , "    this.client.interceptors.response.use("
  , "      (response) => response,"
  , "      async (error) => {"
  , "        if (error.response?.status === 401 && this.authState.refreshToken) {"
  , "          await this.refreshTokenIfNeeded();"
  , "          return this.client.request(error.config);"
  , "        }"
  , "        return Promise.reject(error);"
  , "      }"
  , "    );"
  , "  }"
  , ""
  ] ++ generateProviderMethods config ++
  [ ""
  , "  // Session management methods"
  , "  async getSession(): Promise<UserSession | null> {"
  , "    try {"
  , "      const response = await this.client.get<UserSession>('/session');"
  , "      return response.data;"
  , "    } catch (error) {"
  , "      return null;"
  , "    }"
  , "  }"
  , ""
  , "  async logout(): Promise<void> {"
  , "    try {"
  , "      await this.client.post('/logout');"
  , "    } finally {"
  , "      this.clearAuthState();"
  , "    }"
  , "  }"
  , ""
  ] ++ generateSessionMethods config ++
  [ ""
  , "  // Authentication state management"
  , "  getAuthState(): AuthState {"
  , "    return { ...this.authState };"
  , "  }"
  , ""
  , "  isAuthenticated(): boolean {"
  , "    return this.authState.isAuthenticated && !this.isTokenExpired();"
  , "  }"
  , ""
  , "  private isTokenExpired(): boolean {"
  , "    if (!this.authState.expiresAt) return false;"
  , "    return new Date() >= this.authState.expiresAt;"
  , "  }"
  , ""
  , "  private async refreshTokenIfNeeded(): Promise<AuthResponse | void> {"
  , "    if (this.tokenRefreshPromise) {"
  , "      return this.tokenRefreshPromise;"
  , "    }"
  , ""
  , "    if (!this.authState.refreshToken || !this.isTokenExpired()) {"
  , "      return;"
  , "    }"
  , ""
  , "    this.tokenRefreshPromise = this.performTokenRefresh();"
  , "    try {"
  , "      await this.tokenRefreshPromise;"
  , "    } finally {"
  , "      this.tokenRefreshPromise = undefined;"
  , "    }"
  , "  }"
  , ""
  , "  private async performTokenRefresh(): Promise<AuthResponse> {"
  , "    try {"
  , "      const response = await this.client.post<AuthResponse>('/refresh', {"
  , "        refreshToken: this.authState.refreshToken"
  , "      });"
  , "      this.updateAuthState(response.data);"
  , "      return response.data;"
  , "    } catch (error) {"
  , "      this.clearAuthState();"
  , "      throw error;"
  , "    }"
  , "  }"
  , ""
  , "  private updateAuthState(authResponse: AuthResponse): void {"
  , "    this.authState = {"
  , "      isAuthenticated: true,"
  , "      user: authResponse.user,"
  , "      token: authResponse.token,"
  , "      refreshToken: authResponse.refreshToken,"
  , "      expiresAt: authResponse.expiresAt ? new Date(authResponse.expiresAt) : undefined"
  , "    };"
  , "  }"
  , ""
  , "  private clearAuthState(): void {"
  , "    this.authState = { isAuthenticated: false };"
  , "  }"
  , "}"
  ]

-- | Placeholder Python auth code generator
generatePythonAuth :: AuthConfig -> Text
generatePythonAuth config = T.unlines
  [ "# Generated Python Auth Code"
  , "# Providers: " <> T.pack (show (length (providers config)))
  , ""
  , "class AuthClient:"
  , "    # Implementation will be added in task 10.2"
  , "    pass"
  ]

-- | Placeholder Go auth code generator
generateGoAuth :: AuthConfig -> Text
generateGoAuth config = T.unlines
  [ "// Generated Go Auth Code"
  , "// Providers: " <> T.pack (show (length (providers config)))
  , ""
  , "package auth"
  , ""
  , "type AuthClient struct {"
  , "    // Implementation will be added in task 10.2"
  , "}"
  ]

-- | Generate TypeScript type definitions
generateTypeScriptTypes :: AuthConfig -> Text
generateTypeScriptTypes config = T.unlines $ generateTypeScriptTypes' config

-- | Helper function to generate TypeScript type definitions
generateTypeScriptTypes' :: AuthConfig -> [Text]
generateTypeScriptTypes' config =
  [ "// Type definitions generated from auth.dl configuration"
  , ""
  , "export interface UserInfo {"
  , "  id: string;"
  , "  email: string;"
  , "  name?: string;"
  , "  avatar?: string;"
  , "  roles: string[];"
  , "  metadata?: Record<string, any>;"
  , "}"
  , ""
  , "export interface UserSession {"
  , "  id: string;"
  , "  userId: string;"
  , "  expiresAt: string;"
  , "  scopes: string[];"
  , "  metadata?: Record<string, any>;"
  , "}"
  , ""
  , "export interface AuthResponse {"
  , "  user: UserInfo;"
  , "  token: string;"
  , "  refreshToken?: string;"
  , "  expiresAt?: string;"
  , "}"
  , ""
  , "export interface LoginRequest {"
  , "  provider: string;"
  , "  redirectUrl?: string;"
  , "}"
  , ""
  ] ++ generateProviderTypes config ++
  [ ""
  , "export interface AuthError {"
  , "  code: string;"
  , "  message: string;"
  , "  details?: Record<string, any>;"
  , "}"
  , ""
  , "export type AuthProvider = " <> T.intercalate " | " (map getProviderTypeName (providers config)) <> ";"
  ]

-- | Generate provider-specific type definitions
generateProviderTypes :: AuthConfig -> [Text]
generateProviderTypes config = concatMap generateProviderType (providers config)

generateProviderType :: AuthProvider -> [Text]
generateProviderType (GoogleOAuth _) =
  [ "export interface GoogleAuthConfig {"
  , "  clientId: string;"
  , "  scopes: string[];"
  , "  redirectUri?: string;"
  , "}"
  , ""
  ]
generateProviderType (PasswordAuth passwordConfig) =
  [ "export interface PasswordAuthConfig {"
  , "  minLength: number;"
  , "  requireSpecial: boolean;"
  , "  requireNumbers: boolean;"
  , "  requireUppercase: boolean;"
  , "}"
  , ""
  , "export interface PasswordLoginRequest {"
  , "  email: string;"
  , "  password: string;"
  , "}"
  , ""
  , "export interface PasswordRegisterRequest {"
  , "  email: string;"
  , "  password: string;"
  , "  name?: string;"
  , "}"
  , ""
  ]

-- | Get provider type name for union type
getProviderTypeName :: AuthProvider -> Text
getProviderTypeName (GoogleOAuth _) = "'google'"
getProviderTypeName (PasswordAuth _) = "'password'"

-- | Generate provider-specific authentication methods
generateProviderMethods :: AuthConfig -> [Text]
generateProviderMethods config = concatMap generateProviderMethod (providers config)

generateProviderMethod :: AuthProvider -> [Text]
generateProviderMethod (GoogleOAuth googleConfig) =
  [ "  // Google OAuth2 authentication"
  , "  async loginWithGoogle(redirectUrl?: string): Promise<string> {"
  , "    const params = new URLSearchParams({"
  , "      provider: 'google',"
  , "      ...(redirectUrl && { redirect_url: redirectUrl })"
  , "    });"
  , "    const response = await this.client.get<{ url: string }>(`/login/google?${params}`);"
  , "    return response.data.url;"
  , "  }"
  , ""
  , "  async handleGoogleCallback(code: string, state?: string): Promise<AuthResponse> {"
  , "    const response = await this.client.post<AuthResponse>('/callback/google', {"
  , "      code,"
  , "      state"
  , "    });"
  , "    this.updateAuthState(response.data);"
  , "    return response.data;"
  , "  }"
  ]

generateProviderMethod (PasswordAuth passwordConfig) =
  [ "  // Password-based authentication"
  , "  async loginWithPassword(email: string, password: string): Promise<AuthResponse> {"
  , "    const response = await this.client.post<AuthResponse>('/login/password', {"
  , "      email,"
  , "      password"
  , "    });"
  , "    this.updateAuthState(response.data);"
  , "    return response.data;"
  , "  }"
  , ""
  , "  async registerWithPassword(request: PasswordRegisterRequest): Promise<AuthResponse> {"
  , "    const response = await this.client.post<AuthResponse>('/register', request);"
  , "    this.updateAuthState(response.data);"
  , "    return response.data;"
  , "  }"
  , ""
  , "  validatePassword(password: string): { valid: boolean; errors: string[] } {"
  , "    const errors: string[] = [];"
  , ""
  , "    if (password.length < " <> T.pack (show (passwordMinLength passwordConfig)) <> ") {"
  , "      errors.push('Password must be at least " <> T.pack (show (passwordMinLength passwordConfig)) <> " characters long');"
  , "    }"
  , ""
  ] ++ generatePasswordValidation passwordConfig ++
  [ ""
  , "    return { valid: errors.length === 0, errors };"
  , "  }"
  ]

-- | Generate password validation rules
generatePasswordValidation :: PasswordConfig -> [Text]
generatePasswordValidation config = 
  (if passwordRequireUppercase config then
    [ "    if (!/[A-Z]/.test(password)) {"
    , "      errors.push('Password must contain at least one uppercase letter');"
    , "    }"
    , ""
    ] else []) ++
  (if passwordRequireNumbers config then
    [ "    if (!/\\d/.test(password)) {"
    , "      errors.push('Password must contain at least one number');"
    , "    }"
    , ""
    ] else []) ++
  (if passwordRequireSpecial config then
    [ "    if (!/[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]/.test(password)) {"
    , "      errors.push('Password must contain at least one special character');"
    , "    }"
    , ""
    ] else [])

-- | Generate session-specific methods based on session strategy
generateSessionMethods :: AuthConfig -> [Text]
generateSessionMethods config = 
  case strategy (session config) of
    StoreJWT jwtConfig -> generateJWTSessionMethods jwtConfig
    StoreCookie cookieConfig -> generateCookieSessionMethods cookieConfig

-- | Generate JWT-specific session methods
generateJWTSessionMethods :: JWTConfig -> [Text]
generateJWTSessionMethods jwtConfig =
  [ "  // JWT session management"
  , "  setToken(token: string, refreshToken?: string, expiresAt?: string): void {"
  , "    this.authState.token = token;"
  , "    this.authState.refreshToken = refreshToken;"
  , "    this.authState.expiresAt = expiresAt ? new Date(expiresAt) : undefined;"
  , "    this.authState.isAuthenticated = true;"
  , "  }"
  , ""
  , "  getToken(): string | undefined {"
  , "    return this.authState.token;"
  , "  }"
  , ""
  , "  getRefreshToken(): string | undefined {"
  , "    return this.authState.refreshToken;"
  , "  }"
  ] ++ (if jwtRefreshEnabled jwtConfig then
    [ ""
    , "  async refreshToken(): Promise<AuthResponse> {"
    , "    if (!this.authState.refreshToken) {"
    , "      throw new Error('No refresh token available');"
    , "    }"
    , "    return this.performTokenRefresh();"
    , "  }"
    ] else [])

-- | Generate cookie-specific session methods
generateCookieSessionMethods :: CookieConfig -> [Text]
generateCookieSessionMethods cookieConfig =
  [ "  // Cookie session management"
  , "  async validateSession(): Promise<boolean> {"
  , "    try {"
  , "      const session = await this.getSession();"
  , "      if (session) {"
  , "        this.authState.isAuthenticated = true;"
  , "        return true;"
  , "      }"
  , "      return false;"
  , "    } catch (error) {"
  , "      return false;"
  , "    }"
  , "  }"
  , ""
  , "  getCookieName(): string {"
  , "    return '" <> cookieName cookieConfig <> "';"
  , "  }"
  ]

generatePythonTypes :: AuthConfig -> Text
generatePythonTypes _ = "# Python types - will be implemented in task 10.2"

generateGoTypes :: AuthConfig -> Text
generateGoTypes _ = "// Go types - will be implemented in task 10.2"

-- | Placeholder client generators
generateTypeScriptClient :: AuthConfig -> Text
generateTypeScriptClient _ = "// TypeScript client - will be implemented in task 11.1"

generatePythonClient :: AuthConfig -> Text
generatePythonClient _ = "# Python client - will be implemented in task 11.1"

generateGoClient :: AuthConfig -> Text
generateGoClient _ = "// Go client - will be implemented in task 11.1"