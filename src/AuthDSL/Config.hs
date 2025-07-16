{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.Config
  ( RuntimeConfig(..)
  , SessionManagerConfig(..)
  , DatabaseConnectionConfig(..)
  , DatabaseConnection(..)
  , HttpConfig(..)
  , CORSConfig(..)
  , ValidationError(..)
  , ValidationResult
  , ConfigValidator(..)
  , validateConfig
  , transformToRuntime
  , resolveEnvironmentVariables
  , loadSecrets
  , validateDuration
  , establishDatabaseConnection
  , initializeSessionManager
  , createHttpConfig
  , createServerConfigWithSecurity
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Map (Map)
import qualified Data.Map as Map
import Data.List (intercalate)
import System.Environment (lookupEnv)
import Control.Monad (when)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Text.Read (readMaybe)

import AuthDSL.Types
import AuthDSL.Security (SecurityConfig(..), defaultSecurityConfig, CORSPolicy(..))

-- | Runtime configuration after validation and transformation
data RuntimeConfig = RuntimeConfig
  { httpConfig :: HttpConfig
  , authProviders :: Map ProviderName AuthProvider
  , sessionManager :: SessionManagerConfig
  , databaseConnection :: DatabaseConnectionConfig
  } deriving (Show, Eq)

-- | HTTP server configuration
data HttpConfig = HttpConfig
  { httpPort :: Int
  , httpHost :: Text
  , httpTLS :: Bool
  , httpCORS :: CORSConfig
  } deriving (Show, Eq)

-- | CORS configuration
data CORSConfig = CORSConfig
  { corsOrigins :: [Text]
  , corsMethods :: [Text]
  , corsHeaders :: [Text]
  } deriving (Show, Eq)

-- | Session manager configuration
data SessionManagerConfig = SessionManagerConfig
  { sessionStrategy :: SessionStrategy
  , sessionExpiration :: Int -- seconds
  , sessionSecure :: Bool
  } deriving (Show, Eq)

-- | Database connection configuration
data DatabaseConnectionConfig = DatabaseConnectionConfig
  { dbConnType :: DatabaseType
  , dbConnString :: Text
  , dbConnPoolSize :: Int
  } deriving (Show, Eq)

-- | Validation error type with detailed error reporting
data ValidationError
  = MissingProvider Text
  | InvalidConfiguration Text Text -- field name, error message
  | DatabaseConnectionError Text
  | SecretResolutionError Text Text -- secret name, error message
  | EnvironmentVariableError Text Text -- variable name, error message
  | ValidationErrors [ValidationError] -- multiple validation errors
  | ProviderValidationError ProviderName ValidationError
  | SessionValidationError ValidationError
  | DatabaseValidationError ValidationError
  | DurationValidationError Text Text -- field name, error message
  deriving (Show, Eq)

-- | Type alias for validation results
type ValidationResult a = Either ValidationError a

-- | Configuration validator typeclass
class ConfigValidator a where
  validate :: a -> ValidationResult a

-- | Validate AuthConfig with comprehensive error collection
instance ConfigValidator AuthConfig where
  validate config = do
    let errors = collectValidationErrors config
    if null errors
      then Right config
      else Left (ValidationErrors errors)
    where
      collectValidationErrors cfg = concat
        [ validateProviders (providers cfg)
        , validateSession (session cfg)
        , validateDatabase (database cfg)
        , validateProtectRules (protect cfg)
        ]

-- | Validate authentication providers
validateProviders :: [AuthProvider] -> [ValidationError]
validateProviders [] = [MissingProvider "At least one authentication provider is required"]
validateProviders providers = concatMap validateProvider providers

-- | Validate individual authentication provider
validateProvider :: AuthProvider -> [ValidationError]
validateProvider (GoogleOAuth config) = map (ProviderValidationError "google") (validateGoogleConfig config)
validateProvider (PasswordAuth config) = map (ProviderValidationError "password") (validatePasswordConfig config)

-- | Validate Google OAuth configuration
validateGoogleConfig :: GoogleConfig -> [ValidationError]
validateGoogleConfig config = concat
  [ validateRequired "googleClientId" (googleClientId config)
  , validateRequired "googleClientSecret" (googleClientSecret config)
  , validateScopes "googleScopes" (googleScopes config)
  , validateRedirectUri (googleRedirectUri config)
  ]

-- | Validate password authentication configuration
validatePasswordConfig :: PasswordConfig -> [ValidationError]
validatePasswordConfig config = concat
  [ validatePasswordLength (passwordMinLength config)
  , validateMaxAttempts (passwordMaxAttempts config)
  , validateDuration "passwordLockoutDuration" (passwordLockoutDuration config)
  ]

-- | Validate session configuration
validateSession :: SessionConfig -> [ValidationError]
validateSession config = map SessionValidationError $ concat
  [ validateSessionStrategy (strategy config)
  , validateDuration "expiration" (expiration config)
  , validateSameSite (sameSite config)
  ]

-- | Validate session strategy
validateSessionStrategy :: SessionStrategy -> [ValidationError]
validateSessionStrategy (StoreJWT config) = validateJWTConfig config
validateSessionStrategy (StoreCookie config) = validateCookieConfig config

-- | Validate JWT configuration
validateJWTConfig :: JWTConfig -> [ValidationError]
validateJWTConfig config = concat
  [ validateRequired "jwtSecret" (jwtSecret config)
  , validateJWTAlgorithm (jwtAlgorithm config)
  ]

-- | Validate cookie configuration
validateCookieConfig :: CookieConfig -> [ValidationError]
validateCookieConfig config = concat
  [ validateRequired "cookieName" (cookieName config)
  , validateCookiePath (cookiePath config)
  , maybe [] (\d -> validateDuration "cookieMaxAge" d) (cookieMaxAge config)
  ]

-- | Validate database configuration
validateDatabase :: DatabaseConfig -> [ValidationError]
validateDatabase config = map DatabaseValidationError $ concat
  [ validateRequired "dbConnectionString" (dbConnectionString config)
  , validatePoolSize (dbPoolSize config)
  , validateDuration "dbTimeout" (dbTimeout config)
  , validateDatabaseType (dbType config) (dbConnectionString config)
  ]

-- | Validate protect rules
validateProtectRules :: [ProtectRule] -> [ValidationError]
validateProtectRules = concatMap validateProtectRule

-- | Validate individual protect rule
validateProtectRule :: ProtectRule -> [ValidationError]
validateProtectRule rule = concat
  [ validateRequired "protectPath" (protectPath rule)
  , validateHttpMethods (protectMethods rule)
  ]

-- Helper validation functions

-- | Validate required text field
validateRequired :: Text -> Text -> [ValidationError]
validateRequired fieldName value
  | T.null (T.strip value) = [InvalidConfiguration fieldName "Field is required and cannot be empty"]
  | otherwise = []

-- | Validate scopes list
validateScopes :: Text -> [Scope] -> [ValidationError]
validateScopes fieldName scopes
  | null scopes = [InvalidConfiguration fieldName "At least one scope is required"]
  | any T.null scopes = [InvalidConfiguration fieldName "Scopes cannot be empty"]
  | otherwise = []

-- | Validate redirect URI
validateRedirectUri :: Maybe Text -> [ValidationError]
validateRedirectUri Nothing = []
validateRedirectUri (Just uri)
  | T.null (T.strip uri) = [InvalidConfiguration "googleRedirectUri" "Redirect URI cannot be empty if provided"]
  | not (T.isPrefixOf "http" uri) = [InvalidConfiguration "googleRedirectUri" "Redirect URI must start with http:// or https://"]
  | otherwise = []

-- | Validate password minimum length
validatePasswordLength :: Int -> [ValidationError]
validatePasswordLength len
  | len < 8 = [InvalidConfiguration "passwordMinLength" "Password minimum length must be at least 8 characters"]
  | len > 128 = [InvalidConfiguration "passwordMinLength" "Password minimum length cannot exceed 128 characters"]
  | otherwise = []

-- | Validate maximum login attempts
validateMaxAttempts :: Int -> [ValidationError]
validateMaxAttempts attempts
  | attempts < 1 = [InvalidConfiguration "passwordMaxAttempts" "Maximum attempts must be at least 1"]
  | attempts > 100 = [InvalidConfiguration "passwordMaxAttempts" "Maximum attempts cannot exceed 100"]
  | otherwise = []

-- | Validate duration configuration
validateDuration :: Text -> Duration -> [ValidationError]
validateDuration fieldName (Duration value unit)
  | value <= 0 = [DurationValidationError fieldName "Duration value must be positive"]
  | unit `notElem` validUnits = [DurationValidationError fieldName ("Invalid duration unit. Must be one of: " <> T.intercalate ", " validUnits)]
  | otherwise = []
  where
    validUnits = ["seconds", "minutes", "hours", "days"]

-- | Validate JWT algorithm
validateJWTAlgorithm :: Text -> [ValidationError]
validateJWTAlgorithm algo
  | algo `notElem` validAlgos = [InvalidConfiguration "jwtAlgorithm" ("Invalid JWT algorithm. Must be one of: " <> T.intercalate ", " validAlgos)]
  | otherwise = []
  where
    validAlgos = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]

-- | Validate SameSite attribute
validateSameSite :: Text -> [ValidationError]
validateSameSite sameSite
  | sameSite `notElem` validValues = [InvalidConfiguration "sameSite" ("Invalid SameSite value. Must be one of: " <> T.intercalate ", " validValues)]
  | otherwise = []
  where
    validValues = ["Strict", "Lax", "None"]

-- | Validate cookie path
validateCookiePath :: Text -> [ValidationError]
validateCookiePath path
  | T.null path = [InvalidConfiguration "cookiePath" "Cookie path cannot be empty"]
  | not (T.isPrefixOf "/" path) = [InvalidConfiguration "cookiePath" "Cookie path must start with /"]
  | otherwise = []

-- | Validate database pool size
validatePoolSize :: Int -> [ValidationError]
validatePoolSize size
  | size < 1 = [InvalidConfiguration "dbPoolSize" "Database pool size must be at least 1"]
  | size > 100 = [InvalidConfiguration "dbPoolSize" "Database pool size cannot exceed 100"]
  | otherwise = []

-- | Validate database type and connection string compatibility
validateDatabaseType :: DatabaseType -> Text -> [ValidationError]
validateDatabaseType SQLite connStr
  | T.null connStr = [DatabaseConnectionError "SQLite connection string cannot be empty"]
  | otherwise = []
validateDatabaseType PostgreSQL connStr
  | T.null connStr = [DatabaseConnectionError "PostgreSQL connection string cannot be empty"]
  | not (T.isInfixOf "postgresql://" connStr || T.isInfixOf "postgres://" connStr) = 
      [DatabaseConnectionError "PostgreSQL connection string must start with postgresql:// or postgres://"]
  | otherwise = []
validateDatabaseType Supabase connStr
  | T.null connStr = [DatabaseConnectionError "Supabase connection string cannot be empty"]
  | not (T.isInfixOf "supabase" connStr) = 
      [DatabaseConnectionError "Supabase connection string must contain 'supabase'"]
  | otherwise = []

-- | Validate HTTP methods
validateHttpMethods :: [Text] -> [ValidationError]
validateHttpMethods methods
  | null methods = [InvalidConfiguration "protectMethods" "At least one HTTP method is required"]
  | any (`notElem` validMethods) methods = [InvalidConfiguration "protectMethods" ("Invalid HTTP method. Must be one of: " <> T.intercalate ", " validMethods)]
  | otherwise = []
  where
    validMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

-- | Validate and transform AuthConfig to RuntimeConfig
validateConfig :: AuthConfig -> Either ValidationError AuthConfig
validateConfig = validate

-- | Transform validated AuthConfig to RuntimeConfig with database connection establishment
transformToRuntime :: MonadIO m => AuthConfig -> m (ValidationResult RuntimeConfig)
transformToRuntime config = do
  -- Establish database connection
  dbConnResult <- establishDatabaseConnection (database config)
  case dbConnResult of
    Left err -> return $ Left err
    Right dbConn -> do
      -- Initialize session manager with database connection
      sessionMgrResult <- initializeSessionManager (session config) dbConn
      case sessionMgrResult of
        Left err -> return $ Left err
        Right sessionMgr -> return $ Right RuntimeConfig
          { httpConfig = createHttpConfig config
          , authProviders = Map.fromList $ map providerToTuple (providers config)
          , sessionManager = sessionMgr
          , databaseConnection = dbToConnectionConfig (database config)
          }
  where
    providerToTuple provider = case provider of
      GoogleOAuth _ -> ("google", provider)
      PasswordAuth _ -> ("password", provider)

-- | Default HTTP configuration
defaultHttpConfig :: HttpConfig
defaultHttpConfig = HttpConfig
  { httpPort = 8080
  , httpHost = "localhost"
  , httpTLS = False
  , httpCORS = defaultCORSConfig
  }

-- | Default CORS configuration
defaultCORSConfig :: CORSConfig
defaultCORSConfig = CORSConfig
  { corsOrigins = ["*"]
  , corsMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  , corsHeaders = ["Content-Type", "Authorization"]
  }

-- | Convert SessionConfig to SessionManagerConfig
sessionToManagerConfig :: SessionConfig -> SessionManagerConfig
sessionToManagerConfig config = SessionManagerConfig
  { sessionStrategy = strategy config
  , sessionExpiration = durationToSeconds (expiration config)
  , sessionSecure = secure config
  }

-- | Convert DatabaseConfig to DatabaseConnectionConfig
dbToConnectionConfig :: DatabaseConfig -> DatabaseConnectionConfig
dbToConnectionConfig config = DatabaseConnectionConfig
  { dbConnType = dbType config
  , dbConnString = dbConnectionString config
  , dbConnPoolSize = dbPoolSize config
  }

-- | Convert Duration to seconds
durationToSeconds :: Duration -> Int
durationToSeconds (Duration value unit) = case unit of
  "seconds" -> value
  "minutes" -> value * 60
  "hours" -> value * 3600
  "days" -> value * 86400
  _ -> value -- default to seconds

-- | Resolve environment variables in configuration
resolveEnvironmentVariables :: MonadIO m => AuthConfig -> m (ValidationResult AuthConfig)
resolveEnvironmentVariables config = do
  resolvedProviders <- mapM resolveProviderEnvVars (providers config)
  resolvedSession <- resolveSessionEnvVars (session config)
  resolvedDatabase <- resolveDatabaseEnvVars (database config)
  
  case sequence resolvedProviders of
    Left err -> return $ Left err
    Right providers' -> 
      case resolvedSession of
        Left err -> return $ Left err
        Right session' ->
          case resolvedDatabase of
            Left err -> return $ Left err
            Right database' -> return $ Right config
              { providers = providers'
              , session = session'
              , database = database'
              }

-- | Resolve environment variables in authentication providers
resolveProviderEnvVars :: MonadIO m => AuthProvider -> m (ValidationResult AuthProvider)
resolveProviderEnvVars (GoogleOAuth config) = do
  clientId <- resolveEnvVar (googleClientId config)
  clientSecret <- resolveEnvVar (googleClientSecret config)
  redirectUri <- maybe (return $ Right Nothing) 
                       (\uri -> fmap (fmap Just) (resolveEnvVar uri)) 
                       (googleRedirectUri config)
  
  case (clientId, clientSecret, redirectUri) of
    (Right cid, Right cs, Right ru) -> return $ Right $ GoogleOAuth config
      { googleClientId = cid
      , googleClientSecret = cs
      , googleRedirectUri = ru
      }
    (Left err, _, _) -> return $ Left err
    (_, Left err, _) -> return $ Left err
    (_, _, Left err) -> return $ Left err

resolveProviderEnvVars (PasswordAuth config) = return $ Right (PasswordAuth config)

-- | Resolve environment variables in session configuration
resolveSessionEnvVars :: MonadIO m => SessionConfig -> m (ValidationResult SessionConfig)
resolveSessionEnvVars config = do
  resolvedStrategy <- resolveStrategyEnvVars (strategy config)
  case resolvedStrategy of
    Left err -> return $ Left err
    Right strategy' -> return $ Right config { strategy = strategy' }

-- | Resolve environment variables in session strategy
resolveStrategyEnvVars :: MonadIO m => SessionStrategy -> m (ValidationResult SessionStrategy)
resolveStrategyEnvVars (StoreJWT config) = do
  secret <- resolveEnvVar (jwtSecret config)
  issuer <- maybe (return $ Right Nothing)
                  (\iss -> fmap (fmap Just) (resolveEnvVar iss))
                  (jwtIssuer config)
  audience <- maybe (return $ Right Nothing)
                    (\aud -> fmap (fmap Just) (resolveEnvVar aud))
                    (jwtAudience config)
  
  case (secret, issuer, audience) of
    (Right s, Right i, Right a) -> return $ Right $ StoreJWT config
      { jwtSecret = s
      , jwtIssuer = i
      , jwtAudience = a
      }
    (Left err, _, _) -> return $ Left err
    (_, Left err, _) -> return $ Left err
    (_, _, Left err) -> return $ Left err

resolveStrategyEnvVars (StoreCookie config) = do
  domain <- maybe (return $ Right Nothing)
                  (\d -> fmap (fmap Just) (resolveEnvVar d))
                  (cookieDomain config)
  case domain of
    Right d -> return $ Right $ StoreCookie config { cookieDomain = d }
    Left err -> return $ Left err

-- | Resolve environment variables in database configuration
resolveDatabaseEnvVars :: MonadIO m => DatabaseConfig -> m (ValidationResult DatabaseConfig)
resolveDatabaseEnvVars config = do
  connStr <- resolveEnvVar (dbConnectionString config)
  case connStr of
    Right cs -> return $ Right config { dbConnectionString = cs }
    Left err -> return $ Left err

-- | Resolve a single environment variable
resolveEnvVar :: MonadIO m => Text -> m (ValidationResult Text)
resolveEnvVar value
  | T.isPrefixOf "${" value && T.isSuffixOf "}" value = do
      let envVarName = T.drop 2 $ T.dropEnd 1 value
      maybeValue <- liftIO $ lookupEnv (T.unpack envVarName)
      case maybeValue of
        Just envValue -> return $ Right (T.pack envValue)
        Nothing -> return $ Left $ EnvironmentVariableError envVarName "Environment variable not found"
  | otherwise = return $ Right value

-- | Load secrets from external secret management systems
loadSecrets :: MonadIO m => AuthConfig -> m (ValidationResult AuthConfig)
loadSecrets config = do
  -- For now, this is a placeholder that could be extended to support
  -- AWS KMS, HashiCorp Vault, or other secret management systems
  resolvedProviders <- mapM loadProviderSecrets (providers config)
  resolvedSession <- loadSessionSecrets (session config)
  resolvedDatabase <- loadDatabaseSecrets (database config)
  
  case sequence resolvedProviders of
    Left err -> return $ Left err
    Right providers' ->
      case resolvedSession of
        Left err -> return $ Left err
        Right session' ->
          case resolvedDatabase of
            Left err -> return $ Left err
            Right database' -> return $ Right config
              { providers = providers'
              , session = session'
              , database = database'
              }

-- | Load secrets for authentication providers
loadProviderSecrets :: MonadIO m => AuthProvider -> m (ValidationResult AuthProvider)
loadProviderSecrets (GoogleOAuth config) = do
  clientSecret <- loadSecret (googleClientSecret config)
  case clientSecret of
    Right cs -> return $ Right $ GoogleOAuth config { googleClientSecret = cs }
    Left err -> return $ Left err

loadProviderSecrets (PasswordAuth config) = return $ Right (PasswordAuth config)

-- | Load secrets for session configuration
loadSessionSecrets :: MonadIO m => SessionConfig -> m (ValidationResult SessionConfig)
loadSessionSecrets config = do
  resolvedStrategy <- loadStrategySecrets (strategy config)
  case resolvedStrategy of
    Left err -> return $ Left err
    Right strategy' -> return $ Right config { strategy = strategy' }

-- | Load secrets for session strategy
loadStrategySecrets :: MonadIO m => SessionStrategy -> m (ValidationResult SessionStrategy)
loadStrategySecrets (StoreJWT config) = do
  secret <- loadSecret (jwtSecret config)
  case secret of
    Right s -> return $ Right $ StoreJWT config { jwtSecret = s }
    Left err -> return $ Left err

loadStrategySecrets (StoreCookie config) = return $ Right (StoreCookie config)

-- | Load secrets for database configuration
loadDatabaseSecrets :: MonadIO m => DatabaseConfig -> m (ValidationResult DatabaseConfig)
loadDatabaseSecrets config = do
  connStr <- loadSecret (dbConnectionString config)
  case connStr of
    Right cs -> return $ Right config { dbConnectionString = cs }
    Left err -> return $ Left err

-- | Load a single secret (placeholder implementation)
loadSecret :: MonadIO m => Text -> m (ValidationResult Text)
loadSecret value
  | T.isPrefixOf "kms://" value = do
      -- Placeholder for KMS integration
      return $ Left $ SecretResolutionError value "KMS integration not yet implemented"
  | T.isPrefixOf "vault://" value = do
      -- Placeholder for Vault integration
      return $ Left $ SecretResolutionError value "Vault integration not yet implemented"
  | otherwise = return $ Right value

-- Runtime Configuration Transformation Functions

-- | Database connection handle (placeholder for actual database connections)
data DatabaseConnection = DatabaseConnection
  { dbConnHandle :: Text -- Placeholder for actual connection handle
  , dbConnType' :: DatabaseType
  , dbConnPool :: Int
  } deriving (Show, Eq)

-- | Establish database connection based on configuration
establishDatabaseConnection :: MonadIO m => DatabaseConfig -> m (ValidationResult DatabaseConnection)
establishDatabaseConnection config = do
  -- For now, this is a placeholder implementation
  -- In a real implementation, this would establish actual database connections
  case dbType config of
    SQLite -> do
      -- Validate SQLite file path and create connection
      let connStr = dbConnectionString config
      if T.null connStr
        then return $ Left $ DatabaseConnectionError "SQLite connection string cannot be empty"
        else return $ Right $ DatabaseConnection
          { dbConnHandle = connStr
          , dbConnType' = SQLite
          , dbConnPool = dbPoolSize config
          }
    
    PostgreSQL -> do
      -- Validate PostgreSQL connection string and establish connection
      let connStr = dbConnectionString config
      if not (T.isInfixOf "postgresql://" connStr || T.isInfixOf "postgres://" connStr)
        then return $ Left $ DatabaseConnectionError "Invalid PostgreSQL connection string format"
        else return $ Right $ DatabaseConnection
          { dbConnHandle = connStr
          , dbConnType' = PostgreSQL
          , dbConnPool = dbPoolSize config
          }
    
    Supabase -> do
      -- Validate Supabase connection string and establish connection
      let connStr = dbConnectionString config
      if not (T.isInfixOf "supabase" connStr)
        then return $ Left $ DatabaseConnectionError "Invalid Supabase connection string format"
        else return $ Right $ DatabaseConnection
          { dbConnHandle = connStr
          , dbConnType' = Supabase
          , dbConnPool = dbPoolSize config
          }

-- | Initialize session manager based on strategy and database connection
initializeSessionManager :: MonadIO m => SessionConfig -> DatabaseConnection -> m (ValidationResult SessionManagerConfig)
initializeSessionManager sessionConfig dbConn = do
  -- Validate session strategy compatibility with database
  case strategy sessionConfig of
    StoreJWT jwtConfig -> do
      -- JWT sessions don't require database storage, but validate JWT config
      if T.null (jwtSecret jwtConfig)
        then return $ Left $ SessionValidationError $ InvalidConfiguration "jwtSecret" "JWT secret cannot be empty"
        else return $ Right $ SessionManagerConfig
          { sessionStrategy = StoreJWT jwtConfig
          , sessionExpiration = durationToSeconds (expiration sessionConfig)
          , sessionSecure = secure sessionConfig
          }
    
    StoreCookie cookieConfig -> do
      -- Cookie sessions require database storage for session persistence
      if T.null (cookieName cookieConfig)
        then return $ Left $ SessionValidationError $ InvalidConfiguration "cookieName" "Cookie name cannot be empty"
        else return $ Right $ SessionManagerConfig
          { sessionStrategy = StoreCookie cookieConfig
          , sessionExpiration = durationToSeconds (expiration sessionConfig)
          , sessionSecure = secure sessionConfig
          }

-- | Create HTTP configuration from AuthConfig
createHttpConfig :: AuthConfig -> HttpConfig
createHttpConfig config = HttpConfig
  { httpPort = 8080 -- Default port, could be configurable
  , httpHost = "localhost" -- Default host, could be configurable
  , httpTLS = False -- Default to HTTP, could be inferred from environment
  , httpCORS = createCORSConfig config
  }

-- | Create CORS configuration based on protect rules and providers
createCORSConfig :: AuthConfig -> CORSConfig
createCORSConfig config = CORSConfig
  { corsOrigins = extractOrigins config
  , corsMethods = extractMethods config
  , corsHeaders = defaultHeaders
  }
  where
    -- Extract allowed origins from OAuth redirect URIs
    extractOrigins cfg = case providers cfg of
      [] -> ["*"] -- Default to allow all origins if no providers
      provs -> concatMap extractProviderOrigins provs ++ ["*"]
    
    extractProviderOrigins (GoogleOAuth googleConfig) = 
      case googleRedirectUri googleConfig of
        Just uri -> [extractOriginFromUri uri]
        Nothing -> []
    extractProviderOrigins (PasswordAuth _) = []
    
    extractOriginFromUri uri = 
      let parts = T.splitOn "/" uri
      in if length parts >= 3
         then T.intercalate "/" (take 3 parts)
         else uri
    
    -- Extract HTTP methods from protect rules
    extractMethods cfg = case protect cfg of
      [] -> defaultMethods
      rules -> concatMap protectMethods rules ++ defaultMethods
    
    defaultMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    defaultHeaders = ["Content-Type", "Authorization", "X-Requested-With"]

-- | Create ServerConfig with security settings based on AuthConfig
createServerConfigWithSecurity :: RuntimeConfig -> SecurityConfig
createServerConfigWithSecurity runtimeConfig = 
  let httpConf = httpConfig runtimeConfig
      corsConf = httpCORS httpConf
      defaultSec = defaultSecurityConfig
  in defaultSec
    { secCORS = (secCORS defaultSec)
        { corsAllowedOrigins = corsOrigins corsConf
        , corsAllowedMethods = corsMethods corsConf  
        , corsAllowedHeaders = corsHeaders corsConf
        }
    }