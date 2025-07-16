{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.ConfigSpec (spec) where

import Test.Hspec
import Test.QuickCheck
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Map as Map

import AuthDSL.Types
import AuthDSL.Config

spec :: Spec
spec = do
  describe "ConfigValidator" $ do
    describe "AuthConfig validation" $ do
      it "validates a complete valid configuration" $ do
        let config = validAuthConfig
        validate config `shouldBe` Right config

      it "rejects configuration with no providers" $ do
        let config = validAuthConfig { providers = [] }
        case validate config of
          Left (ValidationErrors errors) -> 
            errors `shouldContain` [MissingProvider "At least one authentication provider is required"]
          _ -> expectationFailure "Expected ValidationErrors with MissingProvider"

      it "validates Google OAuth provider configuration" $ do
        let googleConfig = GoogleConfig
              { googleClientId = "client123"
              , googleClientSecret = "secret456"
              , googleScopes = ["openid", "email"]
              , googleRedirectUri = Just "https://example.com/callback"
              }
        let config = validAuthConfig { providers = [GoogleOAuth googleConfig] }
        validate config `shouldBe` Right config

      it "rejects Google OAuth with empty client ID" $ do
        let googleConfig = GoogleConfig
              { googleClientId = ""
              , googleClientSecret = "secret456"
              , googleScopes = ["openid", "email"]
              , googleRedirectUri = Nothing
              }
        let config = validAuthConfig { providers = [GoogleOAuth googleConfig] }
        case validate config of
          Left (ValidationErrors errors) -> 
            any isGoogleClientIdError errors `shouldBe` True
          _ -> expectationFailure "Expected validation error for empty client ID"

      it "rejects Google OAuth with invalid redirect URI" $ do
        let googleConfig = GoogleConfig
              { googleClientId = "client123"
              , googleClientSecret = "secret456"
              , googleScopes = ["openid", "email"]
              , googleRedirectUri = Just "invalid-uri"
              }
        let config = validAuthConfig { providers = [GoogleOAuth googleConfig] }
        case validate config of
          Left (ValidationErrors errors) -> 
            any isRedirectUriError errors `shouldBe` True
          _ -> expectationFailure "Expected validation error for invalid redirect URI"

    describe "Password authentication validation" $ do
      it "validates password configuration with valid settings" $ do
        let passwordConfig = PasswordConfig
              { passwordMinLength = 12
              , passwordRequireSpecial = True
              , passwordRequireNumbers = True
              , passwordRequireUppercase = True
              , passwordMaxAttempts = 5
              , passwordLockoutDuration = Duration 15 "minutes"
              }
        let config = validAuthConfig { providers = [PasswordAuth passwordConfig] }
        validate config `shouldBe` Right config

      it "rejects password configuration with too short minimum length" $ do
        let passwordConfig = PasswordConfig
              { passwordMinLength = 4
              , passwordRequireSpecial = True
              , passwordRequireNumbers = True
              , passwordRequireUppercase = True
              , passwordMaxAttempts = 5
              , passwordLockoutDuration = Duration 15 "minutes"
              }
        let config = validAuthConfig { providers = [PasswordAuth passwordConfig] }
        case validate config of
          Left (ValidationErrors errors) -> 
            any isPasswordLengthError errors `shouldBe` True
          _ -> expectationFailure "Expected validation error for short password length"

    describe "Session configuration validation" $ do
      it "validates JWT session strategy" $ do
        let jwtConfig = JWTConfig
              { jwtSecret = "super-secret-key"
              , jwtAlgorithm = "HS256"
              , jwtIssuer = Just "auth-dsl"
              , jwtAudience = Just "my-app"
              , jwtRefreshEnabled = True
              }
        let sessionConfig = SessionConfig
              { strategy = StoreJWT jwtConfig
              , expiration = Duration 24 "hours"
              , secure = True
              , sameSite = "Strict"
              , httpOnly = True
              }
        let config = validAuthConfig { session = sessionConfig }
        validate config `shouldBe` Right config

      it "rejects JWT with invalid algorithm" $ do
        let jwtConfig = JWTConfig
              { jwtSecret = "super-secret-key"
              , jwtAlgorithm = "INVALID"
              , jwtIssuer = Nothing
              , jwtAudience = Nothing
              , jwtRefreshEnabled = False
              }
        let sessionConfig = validSessionConfig { strategy = StoreJWT jwtConfig }
        let config = validAuthConfig { session = sessionConfig }
        case validate config of
          Left (ValidationErrors errors) -> 
            any isJWTAlgorithmError errors `shouldBe` True
          _ -> expectationFailure "Expected validation error for invalid JWT algorithm"

      it "validates cookie session strategy" $ do
        let cookieConfig = CookieConfig
              { cookieName = "auth_session"
              , cookieDomain = Just "example.com"
              , cookiePath = "/"
              , cookieMaxAge = Just (Duration 7 "days")
              }
        let sessionConfig = SessionConfig
              { strategy = StoreCookie cookieConfig
              , expiration = Duration 24 "hours"
              , secure = True
              , sameSite = "Lax"
              , httpOnly = True
              }
        let config = validAuthConfig { session = sessionConfig }
        validate config `shouldBe` Right config

      it "rejects cookie with invalid path" $ do
        let cookieConfig = CookieConfig
              { cookieName = "auth_session"
              , cookieDomain = Nothing
              , cookiePath = "invalid-path"
              , cookieMaxAge = Nothing
              }
        let sessionConfig = validSessionConfig { strategy = StoreCookie cookieConfig }
        let config = validAuthConfig { session = sessionConfig }
        case validate config of
          Left (ValidationErrors errors) -> 
            any isCookiePathError errors `shouldBe` True
          _ -> expectationFailure "Expected validation error for invalid cookie path"

    describe "Database configuration validation" $ do
      it "validates SQLite database configuration" $ do
        let dbConfig = DatabaseConfig
              { dbType = SQLite
              , dbConnectionString = "auth.db"
              , dbPoolSize = 10
              , dbTimeout = Duration 30 "seconds"
              }
        let config = validAuthConfig { database = dbConfig }
        validate config `shouldBe` Right config

      it "validates PostgreSQL database configuration" $ do
        let dbConfig = DatabaseConfig
              { dbType = PostgreSQL
              , dbConnectionString = "postgresql://user:pass@localhost/auth"
              , dbPoolSize = 20
              , dbTimeout = Duration 30 "seconds"
              }
        let config = validAuthConfig { database = dbConfig }
        validate config `shouldBe` Right config

      it "rejects PostgreSQL with invalid connection string" $ do
        let dbConfig = DatabaseConfig
              { dbType = PostgreSQL
              , dbConnectionString = "invalid-connection-string"
              , dbPoolSize = 10
              , dbTimeout = Duration 30 "seconds"
              }
        let config = validAuthConfig { database = dbConfig }
        case validate config of
          Left (ValidationErrors errors) -> 
            any isDatabaseConnectionError errors `shouldBe` True
          _ -> expectationFailure "Expected validation error for invalid PostgreSQL connection string"

    describe "Duration validation" $ do
      it "validates positive duration values" $ do
        let duration = Duration 30 "minutes"
        validateDuration "test" duration `shouldBe` []

      it "rejects zero duration values" $ do
        let duration = Duration 0 "minutes"
        validateDuration "test" duration `shouldNotBe` []

      it "rejects negative duration values" $ do
        let duration = Duration (-5) "minutes"
        validateDuration "test" duration `shouldNotBe` []

      it "rejects invalid duration units" $ do
        let duration = Duration 30 "invalid"
        validateDuration "test" duration `shouldNotBe` []

  describe "Environment variable resolution" $ do
    it "resolves environment variables in provider configuration" $ do
      let googleConfig = GoogleConfig
            { googleClientId = "${GOOGLE_CLIENT_ID}"
            , googleClientSecret = "${GOOGLE_CLIENT_SECRET}"
            , googleScopes = ["openid", "email"]
            , googleRedirectUri = Nothing
            }
      let config = validAuthConfig { providers = [GoogleOAuth googleConfig] }
      -- This test would need actual environment variables set
      -- For now, we just test the structure
      result <- resolveEnvironmentVariables config
      case result of
        Left (EnvironmentVariableError _ _) -> return () -- Expected when env vars not set
        Right _ -> return () -- Expected when env vars are set
        Left other -> expectationFailure $ "Unexpected error: " ++ show other

  describe "Runtime configuration transformation" $ do
    it "transforms valid AuthConfig to RuntimeConfig" $ do
      let config = validAuthConfig
      result <- transformToRuntime config
      case result of
        Right runtimeConfig -> do
          httpPort (httpConfig runtimeConfig) `shouldBe` 8080
          httpHost (httpConfig runtimeConfig) `shouldBe` "localhost"
          Map.size (authProviders runtimeConfig) `shouldBe` 1
          sessionExpiration (sessionManager runtimeConfig) `shouldBe` 86400 -- 24 hours in seconds
        Left err -> expectationFailure $ "Expected successful transformation, got: " ++ show err

    it "establishes SQLite database connection" $ do
      let dbConfig = DatabaseConfig
            { dbType = SQLite
            , dbConnectionString = "test.db"
            , dbPoolSize = 5
            , dbTimeout = Duration 30 "seconds"
            }
      result <- establishDatabaseConnection dbConfig
      case result of
        Right dbConn -> do
          dbConnHandle dbConn `shouldBe` "test.db"
          dbConnType' dbConn `shouldBe` SQLite
          dbConnPool dbConn `shouldBe` 5
        Left err -> expectationFailure $ "Expected successful connection, got: " ++ show err

    it "establishes PostgreSQL database connection" $ do
      let dbConfig = DatabaseConfig
            { dbType = PostgreSQL
            , dbConnectionString = "postgresql://user:pass@localhost/testdb"
            , dbPoolSize = 10
            , dbTimeout = Duration 30 "seconds"
            }
      result <- establishDatabaseConnection dbConfig
      case result of
        Right dbConn -> do
          dbConnHandle dbConn `shouldBe` "postgresql://user:pass@localhost/testdb"
          dbConnType' dbConn `shouldBe` PostgreSQL
          dbConnPool dbConn `shouldBe` 10
        Left err -> expectationFailure $ "Expected successful connection, got: " ++ show err

    it "rejects invalid PostgreSQL connection string" $ do
      let dbConfig = DatabaseConfig
            { dbType = PostgreSQL
            , dbConnectionString = "invalid-connection-string"
            , dbPoolSize = 10
            , dbTimeout = Duration 30 "seconds"
            }
      result <- establishDatabaseConnection dbConfig
      case result of
        Left (DatabaseConnectionError _) -> return () -- Expected
        Right _ -> expectationFailure "Expected database connection error"
        Left other -> expectationFailure $ "Unexpected error: " ++ show other

    it "initializes JWT session manager" $ do
      let jwtConfig = JWTConfig
            { jwtSecret = "test-secret"
            , jwtAlgorithm = "HS256"
            , jwtIssuer = Just "test-issuer"
            , jwtAudience = Just "test-audience"
            , jwtRefreshEnabled = True
            }
      let sessionConfig = SessionConfig
            { strategy = StoreJWT jwtConfig
            , expiration = Duration 1 "hours"
            , secure = True
            , sameSite = "Strict"
            , httpOnly = True
            }
      let dbConn = DatabaseConnection
            { dbConnHandle = "test.db"
            , dbConnType' = SQLite
            , dbConnPool = 5
            }
      result <- initializeSessionManager sessionConfig dbConn
      case result of
        Right sessionMgr -> do
          sessionExpiration sessionMgr `shouldBe` 3600 -- 1 hour in seconds
          sessionSecure sessionMgr `shouldBe` True
          case sessionStrategy sessionMgr of
            StoreJWT jwt -> jwtSecret jwt `shouldBe` "test-secret"
            _ -> expectationFailure "Expected JWT strategy"
        Left err -> expectationFailure $ "Expected successful initialization, got: " ++ show err

    it "initializes cookie session manager" $ do
      let cookieConfig = CookieConfig
            { cookieName = "session"
            , cookieDomain = Just "example.com"
            , cookiePath = "/"
            , cookieMaxAge = Just (Duration 7 "days")
            }
      let sessionConfig = SessionConfig
            { strategy = StoreCookie cookieConfig
            , expiration = Duration 24 "hours"
            , secure = True
            , sameSite = "Lax"
            , httpOnly = True
            }
      let dbConn = DatabaseConnection
            { dbConnHandle = "test.db"
            , dbConnType' = SQLite
            , dbConnPool = 5
            }
      result <- initializeSessionManager sessionConfig dbConn
      case result of
        Right sessionMgr -> do
          sessionExpiration sessionMgr `shouldBe` 86400 -- 24 hours in seconds
          sessionSecure sessionMgr `shouldBe` True
          case sessionStrategy sessionMgr of
            StoreCookie cookie -> cookieName cookie `shouldBe` "session"
            _ -> expectationFailure "Expected Cookie strategy"
        Left err -> expectationFailure $ "Expected successful initialization, got: " ++ show err

    it "creates HTTP configuration with CORS" $ do
      let config = validAuthConfig
      let httpConfig = createHttpConfig config
      httpPort httpConfig `shouldBe` 8080
      httpHost httpConfig `shouldBe` "localhost"
      httpTLS httpConfig `shouldBe` False
      corsOrigins (httpCORS httpConfig) `shouldContain` ["*"]
      corsMethods (httpCORS httpConfig) `shouldContain` ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
      corsHeaders (httpCORS httpConfig) `shouldContain` ["Content-Type", "Authorization"]

    it "extracts origins from OAuth redirect URIs" $ do
      let googleConfig = GoogleConfig
            { googleClientId = "client123"
            , googleClientSecret = "secret456"
            , googleScopes = ["openid", "email"]
            , googleRedirectUri = Just "https://example.com/auth/callback"
            }
      let config = validAuthConfig { providers = [GoogleOAuth googleConfig] }
      let httpConfig = createHttpConfig config
      corsOrigins (httpCORS httpConfig) `shouldContain` ["https://example.com"]

-- Helper functions for testing

validAuthConfig :: AuthConfig
validAuthConfig = AuthConfig
  { providers = [GoogleOAuth validGoogleConfig]
  , session = validSessionConfig
  , database = validDatabaseConfig
  , protect = []
  }

validGoogleConfig :: GoogleConfig
validGoogleConfig = GoogleConfig
  { googleClientId = "valid-client-id"
  , googleClientSecret = "valid-client-secret"
  , googleScopes = ["openid", "email", "profile"]
  , googleRedirectUri = Just "https://example.com/auth/callback"
  }

validSessionConfig :: SessionConfig
validSessionConfig = SessionConfig
  { strategy = StoreJWT validJWTConfig
  , expiration = Duration 24 "hours"
  , secure = True
  , sameSite = "Strict"
  , httpOnly = True
  }

validJWTConfig :: JWTConfig
validJWTConfig = JWTConfig
  { jwtSecret = "super-secret-jwt-key"
  , jwtAlgorithm = "HS256"
  , jwtIssuer = Just "auth-dsl"
  , jwtAudience = Just "my-application"
  , jwtRefreshEnabled = True
  }

validDatabaseConfig :: DatabaseConfig
validDatabaseConfig = DatabaseConfig
  { dbType = SQLite
  , dbConnectionString = "auth.db"
  , dbPoolSize = 10
  , dbTimeout = Duration 30 "seconds"
  }

-- Error checking helper functions

isGoogleClientIdError :: ValidationError -> Bool
isGoogleClientIdError (ProviderValidationError "google" (InvalidConfiguration "googleClientId" _)) = True
isGoogleClientIdError _ = False

isRedirectUriError :: ValidationError -> Bool
isRedirectUriError (ProviderValidationError "google" (InvalidConfiguration "googleRedirectUri" _)) = True
isRedirectUriError _ = False

isPasswordLengthError :: ValidationError -> Bool
isPasswordLengthError (ProviderValidationError "password" (InvalidConfiguration "passwordMinLength" _)) = True
isPasswordLengthError _ = False

isJWTAlgorithmError :: ValidationError -> Bool
isJWTAlgorithmError (SessionValidationError (InvalidConfiguration "jwtAlgorithm" _)) = True
isJWTAlgorithmError _ = False

isCookiePathError :: ValidationError -> Bool
isCookiePathError (SessionValidationError (InvalidConfiguration "cookiePath" _)) = True
isCookiePathError _ = False

isDatabaseConnectionError :: ValidationError -> Bool
isDatabaseConnectionError (DatabaseValidationError (DatabaseConnectionError _)) = True
isDatabaseConnectionError _ = False