{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.DatabaseSpec (spec) where

import Test.Hspec
import Test.QuickCheck
import AuthDSL.Database
import AuthDSL.Database.SQLite
import AuthDSL.Types (DatabaseType(..), DatabaseConfig(..), Duration(..))
import AuthDSL.Session (UserSession(..), SessionMetadata(..))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime, getCurrentTime, addUTCTime)
import System.IO.Temp (withSystemTempFile)
import Control.Exception (bracket)

-- | Test configuration for SQLite
testDatabaseConfig :: FilePath -> DatabaseConfig
testDatabaseConfig dbPath = DatabaseConfig
  { dbType = SQLite
  , dbConnectionString = T.pack dbPath
  , dbPoolSize = 5
  , dbTimeout = Duration 30 "seconds"
  }

-- | Create test user
createTestUser :: IO User
createTestUser = do
  now <- getCurrentTime
  return User
    { AuthDSL.Database.userId = "test-user-123"
    , email = "test@example.com"
    , passwordHash = Just "$2b$12$test.hash"
    , providers = []
    , AuthDSL.Database.metadata = UserMetadata
        { firstName = Just "Test"
        , lastName = Just "User"
        , avatarUrl = Nothing
        , locale = Just "en-US"
        , timezone = Just "UTC"
        }
    , isActive = True
    , emailVerified = False
    , AuthDSL.Database.createdAt = now
    , updatedAt = now
    }

-- | Create test session
createTestSession :: UserId -> IO UserSession
createTestSession uid = do
  now <- getCurrentTime
  let expiresAt = addUTCTime 3600 now -- 1 hour from now
  return UserSession
    { sessionId = "test-session-456"
    , AuthDSL.Session.userId = uid
    , expiresAt = expiresAt
    , scopes = ["read", "write"]
    , roles = ["user"]
    , AuthDSL.Session.metadata = SessionMetadata
        { ipAddress = Just "127.0.0.1"
        , userAgent = Just "Test Agent"
        , deviceId = Just "test-device"
        }
    , AuthDSL.Session.createdAt = now
    , lastAccessedAt = now
    }

-- | Create test provider
createTestProvider :: ConnectedProvider
createTestProvider = ConnectedProvider
  { providerName = "google"
  , providerId = "google-123456"
  , accessToken = Just "access-token-123"
  , refreshToken = Just "refresh-token-456"
  , tokenExpiresAt = Nothing
  }

spec :: Spec
spec = describe "Database Adapter" $ do
  
  describe "Schema Generation" $ do
    it "generates SQLite schema correctly" $ do
      let config = testDatabaseConfig ":memory:"
          schema = generateDatabaseSchema config
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS users"
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS sessions"
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS user_providers"
      T.unpack schema `shouldContain` "CREATE INDEX IF NOT EXISTS idx_users_email"
    
    it "generates PostgreSQL schema correctly" $ do
      let config = DatabaseConfig PostgreSQL "postgresql://localhost/test" 5 (Duration 30 "seconds")
          schema = generateDatabaseSchema config
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS users"
      T.unpack schema `shouldContain` "scopes JSONB"
      T.unpack schema `shouldContain` "ip_address INET"
      T.unpack schema `shouldContain` "id SERIAL PRIMARY KEY"
    
    it "generates Supabase schema correctly" $ do
      let config = DatabaseConfig Supabase "postgresql://localhost/test" 5 (Duration 30 "seconds")
          schema = generateDatabaseSchema config
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS users"
      T.unpack schema `shouldContain` "scopes JSONB"
  
  describe "Database Connection" $ do
    it "creates database adapter configuration" $ do
      let config = testDatabaseConfig ":memory:"
      result <- createDatabaseAdapter config
      case result of
        Left err -> expectationFailure $ "Failed to create adapter: " ++ show err
        Right conn -> do
          connType conn `shouldBe` "SQLite"
          connString conn `shouldBe` ":memory:"
          poolSize conn `shouldBe` 5
          timeout conn `shouldBe` 30
          let schema = generateDatabaseSchema config
          T.unpack schema `shouldContain` "CREATE TABLE"
  
  describe "SQLite Adapter" $ do
    it "creates and initializes SQLite adapter" $ do
      withSystemTempFile "test.db" $ \dbPath handle -> do
        let config = testDatabaseConfig dbPath
        result <- createDatabaseAdapter config
        case result of
          Left err -> expectationFailure $ "Failed to create adapter config: " ++ show err
          Right dbConn -> do
            adapterResult <- createSQLiteAdapter dbConn
            case adapterResult of
              Left err -> expectationFailure $ "Failed to create SQLite adapter: " ++ show err
              Right adapter -> do
                -- Test basic adapter creation
                connType (connConfig adapter) `shouldBe` "SQLite"
    
    it "handles user CRUD operations" $ do
      withSystemTempFile "test.db" $ \dbPath handle -> do
        let config = testDatabaseConfig dbPath
        result <- createDatabaseAdapter config
        case result of
          Left err -> expectationFailure $ "Failed to create adapter config: " ++ show err
          Right dbConn -> do
            adapterResult <- createSQLiteAdapter dbConn
            case adapterResult of
              Left err -> expectationFailure $ "Failed to create SQLite adapter: " ++ show err
              Right adapter -> do
                -- Create test user
                testUser <- createTestUser
                createResult <- createUser adapter testUser
                case createResult of
                  Left err -> expectationFailure $ "Failed to create user: " ++ show err
                  Right createdUser -> do
                    AuthDSL.Database.userId createdUser `shouldBe` AuthDSL.Database.userId testUser
                    email createdUser `shouldBe` email testUser
                
                -- Get user by ID
                getUserResult <- getUserById adapter (AuthDSL.Database.userId testUser)
                case getUserResult of
                  Left err -> expectationFailure $ "Failed to get user by ID: " ++ show err
                  Right maybeUser -> do
                    -- The database operations now work correctly and should return the user
                    case maybeUser of
                      Nothing -> expectationFailure "Expected to find user by ID, but got Nothing"
                      Just foundUser -> do
                        AuthDSL.Database.userId foundUser `shouldBe` AuthDSL.Database.userId testUser
                        email foundUser `shouldBe` email testUser
                
                -- Get user by email
                getUserByEmailResult <- getUserByEmail adapter (email testUser)
                case getUserByEmailResult of
                  Left err -> expectationFailure $ "Failed to get user by email: " ++ show err
                  Right maybeUser -> do
                    -- The database operations now work correctly and should return the user
                    case maybeUser of
                      Nothing -> expectationFailure "Expected to find user by email, but got Nothing"
                      Just foundUser -> do
                        AuthDSL.Database.userId foundUser `shouldBe` AuthDSL.Database.userId testUser
                        email foundUser `shouldBe` email testUser
    
    it "handles session CRUD operations" $ do
      withSystemTempFile "test.db" $ \dbPath handle -> do
        let config = testDatabaseConfig dbPath
        result <- createDatabaseAdapter config
        case result of
          Left err -> expectationFailure $ "Failed to create adapter config: " ++ show err
          Right dbConn -> do
            adapterResult <- createSQLiteAdapter dbConn
            case adapterResult of
              Left err -> expectationFailure $ "Failed to create SQLite adapter: " ++ show err
              Right adapter -> do
                -- Create test session
                testSession <- createTestSession "test-user-123"
                createResult <- createSession adapter testSession
                case createResult of
                  Left err -> expectationFailure $ "Failed to create session: " ++ show err
                  Right createdSession -> do
                    sessionId createdSession `shouldBe` sessionId testSession
                    AuthDSL.Session.userId createdSession `shouldBe` AuthDSL.Session.userId testSession
                
                -- Get session
                getSessionResult <- getSession adapter (sessionId testSession)
                case getSessionResult of
                  Left err -> expectationFailure $ "Failed to get session: " ++ show err
                  Right maybeSession -> do
                    -- The database operations now work correctly and should return the session
                    case maybeSession of
                      Nothing -> expectationFailure "Expected to find session, but got Nothing"
                      Just foundSession -> do
                        sessionId foundSession `shouldBe` sessionId testSession
                        AuthDSL.Session.userId foundSession `shouldBe` AuthDSL.Session.userId testSession
    
    it "handles provider operations" $ do
      withSystemTempFile "test.db" $ \dbPath handle -> do
        let config = testDatabaseConfig dbPath
        result <- createDatabaseAdapter config
        case result of
          Left err -> expectationFailure $ "Failed to create adapter config: " ++ show err
          Right dbConn -> do
            adapterResult <- createSQLiteAdapter dbConn
            case adapterResult of
              Left err -> expectationFailure $ "Failed to create SQLite adapter: " ++ show err
              Right adapter -> do
                -- Add provider to user
                let testUserId = "test-user-123"
                addResult <- addUserProvider adapter testUserId createTestProvider
                case addResult of
                  Left err -> expectationFailure $ "Failed to add provider: " ++ show err
                  Right _ -> do
                    -- Provider added successfully
                    True `shouldBe` True
                
                -- Get user by provider (this will return Nothing since we haven't created the user first)
                getUserResult <- getUserByProvider adapter "google" "google-123456"
                case getUserResult of
                  Left err -> expectationFailure $ "Failed to get user by provider: " ++ show err
                  Right maybeUser -> do
                    -- This should return Nothing since we haven't created a user with this provider
                    maybeUser `shouldBe` Nothing

  describe "Duration Conversion" $ do
    it "converts seconds correctly" $ do
      let duration = Duration 30 "seconds"
          config = DatabaseConfig SQLite ":memory:" 5 duration
      result <- createDatabaseAdapter config
      case result of
        Left err -> expectationFailure $ "Failed to create adapter: " ++ show err
        Right conn -> timeout conn `shouldBe` 30
    
    it "converts minutes correctly" $ do
      let duration = Duration 5 "minutes"
          config = DatabaseConfig SQLite ":memory:" 5 duration
      result <- createDatabaseAdapter config
      case result of
        Left err -> expectationFailure $ "Failed to create adapter: " ++ show err
        Right conn -> timeout conn `shouldBe` 300
    
    it "converts hours correctly" $ do
      let duration = Duration 2 "hours"
          config = DatabaseConfig SQLite ":memory:" 5 duration
      result <- createDatabaseAdapter config
      case result of
        Left err -> expectationFailure $ "Failed to create adapter: " ++ show err
        Right conn -> timeout conn `shouldBe` 7200