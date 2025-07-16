{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.Database.AdaptersSpec (spec) where

import Test.Hspec
import AuthDSL.Database
import AuthDSL.Database.Adapters
import AuthDSL.Session (DatabaseConnection(..), UserId, SessionId)
import AuthDSL.Types (DatabaseType(..), DatabaseConfig(..), Duration(..))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (getCurrentTime, addUTCTime)

-- Test configuration for different database types
testSQLiteConfig :: DatabaseConfig
testSQLiteConfig = DatabaseConfig
  { dbType = SQLite
  , dbConnectionString = ":memory:"
  , dbPoolSize = 5
  , dbTimeout = Duration 30 "seconds"
  }

testPostgreSQLConfig :: DatabaseConfig
testPostgreSQLConfig = DatabaseConfig
  { dbType = PostgreSQL
  , dbConnectionString = "postgresql://localhost/test_auth_dsl"
  , dbPoolSize = 10
  , dbTimeout = Duration 30 "seconds"
  }

testSupabaseConfig :: DatabaseConfig
testSupabaseConfig = DatabaseConfig
  { dbType = Supabase
  , dbConnectionString = "https://test.supabase.co;key=test-key"
  , dbPoolSize = 10
  , dbTimeout = Duration 30 "seconds"
  }

-- Test user data
testUser :: IO User
testUser = do
  now <- getCurrentTime
  return User
    { userId = "test-user-123"
    , email = "test@example.com"
    , passwordHash = Just "$2b$12$test.hash"
    , providers = []
    , metadata = UserMetadata
        { firstName = Just "Test"
        , lastName = Just "User"
        , avatarUrl = Nothing
        , locale = Just "en"
        , timezone = Just "UTC"
        }
    , isActive = True
    , emailVerified = False
    , createdAt = now
    , updatedAt = now
    }

spec :: Spec
spec = describe "Database Adapters" $ do
  
  describe "SQLite Adapter" $ do
    it "creates adapter successfully" $ do
      result <- createDatabaseAdapterFromConfig testSQLiteConfig
      case result of
        Left err -> expectationFailure $ "Failed to create SQLite adapter: " ++ show err
        Right _ -> return ()
    
    it "handles basic user operations" $ do
      result <- createDatabaseAdapterFromConfig testSQLiteConfig
      case result of
        Left err -> expectationFailure $ "Failed to create SQLite adapter: " ++ show err
        Right adapter -> do
          user <- testUser
          
          -- Test create user
          createResult <- createUser adapter user
          case createResult of
            Left err -> expectationFailure $ "Failed to create user: " ++ show err
            Right createdUser -> do
              userId createdUser `shouldBe` userId user
              email createdUser `shouldBe` email user
          
          -- Test get user by ID
          getResult <- getUserById adapter (userId user)
          case getResult of
            Left err -> expectationFailure $ "Failed to get user: " ++ show err
            Right (Just foundUser) -> do
              userId foundUser `shouldBe` userId user
              email foundUser `shouldBe` email user
            Right Nothing -> expectationFailure "User not found"
          
          -- Test get user by email
          getByEmailResult <- getUserByEmail adapter (email user)
          case getByEmailResult of
            Left err -> expectationFailure $ "Failed to get user by email: " ++ show err
            Right (Just foundUser) -> do
              userId foundUser `shouldBe` userId user
              email foundUser `shouldBe` email user
            Right Nothing -> expectationFailure "User not found by email"

  describe "PostgreSQL Adapter" $ do
    it "creates adapter configuration" $ do
      -- Note: This test only verifies configuration creation, not actual connection
      -- since we don't have a PostgreSQL instance in the test environment
      dbConnResult <- createDatabaseAdapter testPostgreSQLConfig
      case dbConnResult of
        Left err -> expectationFailure $ "Failed to create PostgreSQL config: " ++ show err
        Right dbConn -> do
          connType dbConn `shouldBe` "PostgreSQL"
          connString dbConn `shouldBe` "postgresql://localhost/test_auth_dsl"
          poolSize dbConn `shouldBe` 10

  describe "Supabase Adapter" $ do
    it "creates adapter configuration" $ do
      -- Note: This test only verifies configuration creation, not actual connection
      -- since we don't have a Supabase instance in the test environment
      dbConnResult <- createDatabaseAdapter testSupabaseConfig
      case dbConnResult of
        Left err -> expectationFailure $ "Failed to create Supabase config: " ++ show err
        Right dbConn -> do
          connType dbConn `shouldBe` "Supabase"
          connString dbConn `shouldBe` "https://test.supabase.co;key=test-key"
          poolSize dbConn `shouldBe` 10

  describe "Database Schema Generation" $ do
    it "generates SQLite schema" $ do
      let schema = generateDatabaseSchema testSQLiteConfig
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS users"
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS sessions"
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS user_providers"
    
    it "generates PostgreSQL schema" $ do
      let schema = generateDatabaseSchema testPostgreSQLConfig
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS users"
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS sessions"
      T.unpack schema `shouldContain` "JSONB"
      T.unpack schema `shouldContain` "INET"
    
    it "generates Supabase schema" $ do
      let schema = generateDatabaseSchema testSupabaseConfig
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS users"
      T.unpack schema `shouldContain` "CREATE TABLE IF NOT EXISTS sessions"
      T.unpack schema `shouldContain` "JSONB"
      T.unpack schema `shouldContain` "INET"