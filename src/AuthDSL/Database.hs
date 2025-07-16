{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module AuthDSL.Database
  ( DatabaseAdapter(..)
  , DatabaseConnection(..)
  , DatabaseError(..)
  , User(..)
  , ConnectedProvider(..)
  , UserMetadata(..)
  , UserId
  , SessionId
  , Email
  , ProviderName
  , EncryptedToken
  , Scope
  , generateDatabaseSchema
  , createDatabaseAdapter
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime, getCurrentTime)
import GHC.Generics (Generic)
import Control.Exception (Exception, try, SomeException)
import Data.Typeable (Typeable)
import AuthDSL.Types (DatabaseType(..), DatabaseConfig(..), Duration(..), Scope, Role)
import AuthDSL.Session (UserSession(..), SessionMetadata(..), UserId, SessionId, DatabaseConnection(..))

-- | Type aliases for clarity
type Email = Text
type ProviderName = Text
type EncryptedToken = Text

-- | Database error types
data DatabaseError
  = ConnectionError Text
  | QueryError Text
  | ValidationError Text
  | NotFoundError Text
  | DuplicateError Text
  deriving (Show, Eq, Typeable)

instance Exception DatabaseError

-- | User metadata for extensible user information
data UserMetadata = UserMetadata
  { firstName :: Maybe Text
  , lastName :: Maybe Text
  , avatarUrl :: Maybe Text
  , locale :: Maybe Text
  , timezone :: Maybe Text
  } deriving (Show, Eq, Generic)



-- | Connected authentication provider information
data ConnectedProvider = ConnectedProvider
  { providerName :: ProviderName
  , providerId :: Text
  , accessToken :: Maybe EncryptedToken
  , refreshToken :: Maybe EncryptedToken
  , tokenExpiresAt :: Maybe UTCTime
  } deriving (Show, Eq, Generic)

-- | User model
data User = User
  { userId :: UserId
  , email :: Email
  , passwordHash :: Maybe Text
  , providers :: [ConnectedProvider]
  , metadata :: UserMetadata
  , isActive :: Bool
  , emailVerified :: Bool
  , createdAt :: UTCTime
  , updatedAt :: UTCTime
  } deriving (Show, Eq, Generic)





-- | Database adapter typeclass defining CRUD operations
class DatabaseAdapter adapter where
  -- User operations
  createUser :: adapter -> User -> IO (Either DatabaseError User)
  getUserById :: adapter -> UserId -> IO (Either DatabaseError (Maybe User))
  getUserByEmail :: adapter -> Email -> IO (Either DatabaseError (Maybe User))
  updateUser :: adapter -> User -> IO (Either DatabaseError User)
  deleteUser :: adapter -> UserId -> IO (Either DatabaseError ())
  
  -- Session operations
  createSession :: adapter -> UserSession -> IO (Either DatabaseError UserSession)
  getSession :: adapter -> SessionId -> IO (Either DatabaseError (Maybe UserSession))
  updateSession :: adapter -> UserSession -> IO (Either DatabaseError UserSession)
  deleteSession :: adapter -> SessionId -> IO (Either DatabaseError ())
  deleteExpiredSessions :: adapter -> UTCTime -> IO (Either DatabaseError Int)
  
  -- Provider operations
  addUserProvider :: adapter -> UserId -> ConnectedProvider -> IO (Either DatabaseError ())
  removeUserProvider :: adapter -> UserId -> ProviderName -> IO (Either DatabaseError ())
  getUserByProvider :: adapter -> ProviderName -> Text -> IO (Either DatabaseError (Maybe User))

-- | Generate database schema based on configuration
generateDatabaseSchema :: DatabaseConfig -> Text
generateDatabaseSchema config = 
  case dbType config of
    SQLite -> generateSQLiteSchema
    PostgreSQL -> generatePostgreSQLSchema
    Supabase -> generateSupabaseSchema

-- | Generate SQLite schema
generateSQLiteSchema :: Text
generateSQLiteSchema = T.unlines
  [ "-- Users table"
  , "CREATE TABLE IF NOT EXISTS users ("
  , "  user_id TEXT PRIMARY KEY,"
  , "  email TEXT UNIQUE NOT NULL,"
  , "  password_hash TEXT,"
  , "  first_name TEXT,"
  , "  last_name TEXT,"
  , "  avatar_url TEXT,"
  , "  locale TEXT,"
  , "  timezone TEXT,"
  , "  is_active BOOLEAN DEFAULT TRUE,"
  , "  email_verified BOOLEAN DEFAULT FALSE,"
  , "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
  , ");"
  , ""
  , "-- Sessions table"
  , "CREATE TABLE IF NOT EXISTS sessions ("
  , "  session_id TEXT PRIMARY KEY,"
  , "  user_id TEXT NOT NULL,"
  , "  expires_at TIMESTAMP NOT NULL,"
  , "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  last_accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  scopes TEXT,"
  , "  ip_address TEXT,"
  , "  user_agent TEXT,"
  , "  device_id TEXT,"
  , "  is_active BOOLEAN DEFAULT TRUE,"
  , "  FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE"
  , ");"
  , ""
  , "-- User providers table"
  , "CREATE TABLE IF NOT EXISTS user_providers ("
  , "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
  , "  user_id TEXT NOT NULL,"
  , "  provider_name TEXT NOT NULL,"
  , "  provider_id TEXT NOT NULL,"
  , "  access_token TEXT,"
  , "  refresh_token TEXT,"
  , "  token_expires_at TIMESTAMP,"
  , "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,"
  , "  UNIQUE (user_id, provider_name),"
  , "  UNIQUE (provider_name, provider_id)"
  , ");"
  , ""
  , "-- Indexes"
  , "CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);"
  , "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);"
  , "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);"
  , "CREATE INDEX IF NOT EXISTS idx_user_providers_user_id ON user_providers (user_id);"
  , "CREATE INDEX IF NOT EXISTS idx_user_providers_provider ON user_providers (provider_name, provider_id);"
  ]

-- | Generate PostgreSQL schema
generatePostgreSQLSchema :: Text
generatePostgreSQLSchema = T.unlines
  [ "-- Users table"
  , "CREATE TABLE IF NOT EXISTS users ("
  , "  user_id TEXT PRIMARY KEY,"
  , "  email TEXT UNIQUE NOT NULL,"
  , "  password_hash TEXT,"
  , "  first_name TEXT,"
  , "  last_name TEXT,"
  , "  avatar_url TEXT,"
  , "  locale TEXT,"
  , "  timezone TEXT,"
  , "  is_active BOOLEAN DEFAULT TRUE,"
  , "  email_verified BOOLEAN DEFAULT FALSE,"
  , "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
  , ");"
  , ""
  , "-- Sessions table"
  , "CREATE TABLE IF NOT EXISTS sessions ("
  , "  session_id TEXT PRIMARY KEY,"
  , "  user_id TEXT NOT NULL,"
  , "  expires_at TIMESTAMP NOT NULL,"
  , "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  last_accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  scopes JSONB,"
  , "  ip_address INET,"
  , "  user_agent TEXT,"
  , "  device_id TEXT,"
  , "  is_active BOOLEAN DEFAULT TRUE,"
  , "  FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE"
  , ");"
  , ""
  , "-- User providers table"
  , "CREATE TABLE IF NOT EXISTS user_providers ("
  , "  id SERIAL PRIMARY KEY,"
  , "  user_id TEXT NOT NULL,"
  , "  provider_name TEXT NOT NULL,"
  , "  provider_id TEXT NOT NULL,"
  , "  access_token TEXT,"
  , "  refresh_token TEXT,"
  , "  token_expires_at TIMESTAMP,"
  , "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
  , "  FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,"
  , "  UNIQUE (user_id, provider_name),"
  , "  UNIQUE (provider_name, provider_id)"
  , ");"
  , ""
  , "-- Indexes"
  , "CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);"
  , "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);"
  , "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);"
  , "CREATE INDEX IF NOT EXISTS idx_user_providers_user_id ON user_providers (user_id);"
  , "CREATE INDEX IF NOT EXISTS idx_user_providers_provider ON user_providers (provider_name, provider_id);"
  ]

-- | Generate Supabase schema (same as PostgreSQL)
generateSupabaseSchema :: Text
generateSupabaseSchema = generatePostgreSQLSchema

-- | Create database adapter based on configuration
createDatabaseAdapter :: DatabaseConfig -> IO (Either DatabaseError DatabaseConnection)
createDatabaseAdapter config = do
  let dbConn = DatabaseConnection 
        { connType = T.pack $ show $ dbType config
        , connString = dbConnectionString config
        , poolSize = dbPoolSize config
        , timeout = durationToSeconds $ dbTimeout config
        }
  
  return $ Right dbConn



-- | Helper function to convert Duration to seconds
durationToSeconds :: AuthDSL.Types.Duration -> Int
durationToSeconds duration = 
  case durationUnit duration of
    "seconds" -> durationValue duration
    "minutes" -> durationValue duration * 60
    "hours" -> durationValue duration * 3600
    "days" -> durationValue duration * 86400
    _ -> durationValue duration -- default to seconds