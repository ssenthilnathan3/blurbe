{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE ScopedTypeVariables #-}

module AuthDSL.Database.SQLite
  ( SQLiteAdapter(..)
  , createSQLiteAdapter
  , initializeSQLiteSchema
  ) where

import AuthDSL.Database
import AuthDSL.Session (UserSession(..), SessionMetadata(..))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime, getCurrentTime)
import Database.SQLite.Simple
import Database.SQLite.Simple.QQ
import Control.Exception (try, SomeException)
import Data.Maybe (listToMaybe)
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Char8 as BS

-- | SQLite adapter with actual database connection
data SQLiteAdapter = SQLiteAdapter
  { sqliteConn :: Connection
  , connConfig :: DatabaseConnection
  }

-- | Create SQLite adapter with real database connection
createSQLiteAdapter :: DatabaseConnection -> IO (Either DatabaseError SQLiteAdapter)
createSQLiteAdapter config = do
  result <- try $ do
    conn <- open (T.unpack $ connString config)
    let adapter = SQLiteAdapter conn config
    schemaResult <- initializeSQLiteSchema adapter
    case schemaResult of
      Left err -> error $ "Schema initialization failed: " ++ show err
      Right _ -> return adapter
  
  case result of
    Left (e :: SomeException) -> return $ Left $ ConnectionError $ T.pack $ show e
    Right adapter -> return $ Right adapter

-- | Initialize SQLite database schema
initializeSQLiteSchema :: SQLiteAdapter -> IO (Either DatabaseError ())
initializeSQLiteSchema (SQLiteAdapter conn _) = do
  result <- try $ do
    -- Create users table
    execute_ conn [sql|
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        first_name TEXT,
        last_name TEXT,
        avatar_url TEXT,
        locale TEXT,
        timezone TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        email_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    |]
    
    -- Create sessions table
    execute_ conn [sql|
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        scopes TEXT, -- JSON array of scopes
        roles TEXT, -- JSON array of roles
        user_agent TEXT,
        ip_address TEXT,
        device_id TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
      )
    |]
    
    -- Create user_providers table for OAuth connections
    execute_ conn [sql|
      CREATE TABLE IF NOT EXISTS user_providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        provider_name TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        access_token TEXT,
        refresh_token TEXT,
        token_expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
        UNIQUE (user_id, provider_name),
        UNIQUE (provider_name, provider_id)
      )
    |]
    
    -- Create indexes for performance
    execute_ conn [sql|CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)|]
    execute_ conn [sql|CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)|]
    execute_ conn [sql|CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)|]
    execute_ conn [sql|CREATE INDEX IF NOT EXISTS idx_user_providers_user_id ON user_providers (user_id)|]
    execute_ conn [sql|CREATE INDEX IF NOT EXISTS idx_user_providers_provider ON user_providers (provider_name, provider_id)|]
    
    return ()
  
  case result of
    Left (e :: SomeException) -> return $ Left $ ConnectionError $ T.pack $ show e
    Right _ -> return $ Right ()

-- Helper functions for converting between database rows and our types
-- We'll implement manual row conversion to avoid ToRow/FromRow limitations with large tuples

-- | Convert database row to User
rowToUser :: (Text, Text, Maybe Text, Maybe Text, Maybe Text, Maybe Text, Maybe Text, Maybe Text, Bool, Bool, UTCTime, UTCTime) -> User
rowToUser (uid, userEmail, passHash, fName, lName, avatar, loc, tz, active, verified, created, updated) =
  User
    { AuthDSL.Database.userId = uid
    , email = userEmail
    , passwordHash = passHash
    , providers = [] -- Will be loaded separately
    , AuthDSL.Database.metadata = UserMetadata
        { firstName = fName
        , lastName = lName
        , avatarUrl = avatar
        , locale = loc
        , timezone = tz
        }
    , isActive = active
    , emailVerified = verified
    , AuthDSL.Database.createdAt = created
    , updatedAt = updated
    }

-- | Convert database row to UserSession
rowToSession :: (Text, Text, UTCTime, Text, Text, Maybe Text, Maybe Text, Maybe Text, UTCTime, UTCTime) -> UserSession
rowToSession (sid, uid, expires, scopesJson, rolesJson, ua, ip, device, created, lastAccessed) =
  UserSession
    { sessionId = sid
    , AuthDSL.Session.userId = uid
    , expiresAt = expires
    , scopes = parseJsonList scopesJson -- Simple parsing for now
    , roles = parseJsonList rolesJson   -- Simple parsing for now
    , AuthDSL.Session.metadata = SessionMetadata
        { userAgent = ua
        , ipAddress = ip
        , deviceId = device
        }
    , AuthDSL.Session.createdAt = created
    , lastAccessedAt = lastAccessed
    }

-- | Simple JSON list parser (for now, just split by comma)
parseJsonList :: Text -> [Text]
parseJsonList "" = []
parseJsonList t = T.splitOn "," t

-- | Convert list to simple JSON (for now, just join with comma)
listToJson :: [Text] -> Text
listToJson = T.intercalate ","

-- | SQLite adapter instance with real database operations
instance DatabaseAdapter SQLiteAdapter where
  createUser (SQLiteAdapter conn _) user = do
    result <- try $ do
      now <- getCurrentTime
      let userWithTime = user { AuthDSL.Database.createdAt = now, updatedAt = now }
          userMeta = AuthDSL.Database.metadata userWithTime
      -- Split into two smaller execute statements to avoid large tuple ToRow issues
      execute conn [sql|
        INSERT INTO users (user_id, email, password_hash, first_name, last_name, 
                          avatar_url, locale, timezone)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      |] ( AuthDSL.Database.userId userWithTime
         , email userWithTime
         , passwordHash userWithTime
         , firstName userMeta
         , lastName userMeta
         , avatarUrl userMeta
         , locale userMeta
         , timezone userMeta
         )
      -- Update the remaining fields
      execute conn [sql|
        UPDATE users SET is_active = ?, email_verified = ?, created_at = ?, updated_at = ?
        WHERE user_id = ?
      |] ( isActive userWithTime
         , emailVerified userWithTime
         , AuthDSL.Database.createdAt userWithTime
         , updatedAt userWithTime
         , AuthDSL.Database.userId userWithTime
         )
      return userWithTime
    
    case result of
      Left (e :: SomeException) -> 
        if "UNIQUE constraint failed" `T.isInfixOf` T.pack (show e)
        then return $ Left $ DuplicateError "User with this email already exists"
        else return $ Left $ QueryError $ T.pack $ show e
      Right newUser -> return $ Right newUser
  
  getUserById (SQLiteAdapter conn _) uid = do
    result <- try $ do
      -- Split query into two parts to avoid large tuple FromRow issues
      basicRows <- query conn [sql|
        SELECT user_id, email, password_hash, first_name, last_name, 
               avatar_url, locale, timezone
        FROM users WHERE user_id = ?
      |] (Only uid)
      case listToMaybe basicRows of
        Nothing -> return Nothing
        Just (userId', userEmail, passHash, fName, lName, avatar, loc, tz) -> do
          metaRows <- query conn [sql|
            SELECT is_active, email_verified, created_at, updated_at
            FROM users WHERE user_id = ?
          |] (Only uid)
          case listToMaybe metaRows of
            Nothing -> return Nothing
            Just (active, verified, created, updated) -> do
              let user = User
                    { AuthDSL.Database.userId = userId'
                    , email = userEmail
                    , passwordHash = passHash
                    , providers = [] -- Will be loaded separately
                    , AuthDSL.Database.metadata = UserMetadata
                        { firstName = fName
                        , lastName = lName
                        , avatarUrl = avatar
                        , locale = loc
                        , timezone = tz
                        }
                    , isActive = active
                    , emailVerified = verified
                    , AuthDSL.Database.createdAt = created
                    , updatedAt = updated
                    }
              return $ Just user
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right user -> return $ Right user
  
  getUserByEmail (SQLiteAdapter conn _) userEmail = do
    result <- try $ do
      -- Split query into two parts to avoid large tuple FromRow issues
      basicRows <- query conn [sql|
        SELECT user_id, email, password_hash, first_name, last_name, 
               avatar_url, locale, timezone
        FROM users WHERE email = ?
      |] (Only userEmail)
      case listToMaybe basicRows of
        Nothing -> return Nothing
        Just (userId', userEmail', passHash, fName, lName, avatar, loc, tz) -> do
          metaRows <- query conn [sql|
            SELECT is_active, email_verified, created_at, updated_at
            FROM users WHERE email = ?
          |] (Only userEmail)
          case listToMaybe metaRows of
            Nothing -> return Nothing
            Just (active, verified, created, updated) -> do
              let user = User
                    { AuthDSL.Database.userId = userId'
                    , email = userEmail'
                    , passwordHash = passHash
                    , providers = [] -- Will be loaded separately
                    , AuthDSL.Database.metadata = UserMetadata
                        { firstName = fName
                        , lastName = lName
                        , avatarUrl = avatar
                        , locale = loc
                        , timezone = tz
                        }
                    , isActive = active
                    , emailVerified = verified
                    , AuthDSL.Database.createdAt = created
                    , updatedAt = updated
                    }
              return $ Just user
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right user -> return $ Right user
  
  updateUser (SQLiteAdapter conn _) user = do
    result <- try $ do
      now <- getCurrentTime
      let updatedUser = user { updatedAt = now }
          userMeta = AuthDSL.Database.metadata updatedUser
      -- Split update into two smaller operations to avoid large tuple ToRow issues
      execute conn [sql|
        UPDATE users SET email = ?, password_hash = ?, first_name = ?, last_name = ?,
                        avatar_url = ?, locale = ?, timezone = ?
        WHERE user_id = ?
      |] ( email updatedUser, passwordHash updatedUser
         , firstName userMeta, lastName userMeta
         , avatarUrl userMeta, locale userMeta
         , timezone userMeta
         , AuthDSL.Database.userId updatedUser
         )
      execute conn [sql|
        UPDATE users SET is_active = ?, email_verified = ?, updated_at = ?
        WHERE user_id = ?
      |] ( isActive updatedUser
         , emailVerified updatedUser, updatedAt updatedUser
         , AuthDSL.Database.userId updatedUser
         )
      return updatedUser
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right updatedUser -> return $ Right updatedUser
  
  deleteUser (SQLiteAdapter conn _) uid = do
    result <- try $ do
      execute conn [sql|DELETE FROM users WHERE user_id = ?|] (Only uid)
      return ()
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right _ -> return $ Right ()
  
  createSession (SQLiteAdapter conn _) session = do
    result <- try $ do
      now <- getCurrentTime
      let sessionWithTime = session { AuthDSL.Session.createdAt = now, lastAccessedAt = now }
          sessionMeta = AuthDSL.Session.metadata sessionWithTime
      execute conn [sql|
        INSERT INTO sessions (session_id, user_id, expires_at, scopes, roles,
                             user_agent, ip_address, device_id, created_at, last_accessed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      |] ( sessionId sessionWithTime
         , AuthDSL.Session.userId sessionWithTime
         , expiresAt sessionWithTime
         , "" :: Text -- scopes as JSON string
         , "" :: Text -- roles as JSON string
         , userAgent sessionMeta
         , ipAddress sessionMeta
         , deviceId sessionMeta
         , AuthDSL.Session.createdAt sessionWithTime
         , lastAccessedAt sessionWithTime
         )
      return sessionWithTime
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right newSession -> return $ Right newSession
  
  getSession (SQLiteAdapter conn _) sid = do
    result <- try $ do
      -- Split query to avoid large tuple FromRow issues
      basicRows <- query conn [sql|
        SELECT session_id, user_id, expires_at, scopes, roles
        FROM sessions WHERE session_id = ?
      |] (Only sid)
      case listToMaybe basicRows of
        Nothing -> return Nothing
        Just (sessionId', userId', expires, scopesJson, rolesJson) -> do
          metaRows <- query conn [sql|
            SELECT user_agent, ip_address, device_id, created_at, last_accessed_at
            FROM sessions WHERE session_id = ?
          |] (Only sid)
          case listToMaybe metaRows of
            Nothing -> return Nothing
            Just (ua, ip, device, created, lastAccessed) -> do
              let session = UserSession
                    { sessionId = sessionId'
                    , AuthDSL.Session.userId = userId'
                    , expiresAt = expires
                    , scopes = parseJsonList scopesJson
                    , roles = parseJsonList rolesJson
                    , AuthDSL.Session.metadata = SessionMetadata
                        { userAgent = ua
                        , ipAddress = ip
                        , deviceId = device
                        }
                    , AuthDSL.Session.createdAt = created
                    , lastAccessedAt = lastAccessed
                    }
              return $ Just session
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right session -> return $ Right session
  
  updateSession (SQLiteAdapter conn _) session = do
    result <- try $ do
      now <- getCurrentTime
      let updatedSession = session { lastAccessedAt = now }
      execute conn [sql|
        UPDATE sessions SET expires_at = ?, last_accessed_at = ?, scopes = ?, roles = ?,
                           ip_address = ?, user_agent = ?, device_id = ?
        WHERE session_id = ?
      |] ( expiresAt updatedSession, lastAccessedAt updatedSession, "" :: Text, "" :: Text
         , ipAddress $ AuthDSL.Session.metadata updatedSession, userAgent $ AuthDSL.Session.metadata updatedSession
         , deviceId $ AuthDSL.Session.metadata updatedSession
         , sessionId updatedSession
         )
      return updatedSession
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right updatedSession -> return $ Right updatedSession
  
  deleteSession (SQLiteAdapter conn _) sid = do
    result <- try $ do
      execute conn [sql|DELETE FROM sessions WHERE session_id = ?|] (Only sid)
      return ()
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right _ -> return $ Right ()
  
  deleteExpiredSessions (SQLiteAdapter conn _) cutoffTime = do
    result <- try $ do
      execute conn [sql|DELETE FROM sessions WHERE expires_at < ?|] (Only cutoffTime)
      changes conn
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right count -> return $ Right $ fromIntegral count
  
  addUserProvider (SQLiteAdapter conn _) uid provider = do
    result <- try $ do
      now <- getCurrentTime
      execute conn [sql|
        INSERT OR REPLACE INTO user_providers (user_id, provider_name, provider_id, 
                                              access_token, refresh_token, token_expires_at,
                                              created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      |] ( uid, providerName provider, providerId provider
         , accessToken provider, refreshToken provider, tokenExpiresAt provider
         , now, now
         )
      return ()
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right _ -> return $ Right ()
  
  removeUserProvider (SQLiteAdapter conn _) uid provName = do
    result <- try $ do
      execute conn [sql|DELETE FROM user_providers WHERE user_id = ? AND provider_name = ?|] 
              (uid, provName)
      return ()
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right _ -> return $ Right ()
  
  getUserByProvider (SQLiteAdapter conn _) provName provId = do
    result <- try $ do
      -- Split query into two parts to avoid large tuple FromRow issues
      basicRows <- query conn [sql|
        SELECT u.user_id, u.email, u.password_hash, u.first_name, u.last_name, 
               u.avatar_url, u.locale, u.timezone
        FROM users u
        JOIN user_providers up ON u.user_id = up.user_id
        WHERE up.provider_name = ? AND up.provider_id = ?
      |] (provName, provId)
      case listToMaybe basicRows of
        Nothing -> return Nothing
        Just (userId', userEmail, passHash, fName, lName, avatar, loc, tz) -> do
          metaRows <- query conn [sql|
            SELECT is_active, email_verified, created_at, updated_at
            FROM users WHERE user_id = ?
          |] (Only userId')
          case listToMaybe metaRows of
            Nothing -> return Nothing
            Just (active, verified, created, updated) -> do
              let user = User
                    { AuthDSL.Database.userId = userId'
                    , email = userEmail
                    , passwordHash = passHash
                    , providers = [] -- Will be loaded separately
                    , AuthDSL.Database.metadata = UserMetadata
                        { firstName = fName
                        , lastName = lName
                        , avatarUrl = avatar
                        , locale = loc
                        , timezone = tz
                        }
                    , isActive = active
                    , emailVerified = verified
                    , AuthDSL.Database.createdAt = created
                    , updatedAt = updated
                    }
              return $ Just user
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right user -> return $ Right user