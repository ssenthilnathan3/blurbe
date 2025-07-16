{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE ScopedTypeVariables #-}

module AuthDSL.Database.PostgreSQL
  ( PostgreSQLAdapter(..)
  , createPostgreSQLAdapter
  , initializePostgreSQLSchema
  ) where

import AuthDSL.Database
import AuthDSL.Session (UserSession(..), SessionMetadata(..))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime, getCurrentTime)
import Database.PostgreSQL.Simple hiding (QueryError)
import Database.PostgreSQL.Simple.Types (Query(..))
import Control.Exception (try, SomeException, bracket)
import Data.Maybe (listToMaybe)
import Data.Pool (Pool, createPool, withResource)
import qualified Data.Pool as Pool
import qualified Data.ByteString.Char8 as BS
import Data.Int (Int64)

-- | PostgreSQL adapter with connection pooling
data PostgreSQLAdapter = PostgreSQLAdapter
  { pgPool :: Pool Connection
  , connConfig :: DatabaseConnection
  }

-- | Create PostgreSQL adapter with connection pooling
createPostgreSQLAdapter :: DatabaseConnection -> IO (Either DatabaseError PostgreSQLAdapter)
createPostgreSQLAdapter config = do
  result <- try $ do
    let connStr = T.unpack $ connString config
        poolSizeInt = fromIntegral $ poolSize config
        timeoutSecs = fromIntegral $ timeout config
    
    pool <- createPool
      (connectPostgreSQL (BS.pack connStr))  -- create connection
      close                                   -- destroy connection
      1                                      -- number of stripes
      (fromIntegral timeoutSecs)             -- keep alive (seconds)
      poolSizeInt                            -- max connections per stripe
    
    let adapter = PostgreSQLAdapter pool config
    
    -- Test connection and initialize schema
    schemaResult <- withResource pool $ \conn -> initializePostgreSQLSchema conn
    case schemaResult of
      Left err -> error $ "Schema initialization failed: " ++ show err
      Right _ -> return adapter
  
  case result of
    Left (e :: SomeException) -> return $ Left $ ConnectionError $ T.pack $ show e
    Right adapter -> return $ Right adapter

-- | Initialize PostgreSQL database schema
initializePostgreSQLSchema :: Connection -> IO (Either DatabaseError ())
initializePostgreSQLSchema conn = do
  result <- try $ do
    -- Create users table
    execute_ conn $ Query $ TE.encodeUtf8 $ T.unlines
      [ "CREATE TABLE IF NOT EXISTS users ("
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
      , ")"
      ]
    
    -- Create sessions table
    execute_ conn $ Query $ TE.encodeUtf8 $ T.unlines
      [ "CREATE TABLE IF NOT EXISTS sessions ("
      , "  session_id TEXT PRIMARY KEY,"
      , "  user_id TEXT NOT NULL,"
      , "  expires_at TIMESTAMP NOT NULL,"
      , "  scopes JSONB,"
      , "  roles JSONB,"
      , "  user_agent TEXT,"
      , "  ip_address INET,"
      , "  device_id TEXT,"
      , "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
      , "  last_accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
      , "  FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE"
      , ")"
      ]
    
    -- Create user_providers table for OAuth connections
    execute_ conn $ Query $ TE.encodeUtf8 $ T.unlines
      [ "CREATE TABLE IF NOT EXISTS user_providers ("
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
      , ")"
      ]
    
    -- Create indexes for performance
    execute_ conn $ Query "CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)"
    execute_ conn $ Query "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)"
    execute_ conn $ Query "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)"
    execute_ conn $ Query "CREATE INDEX IF NOT EXISTS idx_user_providers_user_id ON user_providers (user_id)"
    execute_ conn $ Query "CREATE INDEX IF NOT EXISTS idx_user_providers_provider ON user_providers (provider_name, provider_id)"
    
    return ()
  
  case result of
    Left (e :: SomeException) -> return $ Left $ ConnectionError $ T.pack $ show e
    Right _ -> return $ Right ()

-- Helper functions for JSON handling
-- | Convert list to JSON array string
listToJsonArray :: [Text] -> Text
listToJsonArray items = "[" <> T.intercalate "," (map (\t -> "\"" <> t <> "\"") items) <> "]"

-- | Parse JSON array string to list (simple implementation)
parseJsonArray :: Maybe Text -> [Text]
parseJsonArray Nothing = []
parseJsonArray (Just "") = []
parseJsonArray (Just jsonStr) = 
  let cleaned = T.replace "[" "" $ T.replace "]" "" $ T.replace "\"" "" jsonStr
  in if T.null cleaned then [] else T.splitOn "," cleaned

-- | PostgreSQL adapter instance with connection pooling
instance DatabaseAdapter PostgreSQLAdapter where
  createUser (PostgreSQLAdapter pool _) user = do
    result <- try $ withResource pool $ \conn -> do
      now <- getCurrentTime
      let userWithTime = user { AuthDSL.Database.createdAt = now, updatedAt = now }
          userMeta = AuthDSL.Database.metadata userWithTime
      
      execute conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "INSERT INTO users (user_id, email, password_hash, first_name, last_name,"
        , "                   avatar_url, locale, timezone, is_active, email_verified,"
        , "                   created_at, updated_at)"
        , "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ]) ( AuthDSL.Database.userId userWithTime
           , email userWithTime
           , passwordHash userWithTime
           , firstName userMeta
           , lastName userMeta
           , avatarUrl userMeta
           , locale userMeta
           , timezone userMeta
           , isActive userWithTime
           , emailVerified userWithTime
           , AuthDSL.Database.createdAt userWithTime
           , updatedAt userWithTime
           )
      return userWithTime
    
    case result of
      Left (e :: SomeException) -> 
        if "duplicate key value violates unique constraint" `T.isInfixOf` T.pack (show e)
        then return $ Left $ DuplicateError "User with this email already exists"
        else return $ Left $ QueryError $ T.pack $ show e
      Right newUser -> return $ Right newUser
  
  getUserById (PostgreSQLAdapter pool _) uid = do
    result <- try $ withResource pool $ \conn -> do
      rows <- query conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "SELECT user_id, email, password_hash, first_name, last_name,"
        , "       avatar_url, locale, timezone, is_active, email_verified,"
        , "       created_at, updated_at"
        , "FROM users WHERE user_id = ?"
        ]) (Only uid)
      case listToMaybe rows of
        Nothing -> return Nothing
        Just (userId', userEmail, passHash, fName, lName, avatar, loc, tz, active, verified, created, updated) -> do
          let user = User
                { AuthDSL.Database.userId = userId'
                , email = userEmail
                , passwordHash = passHash
                , providers = [] -- Will be loaded separately if needed
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
  
  getUserByEmail (PostgreSQLAdapter pool _) userEmail = do
    result <- try $ withResource pool $ \conn -> do
      rows <- query conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "SELECT user_id, email, password_hash, first_name, last_name,"
        , "       avatar_url, locale, timezone, is_active, email_verified,"
        , "       created_at, updated_at"
        , "FROM users WHERE email = ?"
        ]) (Only userEmail)
      case listToMaybe rows of
        Nothing -> return Nothing
        Just (userId', userEmail', passHash, fName, lName, avatar, loc, tz, active, verified, created, updated) -> do
          let user = User
                { AuthDSL.Database.userId = userId'
                , email = userEmail'
                , passwordHash = passHash
                , providers = [] -- Will be loaded separately if needed
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
  
  updateUser (PostgreSQLAdapter pool _) user = do
    result <- try $ withResource pool $ \conn -> do
      now <- getCurrentTime
      let updatedUser = user { updatedAt = now }
          userMeta = AuthDSL.Database.metadata updatedUser
      
      execute conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "UPDATE users SET email = ?, password_hash = ?, first_name = ?, last_name = ?,"
        , "                 avatar_url = ?, locale = ?, timezone = ?, is_active = ?,"
        , "                 email_verified = ?, updated_at = ?"
        , "WHERE user_id = ?"
        ]) ( email updatedUser, passwordHash updatedUser
           , firstName userMeta, lastName userMeta
           , avatarUrl userMeta, locale userMeta, timezone userMeta
           , isActive updatedUser, emailVerified updatedUser
           , updatedAt updatedUser, AuthDSL.Database.userId updatedUser
           )
      return updatedUser
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right updatedUser -> return $ Right updatedUser
  
  deleteUser (PostgreSQLAdapter pool _) uid = do
    result <- try $ withResource pool $ \conn -> do
      execute conn (Query "DELETE FROM users WHERE user_id = ?") (Only uid)
      return ()
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right _ -> return $ Right ()
  
  createSession (PostgreSQLAdapter pool _) session = do
    result <- try $ withResource pool $ \conn -> do
      now <- getCurrentTime
      let sessionWithTime = session { AuthDSL.Session.createdAt = now, lastAccessedAt = now }
          sessionMeta = AuthDSL.Session.metadata sessionWithTime
          scopesJson = listToJsonArray $ scopes sessionWithTime
          rolesJson = listToJsonArray $ roles sessionWithTime
      
      execute conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "INSERT INTO sessions (session_id, user_id, expires_at, scopes, roles,"
        , "                      user_agent, ip_address, device_id, created_at, last_accessed_at)"
        , "VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?, ?::inet, ?, ?, ?)"
        ]) ( sessionId sessionWithTime
           , AuthDSL.Session.userId sessionWithTime
           , expiresAt sessionWithTime
           , scopesJson
           , rolesJson
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
  
  getSession (PostgreSQLAdapter pool _) sid = do
    result <- try $ withResource pool $ \conn -> do
      rows <- query conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "SELECT session_id, user_id, expires_at, scopes::text, roles::text,"
        , "       user_agent, ip_address::text, device_id, created_at, last_accessed_at"
        , "FROM sessions WHERE session_id = ?"
        ]) (Only sid)
      case listToMaybe rows of
        Nothing -> return Nothing
        Just (sessionId', userId', expires, scopesJson, rolesJson, ua, ip, device, created, lastAccessed) -> do
          let session = UserSession
                { sessionId = sessionId'
                , AuthDSL.Session.userId = userId'
                , expiresAt = expires
                , scopes = parseJsonArray scopesJson
                , roles = parseJsonArray rolesJson
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
  
  updateSession (PostgreSQLAdapter pool _) session = do
    result <- try $ withResource pool $ \conn -> do
      now <- getCurrentTime
      let updatedSession = session { lastAccessedAt = now }
          sessionMeta = AuthDSL.Session.metadata updatedSession
          scopesJson = listToJsonArray $ scopes updatedSession
          rolesJson = listToJsonArray $ roles updatedSession
      
      execute conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "UPDATE sessions SET expires_at = ?, last_accessed_at = ?, scopes = ?::jsonb,"
        , "                    roles = ?::jsonb, ip_address = ?::inet, user_agent = ?, device_id = ?"
        , "WHERE session_id = ?"
        ]) ( expiresAt updatedSession, lastAccessedAt updatedSession
           , scopesJson, rolesJson
           , ipAddress sessionMeta, userAgent sessionMeta, deviceId sessionMeta
           , sessionId updatedSession
           )
      return updatedSession
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right updatedSession -> return $ Right updatedSession
  
  deleteSession (PostgreSQLAdapter pool _) sid = do
    result <- try $ withResource pool $ \conn -> do
      execute conn (Query "DELETE FROM sessions WHERE session_id = ?") (Only sid)
      return ()
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right _ -> return $ Right ()
  
  deleteExpiredSessions (PostgreSQLAdapter pool _) cutoffTime = do
    result <- try $ withResource pool $ \conn -> do
      rowCount <- execute conn (Query "DELETE FROM sessions WHERE expires_at < ?") (Only cutoffTime)
      return $ fromIntegral rowCount
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right count -> return $ Right count
  
  addUserProvider (PostgreSQLAdapter pool _) uid provider = do
    result <- try $ withResource pool $ \conn -> do
      now <- getCurrentTime
      execute conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "INSERT INTO user_providers (user_id, provider_name, provider_id,"
        , "                           access_token, refresh_token, token_expires_at,"
        , "                           created_at, updated_at)"
        , "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        , "ON CONFLICT (user_id, provider_name) DO UPDATE SET"
        , "  provider_id = EXCLUDED.provider_id,"
        , "  access_token = EXCLUDED.access_token,"
        , "  refresh_token = EXCLUDED.refresh_token,"
        , "  token_expires_at = EXCLUDED.token_expires_at,"
        , "  updated_at = EXCLUDED.updated_at"
        ]) ( uid, providerName provider, providerId provider
           , accessToken provider, refreshToken provider, tokenExpiresAt provider
           , now, now
           )
      return ()
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right _ -> return $ Right ()
  
  removeUserProvider (PostgreSQLAdapter pool _) uid provName = do
    result <- try $ withResource pool $ \conn -> do
      execute conn (Query "DELETE FROM user_providers WHERE user_id = ? AND provider_name = ?") 
              (uid, provName)
      return ()
    
    case result of
      Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
      Right _ -> return $ Right ()
  
  getUserByProvider (PostgreSQLAdapter pool _) provName provId = do
    result <- try $ withResource pool $ \conn -> do
      rows <- query conn (Query $ TE.encodeUtf8 $ T.unlines
        [ "SELECT u.user_id, u.email, u.password_hash, u.first_name, u.last_name,"
        , "       u.avatar_url, u.locale, u.timezone, u.is_active, u.email_verified,"
        , "       u.created_at, u.updated_at"
        , "FROM users u"
        , "JOIN user_providers up ON u.user_id = up.user_id"
        , "WHERE up.provider_name = ? AND up.provider_id = ?"
        ]) (provName, provId)
      case listToMaybe rows of
        Nothing -> return Nothing
        Just (userId', userEmail, passHash, fName, lName, avatar, loc, tz, active, verified, created, updated) -> do
          let user = User
                { AuthDSL.Database.userId = userId'
                , email = userEmail
                , passwordHash = passHash
                , providers = [] -- Will be loaded separately if needed
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