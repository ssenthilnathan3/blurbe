{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}

module AuthDSL.Database.Supabase
  ( SupabaseAdapter(..)
  , createSupabaseAdapter
  , initializeSupabaseSchema
  ) where

import AuthDSL.Database
import AuthDSL.Session (UserSession(..), SessionMetadata(..))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime, getCurrentTime, formatTime, defaultTimeLocale, parseTimeM)
import Data.Aeson
import Data.Aeson.Types (Parser)
import GHC.Generics (Generic)
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types.Status
import Network.HTTP.Types.Header
import Control.Exception (try, SomeException)
import Data.Maybe (listToMaybe, fromMaybe)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BS
import Control.Monad (void)

-- | Supabase adapter using PostgREST API
data SupabaseAdapter = SupabaseAdapter
  { supabaseUrl :: Text
  , supabaseKey :: Text
  , httpManager :: Manager
  , connConfig :: DatabaseConnection
  }

-- | Create Supabase adapter with HTTP client
createSupabaseAdapter :: DatabaseConnection -> IO (Either DatabaseError SupabaseAdapter)
createSupabaseAdapter config = do
  result <- try $ do
    manager <- newManager tlsManagerSettings
    
    -- Parse connection string to extract URL and key
    -- Expected format: "https://your-project.supabase.co;key=your-anon-key"
    let connStr = connString config
        parts = T.splitOn ";" connStr
        url = head parts
        keyPart = if length parts > 1 then parts !! 1 else ""
        key = if T.isPrefixOf "key=" keyPart 
              then T.drop 4 keyPart 
              else error "Supabase connection string must include key parameter"
    
    let adapter = SupabaseAdapter url key manager config
    
    -- Test connection and initialize schema
    schemaResult <- initializeSupabaseSchema adapter
    case schemaResult of
      Left err -> error $ "Schema initialization failed: " ++ show err
      Right _ -> return adapter
  
  case result of
    Left (e :: SomeException) -> return $ Left $ ConnectionError $ T.pack $ show e
    Right adapter -> return $ Right adapter

-- | Initialize Supabase database schema using SQL execution
initializeSupabaseSchema :: SupabaseAdapter -> IO (Either DatabaseError ())
initializeSupabaseSchema adapter = do
  result <- try $ do
    -- Execute schema creation SQL via Supabase SQL API
    let sqlStatements = 
          [ -- Users table
            T.unlines
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
          , -- Sessions table
            T.unlines
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
          , -- User providers table
            T.unlines
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
          , -- Indexes
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)"
          , "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)"
          , "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)"
          , "CREATE INDEX IF NOT EXISTS idx_user_providers_user_id ON user_providers (user_id)"
          , "CREATE INDEX IF NOT EXISTS idx_user_providers_provider ON user_providers (provider_name, provider_id)"
          ]
    
    -- Execute each SQL statement
    mapM_ (executeSupabaseSQL adapter) sqlStatements
    return ()
  
  case result of
    Left (e :: SomeException) -> return $ Left $ ConnectionError $ T.pack $ show e
    Right _ -> return $ Right ()

-- | Execute SQL statement via Supabase SQL API
executeSupabaseSQL :: SupabaseAdapter -> Text -> IO ()
executeSupabaseSQL (SupabaseAdapter url key manager _) sql = do
  let sqlUrl = url <> "/rest/v1/rpc/exec_sql"
  initialRequest <- parseRequest $ T.unpack sqlUrl
  let request = initialRequest
        { method = "POST"
        , requestHeaders = 
            [ ("apikey", TE.encodeUtf8 key)
            , ("Authorization", "Bearer " <> TE.encodeUtf8 key)
            , ("Content-Type", "application/json")
            ]
        , requestBody = RequestBodyLBS $ encode $ object ["sql" .= sql]
        }
  
  response <- httpLbs request manager
  if responseStatus response == status200
    then return ()
    else error $ "SQL execution failed: " ++ show (responseStatus response)

-- JSON instances for Supabase API communication
data SupabaseUser = SupabaseUser
  { supabaseUserId :: Text
  , supabaseEmail :: Text
  , supabasePasswordHash :: Maybe Text
  , supabaseFirstName :: Maybe Text
  , supabaseLastName :: Maybe Text
  , supabaseAvatarUrl :: Maybe Text
  , supabaseLocale :: Maybe Text
  , supabaseTimezone :: Maybe Text
  , supabaseIsActive :: Bool
  , supabaseEmailVerified :: Bool
  , supabaseCreatedAt :: Text
  , supabaseUpdatedAt :: Text
  } deriving (Show, Generic)

instance ToJSON SupabaseUser where
  toJSON user = object
    [ "user_id" .= supabaseUserId user
    , "email" .= supabaseEmail user
    , "password_hash" .= supabasePasswordHash user
    , "first_name" .= supabaseFirstName user
    , "last_name" .= supabaseLastName user
    , "avatar_url" .= supabaseAvatarUrl user
    , "locale" .= supabaseLocale user
    , "timezone" .= supabaseTimezone user
    , "is_active" .= supabaseIsActive user
    , "email_verified" .= supabaseEmailVerified user
    , "created_at" .= supabaseCreatedAt user
    , "updated_at" .= supabaseUpdatedAt user
    ]

instance FromJSON SupabaseUser where
  parseJSON = withObject "SupabaseUser" $ \o -> SupabaseUser
    <$> o .: "user_id"
    <*> o .: "email"
    <*> o .:? "password_hash"
    <*> o .:? "first_name"
    <*> o .:? "last_name"
    <*> o .:? "avatar_url"
    <*> o .:? "locale"
    <*> o .:? "timezone"
    <*> o .:? "is_active" .!= True
    <*> o .:? "email_verified" .!= False
    <*> o .: "created_at"
    <*> o .: "updated_at"

data SupabaseSession = SupabaseSession
  { supabaseSessionId :: Text
  , supabaseSessionUserId :: Text
  , supabaseExpiresAt :: Text
  , supabaseScopes :: Maybe [Text]
  , supabaseRoles :: Maybe [Text]
  , supabaseUserAgent :: Maybe Text
  , supabaseIpAddress :: Maybe Text
  , supabaseDeviceId :: Maybe Text
  , supabaseSessionCreatedAt :: Text
  , supabaseLastAccessedAt :: Text
  } deriving (Show, Generic)

instance ToJSON SupabaseSession where
  toJSON session = object
    [ "session_id" .= supabaseSessionId session
    , "user_id" .= supabaseSessionUserId session
    , "expires_at" .= supabaseExpiresAt session
    , "scopes" .= supabaseScopes session
    , "roles" .= supabaseRoles session
    , "user_agent" .= supabaseUserAgent session
    , "ip_address" .= supabaseIpAddress session
    , "device_id" .= supabaseDeviceId session
    , "created_at" .= supabaseSessionCreatedAt session
    , "last_accessed_at" .= supabaseLastAccessedAt session
    ]

instance FromJSON SupabaseSession where
  parseJSON = withObject "SupabaseSession" $ \o -> SupabaseSession
    <$> o .: "session_id"
    <*> o .: "user_id"
    <*> o .: "expires_at"
    <*> o .:? "scopes"
    <*> o .:? "roles"
    <*> o .:? "user_agent"
    <*> o .:? "ip_address"
    <*> o .:? "device_id"
    <*> o .: "created_at"
    <*> o .: "last_accessed_at"

-- Helper functions for converting between our types and Supabase types
userToSupabase :: User -> SupabaseUser
userToSupabase user = SupabaseUser
  { supabaseUserId = AuthDSL.Database.userId user
  , supabaseEmail = email user
  , supabasePasswordHash = passwordHash user
  , supabaseFirstName = firstName $ AuthDSL.Database.metadata user
  , supabaseLastName = lastName $ AuthDSL.Database.metadata user
  , supabaseAvatarUrl = avatarUrl $ AuthDSL.Database.metadata user
  , supabaseLocale = locale $ AuthDSL.Database.metadata user
  , supabaseTimezone = timezone $ AuthDSL.Database.metadata user
  , supabaseIsActive = isActive user
  , supabaseEmailVerified = emailVerified user
  , supabaseCreatedAt = T.pack $ formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ AuthDSL.Database.createdAt user
  , supabaseUpdatedAt = T.pack $ formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ updatedAt user
  }

supabaseToUser :: SupabaseUser -> Maybe User
supabaseToUser supabaseUser = do
  createdTime <- parseTimeM True defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ T.unpack $ supabaseCreatedAt supabaseUser
  updatedTime <- parseTimeM True defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ T.unpack $ supabaseUpdatedAt supabaseUser
  return User
    { AuthDSL.Database.userId = supabaseUserId supabaseUser
    , email = supabaseEmail supabaseUser
    , passwordHash = supabasePasswordHash supabaseUser
    , providers = [] -- Will be loaded separately if needed
    , AuthDSL.Database.metadata = UserMetadata
        { firstName = supabaseFirstName supabaseUser
        , lastName = supabaseLastName supabaseUser
        , avatarUrl = supabaseAvatarUrl supabaseUser
        , locale = supabaseLocale supabaseUser
        , timezone = supabaseTimezone supabaseUser
        }
    , isActive = supabaseIsActive supabaseUser
    , emailVerified = supabaseEmailVerified supabaseUser
    , AuthDSL.Database.createdAt = createdTime
    , updatedAt = updatedTime
    }

sessionToSupabase :: UserSession -> SupabaseSession
sessionToSupabase session = SupabaseSession
  { supabaseSessionId = sessionId session
  , supabaseSessionUserId = AuthDSL.Session.userId session
  , supabaseExpiresAt = T.pack $ formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ expiresAt session
  , supabaseScopes = Just $ scopes session
  , supabaseRoles = Just $ roles session
  , supabaseUserAgent = userAgent $ AuthDSL.Session.metadata session
  , supabaseIpAddress = ipAddress $ AuthDSL.Session.metadata session
  , supabaseDeviceId = deviceId $ AuthDSL.Session.metadata session
  , supabaseSessionCreatedAt = T.pack $ formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ AuthDSL.Session.createdAt session
  , supabaseLastAccessedAt = T.pack $ formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ lastAccessedAt session
  }

supabaseToSession :: SupabaseSession -> Maybe UserSession
supabaseToSession supabaseSession = do
  expiresTime <- parseTimeM True defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ T.unpack $ supabaseExpiresAt supabaseSession
  createdTime <- parseTimeM True defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ T.unpack $ supabaseSessionCreatedAt supabaseSession
  lastAccessedTime <- parseTimeM True defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" $ T.unpack $ supabaseLastAccessedAt supabaseSession
  return UserSession
    { sessionId = supabaseSessionId supabaseSession
    , AuthDSL.Session.userId = supabaseSessionUserId supabaseSession
    , expiresAt = expiresTime
    , scopes = fromMaybe [] $ supabaseScopes supabaseSession
    , roles = fromMaybe [] $ supabaseRoles supabaseSession
    , AuthDSL.Session.metadata = SessionMetadata
        { userAgent = supabaseUserAgent supabaseSession
        , ipAddress = supabaseIpAddress supabaseSession
        , deviceId = supabaseDeviceId supabaseSession
        }
    , AuthDSL.Session.createdAt = createdTime
    , lastAccessedAt = lastAccessedTime
    }

-- Helper function to make HTTP requests to Supabase
makeSupabaseRequest :: SupabaseAdapter -> Text -> Text -> LBS.ByteString -> IO (Either DatabaseError LBS.ByteString)
makeSupabaseRequest (SupabaseAdapter url key manager _) endpoint method body = do
  result <- try $ do
    let fullUrl = url <> "/rest/v1/" <> endpoint
    initialRequest <- parseRequest $ T.unpack fullUrl
    let request = initialRequest
          { method = TE.encodeUtf8 method
          , requestHeaders = 
              [ ("apikey", TE.encodeUtf8 key)
              , ("Authorization", "Bearer " <> TE.encodeUtf8 key)
              , ("Content-Type", "application/json")
              , ("Prefer", "return=representation")
              ]
          , requestBody = RequestBodyLBS body
          }
    
    response <- httpLbs request manager
    if statusIsSuccessful $ responseStatus response
      then return $ responseBody response
      else error $ "HTTP request failed: " ++ show (responseStatus response) ++ " " ++ show (responseBody response)
  
  case result of
    Left (e :: SomeException) -> return $ Left $ QueryError $ T.pack $ show e
    Right responseBody -> return $ Right responseBody

-- | Supabase adapter instance using PostgREST API
instance DatabaseAdapter SupabaseAdapter where
  createUser adapter user = do
    now <- getCurrentTime
    let userWithTime = user { AuthDSL.Database.createdAt = now, updatedAt = now }
        supabaseUser = userToSupabase userWithTime
    
    result <- makeSupabaseRequest adapter "users" "POST" (encode supabaseUser)
    case result of
      Left err -> return $ Left err
      Right responseBody -> 
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just [createdUser] -> 
            case supabaseToUser createdUser of
              Nothing -> return $ Left $ QueryError "Failed to convert response to User"
              Just user' -> return $ Right user'
          Just [] -> return $ Left $ QueryError "No user created"
          Just _ -> return $ Left $ QueryError "Multiple users created unexpectedly"
  
  getUserById adapter uid = do
    let endpoint = "users?user_id=eq." <> uid
    result <- makeSupabaseRequest adapter endpoint "GET" ""
    case result of
      Left err -> return $ Left err
      Right responseBody ->
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just [] -> return $ Right Nothing
          Just (supabaseUser:_) ->
            case supabaseToUser supabaseUser of
              Nothing -> return $ Left $ QueryError "Failed to convert response to User"
              Just user -> return $ Right $ Just user
  
  getUserByEmail adapter userEmail = do
    let endpoint = "users?email=eq." <> userEmail
    result <- makeSupabaseRequest adapter endpoint "GET" ""
    case result of
      Left err -> return $ Left err
      Right responseBody ->
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just [] -> return $ Right Nothing
          Just (supabaseUser:_) ->
            case supabaseToUser supabaseUser of
              Nothing -> return $ Left $ QueryError "Failed to convert response to User"
              Just user -> return $ Right $ Just user
  
  updateUser adapter user = do
    now <- getCurrentTime
    let updatedUser = user { updatedAt = now }
        supabaseUser = userToSupabase updatedUser
        endpoint = "users?user_id=eq." <> AuthDSL.Database.userId updatedUser
    
    result <- makeSupabaseRequest adapter endpoint "PATCH" (encode supabaseUser)
    case result of
      Left err -> return $ Left err
      Right responseBody ->
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just [updatedSupabaseUser] ->
            case supabaseToUser updatedSupabaseUser of
              Nothing -> return $ Left $ QueryError "Failed to convert response to User"
              Just user' -> return $ Right user'
          Just [] -> return $ Left $ NotFoundError "User not found"
          Just _ -> return $ Left $ QueryError "Multiple users updated unexpectedly"
  
  deleteUser adapter uid = do
    let endpoint = "users?user_id=eq." <> uid
    result <- makeSupabaseRequest adapter endpoint "DELETE" ""
    case result of
      Left err -> return $ Left err
      Right _ -> return $ Right ()
  
  createSession adapter session = do
    now <- getCurrentTime
    let sessionWithTime = session { AuthDSL.Session.createdAt = now, lastAccessedAt = now }
        supabaseSession = sessionToSupabase sessionWithTime
    
    result <- makeSupabaseRequest adapter "sessions" "POST" (encode supabaseSession)
    case result of
      Left err -> return $ Left err
      Right responseBody ->
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just [createdSession] ->
            case supabaseToSession createdSession of
              Nothing -> return $ Left $ QueryError "Failed to convert response to UserSession"
              Just session' -> return $ Right session'
          Just [] -> return $ Left $ QueryError "No session created"
          Just _ -> return $ Left $ QueryError "Multiple sessions created unexpectedly"
  
  getSession adapter sid = do
    let endpoint = "sessions?session_id=eq." <> sid
    result <- makeSupabaseRequest adapter endpoint "GET" ""
    case result of
      Left err -> return $ Left err
      Right responseBody ->
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just [] -> return $ Right Nothing
          Just (supabaseSession:_) ->
            case supabaseToSession supabaseSession of
              Nothing -> return $ Left $ QueryError "Failed to convert response to UserSession"
              Just session -> return $ Right $ Just session
  
  updateSession adapter session = do
    now <- getCurrentTime
    let updatedSession = session { lastAccessedAt = now }
        supabaseSession = sessionToSupabase updatedSession
        endpoint = "sessions?session_id=eq." <> sessionId updatedSession
    
    result <- makeSupabaseRequest adapter endpoint "PATCH" (encode supabaseSession)
    case result of
      Left err -> return $ Left err
      Right responseBody ->
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just [updatedSupabaseSession] ->
            case supabaseToSession updatedSupabaseSession of
              Nothing -> return $ Left $ QueryError "Failed to convert response to UserSession"
              Just session' -> return $ Right session'
          Just [] -> return $ Left $ NotFoundError "Session not found"
          Just _ -> return $ Left $ QueryError "Multiple sessions updated unexpectedly"
  
  deleteSession adapter sid = do
    let endpoint = "sessions?session_id=eq." <> sid
    result <- makeSupabaseRequest adapter endpoint "DELETE" ""
    case result of
      Left err -> return $ Left err
      Right _ -> return $ Right ()
  
  deleteExpiredSessions adapter cutoffTime = do
    let timeStr = T.pack $ formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" cutoffTime
        endpoint = "sessions?expires_at=lt." <> timeStr
    result <- makeSupabaseRequest adapter endpoint "DELETE" ""
    case result of
      Left err -> return $ Left err
      Right responseBody ->
        -- Supabase returns the deleted rows, so we can count them
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just (sessions :: [SupabaseSession]) -> return $ Right $ length sessions
  
  addUserProvider adapter uid provider = do
    now <- getCurrentTime
    let providerData = object
          [ "user_id" .= uid
          , "provider_name" .= providerName provider
          , "provider_id" .= providerId provider
          , "access_token" .= accessToken provider
          , "refresh_token" .= refreshToken provider
          , "token_expires_at" .= fmap (formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ") (tokenExpiresAt provider)
          , "created_at" .= formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" now
          , "updated_at" .= formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" now
          ]
    
    result <- makeSupabaseRequest adapter "user_providers" "POST" (encode providerData)
    case result of
      Left err -> return $ Left err
      Right _ -> return $ Right ()
  
  removeUserProvider adapter uid provName = do
    let endpoint = "user_providers?user_id=eq." <> uid <> "&provider_name=eq." <> provName
    result <- makeSupabaseRequest adapter endpoint "DELETE" ""
    case result of
      Left err -> return $ Left err
      Right _ -> return $ Right ()
  
  getUserByProvider adapter provName provId = do
    let endpoint = "users?select=*&user_providers!inner(provider_name,provider_id)&user_providers.provider_name=eq." <> provName <> "&user_providers.provider_id=eq." <> provId
    result <- makeSupabaseRequest adapter endpoint "GET" ""
    case result of
      Left err -> return $ Left err
      Right responseBody ->
        case decode responseBody of
          Nothing -> return $ Left $ QueryError "Failed to parse response"
          Just [] -> return $ Right Nothing
          Just (supabaseUser:_) ->
            case supabaseToUser supabaseUser of
              Nothing -> return $ Left $ QueryError "Failed to convert response to User"
              Just user -> return $ Right $ Just user