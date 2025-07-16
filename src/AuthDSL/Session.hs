{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module AuthDSL.Session
  ( SessionManager(..)
  , CookieSessionManager(..)
  , JWTSessionManager(..)
  , UserSession(..)
  , SessionId
  , UserId
  , SessionMetadata(..)
  , SessionError(..)
  , SessionCleanupService(..)
  , DatabaseConnection(..)
  , JWTToken(..)
  , RefreshToken(..)
  , createCookieSessionManager
  , createJWTSessionManager
  , generateJWTToken
  , validateJWTToken
  , startSessionCleanupService
  , stopSessionCleanupService
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime, getCurrentTime, addUTCTime, diffUTCTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID
import Data.Aeson (ToJSON(..), FromJSON(..), object, (.=), (.:), withObject, Result(..), fromJSON, Value(..), encode, decode)
import qualified Data.Aeson.KeyMap as KeyMap
import GHC.Generics (Generic)
import Control.Monad (when)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Exception (Exception, throwIO)
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.STM (STM, TVar, newTVarIO, readTVar, writeTVar, atomically)
import Crypto.Random (MonadRandom, getRandomBytes)
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map as Map
import Data.Map (Map)
import qualified Web.JWT as JWT
import Web.JWT (hmacSecret)

import AuthDSL.Types (CookieConfig(..), JWTConfig(..), Duration(..), Role, Scope)

-- | Session identifier type
type SessionId = Text
type UserId = Text

-- | User session data model
data UserSession = UserSession
  { sessionId :: SessionId
  , userId :: UserId
  , expiresAt :: UTCTime
  , scopes :: [Scope]
  , roles :: [Role]
  , metadata :: SessionMetadata
  , createdAt :: UTCTime
  , lastAccessedAt :: UTCTime
  } deriving (Show, Eq, Generic)

-- | Session metadata for additional context
data SessionMetadata = SessionMetadata
  { userAgent :: Maybe Text
  , ipAddress :: Maybe Text
  , deviceId :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Session-related errors
data SessionError
  = SessionNotFound SessionId
  | SessionExpired SessionId
  | SessionInvalid Text
  | DatabaseError Text
  deriving (Show, Eq)

instance Exception SessionError

-- | Session manager interface
class SessionManager m where
  createSession :: m -> UserId -> [Scope] -> [Role] -> SessionMetadata -> IO (Either SessionError UserSession)
  validateSession :: m -> SessionId -> IO (Either SessionError UserSession)
  destroySession :: m -> SessionId -> IO (Either SessionError ())
  refreshSession :: m -> SessionId -> IO (Either SessionError UserSession)
  cleanupExpiredSessions :: m -> IO (Either SessionError Int)

-- | Cookie-based session manager implementation
data CookieSessionManager = CookieSessionManager
  { cookieConfig :: CookieConfig
  , sessionExpiration :: Int -- seconds
  , databaseConnection :: DatabaseConnection
  , secureRandom :: Bool
  } deriving (Show, Eq)

-- | JWT token wrapper
data JWTToken = JWTToken
  { jwtTokenValue :: Text
  , jwtTokenExpiry :: UTCTime
  } deriving (Show, Eq, Generic)

-- | Refresh token for JWT rotation
data RefreshToken = RefreshToken
  { refreshTokenValue :: Text
  , refreshTokenExpiry :: UTCTime
  , refreshTokenUserId :: UserId
  } deriving (Show, Eq, Generic)

-- | JWT-based session manager implementation
data JWTSessionManager = JWTSessionManager
  { jwtConfig :: JWTConfig
  , jwtSecretKey :: Text -- Store as Text instead of JWT.Secret
  , jwtSessionExpiration :: Int -- seconds
  , refreshTokens :: TVar (Map Text RefreshToken) -- In-memory refresh token store
  , refreshEnabled :: Bool
  } deriving (Eq)

-- | Database connection configuration (implemented in task 4.1)
data DatabaseConnection = DatabaseConnection
  { connType :: Text
  , connString :: Text
  , poolSize :: Int
  , timeout :: Int
  } deriving (Show, Eq)

-- JSON instances for serialization
instance ToJSON UserSession where
  toJSON session = object
    [ "sessionId" .= sessionId session
    , "userId" .= userId session
    , "expiresAt" .= expiresAt session
    , "scopes" .= scopes session
    , "roles" .= roles session
    , "metadata" .= metadata session
    , "createdAt" .= createdAt session
    , "lastAccessedAt" .= lastAccessedAt session
    ]

instance FromJSON UserSession where
  parseJSON = withObject "UserSession" $ \o -> UserSession
    <$> o .: "sessionId"
    <*> o .: "userId"
    <*> o .: "expiresAt"
    <*> o .: "scopes"
    <*> o .: "roles"
    <*> o .: "metadata"
    <*> o .: "createdAt"
    <*> o .: "lastAccessedAt"

instance ToJSON SessionMetadata where
  toJSON metadata = object
    [ "userAgent" .= userAgent metadata
    , "ipAddress" .= ipAddress metadata
    , "deviceId" .= deviceId metadata
    ]

instance FromJSON SessionMetadata where
  parseJSON = withObject "SessionMetadata" $ \o -> SessionMetadata
    <$> o .: "userAgent"
    <*> o .: "ipAddress"
    <*> o .: "deviceId"

instance ToJSON JWTToken where
  toJSON token = object
    [ "token" .= jwtTokenValue token
    , "expiresAt" .= jwtTokenExpiry token
    ]

instance FromJSON JWTToken where
  parseJSON = withObject "JWTToken" $ \o -> JWTToken
    <$> o .: "token"
    <*> o .: "expiresAt"

instance ToJSON RefreshToken where
  toJSON token = object
    [ "refreshToken" .= refreshTokenValue token
    , "expiresAt" .= refreshTokenExpiry token
    , "userId" .= refreshTokenUserId token
    ]

instance FromJSON RefreshToken where
  parseJSON = withObject "RefreshToken" $ \o -> RefreshToken
    <$> o .: "refreshToken"
    <*> o .: "expiresAt"
    <*> o .: "userId"

-- | Create a new cookie session manager
createCookieSessionManager :: CookieConfig -> Int -> DatabaseConnection -> CookieSessionManager
createCookieSessionManager config expiration dbConn = CookieSessionManager
  { cookieConfig = config
  , sessionExpiration = expiration
  , databaseConnection = dbConn
  , secureRandom = True
  }

-- | Create a new JWT session manager
createJWTSessionManager :: JWTConfig -> Int -> IO JWTSessionManager
createJWTSessionManager config expiration = do
  refreshTokensVar <- newTVarIO Map.empty
  return JWTSessionManager
    { jwtConfig = config
    , jwtSecretKey = jwtSecret config
    , jwtSessionExpiration = expiration
    , refreshTokens = refreshTokensVar
    , refreshEnabled = jwtRefreshEnabled config
    }

-- | Generate a cryptographically secure session ID
generateSessionId :: IO SessionId
generateSessionId = do
  randomBytes <- getRandomBytes 32
  return $ T.pack $ BS8.unpack $ B64.encode randomBytes

-- | Check if a session is expired
isSessionExpired :: UserSession -> UTCTime -> Bool
isSessionExpired session currentTime = expiresAt session < currentTime

-- | Calculate expiration time from duration
calculateExpirationTime :: Int -> UTCTime -> UTCTime
calculateExpirationTime seconds currentTime = addUTCTime (fromIntegral seconds) currentTime

-- | Generate a cryptographically secure refresh token
generateRefreshToken :: IO Text
generateRefreshToken = do
  randomBytes <- getRandomBytes 32
  return $ T.pack $ BS8.unpack $ B64.encode randomBytes

-- | Simplified JWT token generation (using base64 encoding for demo purposes)
-- In a production system, you would use a proper JWT library
generateJWTToken :: JWTConfig -> Text -> UserSession -> UTCTime -> JWTToken
generateJWTToken config secretText session currentTime =
  let -- Create a simple token payload (in production, use proper JWT)
      payload = object
        [ "userId" .= userId session
        , "sessionId" .= sessionId session
        , "scopes" .= scopes session
        , "roles" .= roles session
        , "metadata" .= metadata session
        , "exp" .= expiresAt session
        , "iat" .= currentTime
        , "iss" .= jwtIssuer config
        , "aud" .= jwtAudience config
        ]
      -- In production, this would be properly signed
      tokenText = T.pack $ BS8.unpack $ B64.encode $ LBS.toStrict $ encode payload
  in JWTToken
    { jwtTokenValue = tokenText
    , jwtTokenExpiry = expiresAt session
    }

-- | Simplified JWT token validation (using base64 decoding for demo purposes)
-- In a production system, you would use a proper JWT library with signature verification
validateJWTToken :: Text -> Text -> IO (Either SessionError UserSession)
validateJWTToken secretText tokenText = do
  currentTime <- getCurrentTime
  case B64.decode (BS8.pack $ T.unpack tokenText) of
    Left _ -> return $ Left $ SessionInvalid "Invalid JWT token format"
    Right decodedBytes -> 
      case decode (LBS.fromStrict decodedBytes) of
        Nothing -> return $ Left $ SessionInvalid "Invalid JWT payload"
        Just payload -> do
          case extractSessionFromPayload payload currentTime of
            Left err -> return $ Left $ SessionInvalid err
            Right session -> return $ Right session

-- | Extract user session from JWT payload
extractSessionFromPayload :: Value -> UTCTime -> Either Text UserSession
extractSessionFromPayload payload currentTime = do
  case fromJSON payload :: Result (Map Text Value) of
    Error err -> Left $ T.pack $ "Invalid JWT payload: " ++ err
    Success obj -> do
      -- Extract fields from the payload object
      uid <- case Map.lookup "userId" obj of
        Nothing -> Left "JWT missing userId"
        Just val -> case fromJSON val of
          Success userId -> Right userId
          Error err -> Left $ T.pack $ "Invalid userId: " ++ err
      
      sessionIdValue <- case Map.lookup "sessionId" obj of
        Nothing -> Left "JWT missing sessionId"
        Just val -> case fromJSON val of
          Success sid -> Right sid
          Error err -> Left $ T.pack $ "Invalid sessionId: " ++ err
      
      sessionScopes <- case Map.lookup "scopes" obj of
        Nothing -> Right []
        Just val -> case fromJSON val of
          Success scopes -> Right scopes
          Error err -> Left $ T.pack $ "Invalid scopes: " ++ err
      
      sessionRoles <- case Map.lookup "roles" obj of
        Nothing -> Right []
        Just val -> case fromJSON val of
          Success roles -> Right roles
          Error err -> Left $ T.pack $ "Invalid roles: " ++ err
      
      sessionMetadata <- case Map.lookup "metadata" obj of
        Nothing -> Right $ SessionMetadata Nothing Nothing Nothing
        Just val -> case fromJSON val of
          Success metadata -> Right metadata
          Error err -> Left $ T.pack $ "Invalid metadata: " ++ err
      
      expirationTime <- case Map.lookup "exp" obj of
        Nothing -> Left "JWT missing expiration"
        Just val -> case fromJSON val of
          Success exp -> Right exp
          Error err -> Left $ T.pack $ "Invalid expiration: " ++ err
      
      -- Check if token is expired
      if expirationTime < currentTime
        then Left "JWT token expired"
        else Right UserSession
          { sessionId = sessionIdValue
          , userId = uid
          , expiresAt = expirationTime
          , scopes = sessionScopes
          , roles = sessionRoles
          , metadata = sessionMetadata
          , createdAt = currentTime -- Approximation
          , lastAccessedAt = currentTime
          }
  where
    obj = case payload of
      Object o -> Map.fromList [(k, v) | (k, v) <- KeyMap.toList o]
      _ -> Map.empty

-- | Session manager implementation for cookie-based sessions
instance SessionManager CookieSessionManager where
  createSession manager uid sessionScopes sessionRoles sessionMetadata = do
    currentTime <- getCurrentTime
    sessionIdValue <- generateSessionId
    let expirationTime = calculateExpirationTime (sessionExpiration manager) currentTime
        session = UserSession
          { sessionId = sessionIdValue
          , userId = uid
          , expiresAt = expirationTime
          , scopes = sessionScopes
          , roles = sessionRoles
          , metadata = sessionMetadata
          , createdAt = currentTime
          , lastAccessedAt = currentTime
          }
    
    -- Store session in database (placeholder - will be implemented with database adapters)
    result <- storeSessionInDatabase (databaseConnection manager) session
    case result of
      Left err -> return $ Left $ DatabaseError err
      Right _ -> return $ Right session

  validateSession manager sessionIdValue = do
    currentTime <- getCurrentTime
    -- Retrieve session from database (placeholder)
    result <- retrieveSessionFromDatabase (databaseConnection manager) sessionIdValue
    case result of
      Left err -> return $ Left $ DatabaseError err
      Right session -> 
        if isSessionExpired session currentTime
          then do
            -- Clean up expired session
            _ <- deleteSessionFromDatabase (databaseConnection manager) sessionIdValue
            return $ Left $ SessionExpired sessionIdValue
          else do
            -- Update last accessed time
            let updatedSession = session { lastAccessedAt = currentTime }
            _ <- updateSessionInDatabase (databaseConnection manager) updatedSession
            return $ Right updatedSession

  destroySession manager sessionIdValue = do
    result <- deleteSessionFromDatabase (databaseConnection manager) sessionIdValue
    case result of
      Left err -> return $ Left $ DatabaseError err
      Right _ -> return $ Right ()

  refreshSession manager sessionIdValue = do
    currentTime <- getCurrentTime
    result <- retrieveSessionFromDatabase (databaseConnection manager) sessionIdValue
    case result of
      Left err -> return $ Left $ DatabaseError err
      Right session ->
        if isSessionExpired session currentTime
          then return $ Left $ SessionExpired sessionIdValue
          else do
            let newExpirationTime = calculateExpirationTime (sessionExpiration manager) currentTime
                refreshedSession = session 
                  { expiresAt = newExpirationTime
                  , lastAccessedAt = currentTime
                  }
            updateResult <- updateSessionInDatabase (databaseConnection manager) refreshedSession
            case updateResult of
              Left err -> return $ Left $ DatabaseError err
              Right _ -> return $ Right refreshedSession

  cleanupExpiredSessions manager = do
    currentTime <- getCurrentTime
    result <- deleteExpiredSessionsFromDatabase (databaseConnection manager) currentTime
    case result of
      Left err -> return $ Left $ DatabaseError err
      Right count -> return $ Right count

-- | Session manager implementation for JWT-based sessions
instance SessionManager JWTSessionManager where
  createSession manager uid sessionScopes sessionRoles sessionMetadata = do
    currentTime <- getCurrentTime
    sessionIdValue <- generateSessionId
    let expirationTime = calculateExpirationTime (jwtSessionExpiration manager) currentTime
        session = UserSession
          { sessionId = sessionIdValue
          , userId = uid
          , expiresAt = expirationTime
          , scopes = sessionScopes
          , roles = sessionRoles
          , metadata = sessionMetadata
          , createdAt = currentTime
          , lastAccessedAt = currentTime
          }
        jwtToken = generateJWTToken (jwtConfig manager) (jwtSecretKey manager) session currentTime
    
    -- If refresh tokens are enabled, create and store a refresh token
    if refreshEnabled manager
      then do
        refreshTokenValue <- generateRefreshToken
        let refreshTokenExpiry = addUTCTime (fromIntegral $ jwtSessionExpiration manager * 2) currentTime -- Refresh token lasts twice as long
            refreshToken = RefreshToken refreshTokenValue refreshTokenExpiry uid
        atomically $ do
          tokens <- readTVar (refreshTokens manager)
          writeTVar (refreshTokens manager) (Map.insert refreshTokenValue refreshToken tokens)
        return $ Right session
      else return $ Right session

  validateSession manager tokenText = do
    -- For JWT sessions, the sessionId is actually the JWT token
    result <- validateJWTToken (jwtSecretKey manager) tokenText
    case result of
      Left err -> return $ Left err
      Right session -> do
        -- Update last accessed time (this is conceptual since JWT is stateless)
        currentTime <- getCurrentTime
        let updatedSession = session { lastAccessedAt = currentTime }
        return $ Right updatedSession

  destroySession manager tokenText = do
    -- For JWT, we can't truly "destroy" a token since it's stateless
    -- But we can remove any associated refresh token
    if refreshEnabled manager
      then do
        -- Try to find and remove refresh token associated with this session
        -- This is a simplified approach - in practice, you might want to maintain
        -- a blacklist of revoked tokens or use shorter expiration times
        atomically $ do
          tokens <- readTVar (refreshTokens manager)
          let filteredTokens = Map.filter (\rt -> refreshTokenUserId rt /= extractUserIdFromToken tokenText) tokens
          writeTVar (refreshTokens manager) filteredTokens
        return $ Right ()
      else return $ Right ()
    where
      extractUserIdFromToken token = 
        -- For the simplified JWT implementation, extract user ID from the token payload
        case B64.decode (BS8.pack $ T.unpack token) of
          Left _ -> ""
          Right decodedBytes -> 
            case decode (LBS.fromStrict decodedBytes) of
              Nothing -> ""
              Just payload -> 
                let obj = case payload of
                      Object o -> Map.fromList [(k, v) | (k, v) <- KeyMap.toList o]
                      _ -> Map.empty
                in case Map.lookup "userId" obj of
                  Nothing -> ""
                  Just val -> case fromJSON val of
                    Success userId -> userId
                    Error _ -> ""

  refreshSession manager refreshTokenValue = do
    if not (refreshEnabled manager)
      then return $ Left $ SessionInvalid "Refresh tokens not enabled"
      else do
        currentTime <- getCurrentTime
        tokens <- atomically $ readTVar (refreshTokens manager)
        case Map.lookup refreshTokenValue tokens of
          Nothing -> return $ Left $ SessionNotFound refreshTokenValue
          Just refreshToken -> 
            if refreshTokenExpiry refreshToken < currentTime
              then do
                -- Remove expired refresh token
                atomically $ do
                  updatedTokens <- readTVar (refreshTokens manager)
                  writeTVar (refreshTokens manager) (Map.delete refreshTokenValue updatedTokens)
                return $ Left $ SessionExpired refreshTokenValue
              else do
                -- Create new session with extended expiration
                let uid = refreshTokenUserId refreshToken
                    newExpirationTime = calculateExpirationTime (jwtSessionExpiration manager) currentTime
                sessionIdValue <- generateSessionId
                let newSession = UserSession
                      { sessionId = sessionIdValue
                      , userId = uid
                      , expiresAt = newExpirationTime
                      , scopes = [] -- Default scopes - could be stored in refresh token
                      , roles = [] -- Default roles - could be stored in refresh token
                      , metadata = SessionMetadata Nothing Nothing Nothing
                      , createdAt = currentTime
                      , lastAccessedAt = currentTime
                      }
                
                -- Generate new refresh token
                newRefreshTokenValue <- generateRefreshToken
                let newRefreshTokenExpiry = addUTCTime (fromIntegral $ jwtSessionExpiration manager * 2) currentTime
                    newRefreshToken = RefreshToken newRefreshTokenValue newRefreshTokenExpiry uid
                
                -- Update refresh tokens map
                atomically $ do
                  updatedTokens <- readTVar (refreshTokens manager)
                  let tokensWithoutOld = Map.delete refreshTokenValue updatedTokens
                      tokensWithNew = Map.insert newRefreshTokenValue newRefreshToken tokensWithoutOld
                  writeTVar (refreshTokens manager) tokensWithNew
                
                return $ Right newSession

  cleanupExpiredSessions manager = do
    if not (refreshEnabled manager)
      then return $ Right 0 -- No cleanup needed for stateless JWT
      else do
        currentTime <- getCurrentTime
        atomically $ do
          tokens <- readTVar (refreshTokens manager)
          let (expiredTokens, validTokens) = Map.partition (\rt -> refreshTokenExpiry rt < currentTime) tokens
          writeTVar (refreshTokens manager) validTokens
          return $ Right $ Map.size expiredTokens

-- | Database operations (placeholder implementations - will be implemented with database adapters)
storeSessionInDatabase :: DatabaseConnection -> UserSession -> IO (Either Text ())
storeSessionInDatabase _conn _session = do
  -- Placeholder - will be implemented in task 4.1
  return $ Right ()

retrieveSessionFromDatabase :: DatabaseConnection -> SessionId -> IO (Either Text UserSession)
retrieveSessionFromDatabase _conn _sessionId = do
  -- Placeholder - will be implemented in task 4.1
  currentTime <- getCurrentTime
  let placeholderSession = UserSession
        { sessionId = _sessionId
        , userId = "placeholder-user"
        , expiresAt = addUTCTime 3600 currentTime -- 1 hour from now
        , scopes = ["read"]
        , roles = ["user"]
        , metadata = SessionMetadata Nothing Nothing Nothing
        , createdAt = currentTime
        , lastAccessedAt = currentTime
        }
  return $ Right placeholderSession

updateSessionInDatabase :: DatabaseConnection -> UserSession -> IO (Either Text ())
updateSessionInDatabase _conn _session = do
  -- Placeholder - will be implemented in task 4.1
  return $ Right ()

deleteSessionFromDatabase :: DatabaseConnection -> SessionId -> IO (Either Text ())
deleteSessionFromDatabase _conn _sessionId = do
  -- Placeholder - will be implemented in task 4.1
  return $ Right ()

deleteExpiredSessionsFromDatabase :: DatabaseConnection -> UTCTime -> IO (Either Text Int)
deleteExpiredSessionsFromDatabase _conn _currentTime = do
  -- Placeholder - will be implemented in task 4.1
  return $ Right 0

-- | Session cleanup service for background garbage collection
data SessionCleanupService = SessionCleanupService
  { cleanupManager :: CookieSessionManager
  , cleanupInterval :: Int -- seconds
  , cleanupRunning :: TVar Bool
  } deriving (Eq)

-- | Start the session cleanup service
startSessionCleanupService :: CookieSessionManager -> Int -> IO SessionCleanupService
startSessionCleanupService manager intervalSeconds = do
  runningVar <- newTVarIO True
  let service = SessionCleanupService manager intervalSeconds runningVar
  
  -- Start background cleanup thread
  _ <- forkIO $ cleanupLoop service
  
  return service
  where
    cleanupLoop service = do
      isRunning <- atomically $ readTVar (cleanupRunning service)
      if isRunning
        then do
          -- Perform cleanup
          result <- cleanupExpiredSessions (cleanupManager service)
          case result of
            Left err -> putStrLn $ "Session cleanup error: " ++ show err
            Right count -> when (count > 0) $ 
              putStrLn $ "Cleaned up " ++ show count ++ " expired sessions"
          
          -- Wait for the specified interval
          threadDelay (cleanupInterval service * 1000000) -- Convert to microseconds
          cleanupLoop service
        else return ()

-- | Stop the session cleanup service
stopSessionCleanupService :: SessionCleanupService -> IO ()
stopSessionCleanupService service = do
  atomically $ writeTVar (cleanupRunning service) False

-- | Helper function to check if cleanup service is running
isCleanupServiceRunning :: SessionCleanupService -> IO Bool
isCleanupServiceRunning service = atomically $ readTVar (cleanupRunning service)