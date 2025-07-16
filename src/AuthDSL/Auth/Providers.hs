{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}

module AuthDSL.Auth.Providers
  ( AuthProvider(..)
  , AuthResult(..)
  , AuthError(..)
  , UserInfo(..)
  , AuthRedirect(..)
  , CallbackData(..)
  , SessionToken(..)
  , UserId(..)
  , ProviderState(..)
  , GoogleOAuthProvider(..)
  , PasswordAuthProvider(..)
  , StateStore(..)
  , AttemptStore(..)
  , initiateAuth
  , handleCallback
  , validateSession
  , createGoogleProvider
  , createPasswordProvider
  , authenticatePassword
  , registerPassword
  , createInMemoryStateStore
  , createInMemoryAttemptStore
  , createGoogleProviderWithMemoryStore
  , createPasswordProviderWithMemoryStore
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime, getCurrentTime, addUTCTime, diffUTCTime)
import GHC.Generics (Generic)
import Data.Aeson (ToJSON, FromJSON, decode, encode, object, (.=), (.:), (.:?))
import qualified Data.Aeson as A
import Data.Aeson.Types (parseMaybe)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Network.HTTP.Simple
import Network.HTTP.Types.Status (statusCode)
import Network.HTTP.Types.URI (urlEncode)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.ByteString.Char8 as BS
import System.Random (randomRIO)
import Control.Monad (when)
import Control.Exception (try, SomeException)
import Crypto.Random (getRandomBytes)
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text.Encoding as TE
import Crypto.BCrypt (hashPasswordUsingPolicy, validatePassword, slowerBcryptHashingPolicy)
import Control.Concurrent.STM (STM, TVar, newTVarIO, readTVar, writeTVar, atomically, modifyTVar')
import qualified Data.Map as Map
import Data.Map (Map)

import AuthDSL.Types (GoogleConfig(..), PasswordConfig(..), ProviderName, Duration(..))

-- | Authentication result type
data AuthResult
  = AuthSuccess UserInfo SessionToken
  | AuthRedirectResult AuthRedirect
  | AuthFailure AuthError
  deriving (Show, Eq, Generic)

-- | Authentication error types
data AuthError
  = InvalidCredentials Text
  | ProviderError Text Text -- provider name, error message
  | TokenExpired
  | InvalidToken
  | RateLimited
  | AccountLocked UTCTime -- unlock time
  | NetworkError Text
  | ConfigurationError Text
  deriving (Show, Eq, Generic)

-- | User information returned from authentication
data UserInfo = UserInfo
  { userEmail :: Text
  , userName :: Maybe Text
  , userAvatar :: Maybe Text
  , userProviderId :: Text
  , userProviderName :: ProviderName
  , userMetadata :: [(Text, Text)]
  } deriving (Show, Eq, Generic)

instance ToJSON UserInfo
instance FromJSON UserInfo

-- | Authentication redirect information
data AuthRedirect = AuthRedirect
  { redirectUrl :: Text
  , redirectState :: Text
  } deriving (Show, Eq, Generic)

instance ToJSON AuthRedirect
instance FromJSON AuthRedirect

-- | OAuth callback data
data CallbackData = CallbackData
  { callbackCode :: Maybe Text
  , callbackState :: Maybe Text
  , callbackError :: Maybe Text
  , callbackErrorDescription :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Session token wrapper
newtype SessionToken = SessionToken Text
  deriving (Show, Eq, Generic)

-- | User ID wrapper
newtype UserId = UserId Text
  deriving (Show, Eq, Generic)

-- | Provider state for OAuth flows
data ProviderState = ProviderState
  { stateValue :: Text
  , stateNonce :: Text
  , stateCreatedAt :: UTCTime
  , stateRedirectUri :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Authentication provider typeclass
class AuthProvider p where
  initiateAuth :: MonadIO m => p -> Maybe UserId -> m AuthResult
  handleCallback :: MonadIO m => p -> CallbackData -> m AuthResult
  validateSession :: MonadIO m => p -> SessionToken -> m (Either AuthError UserInfo)

-- | Google OAuth2 provider implementation
data GoogleOAuthProvider = GoogleOAuthProvider
  { googleConfig :: GoogleConfig
  , googleStateStore :: StateStore
  } deriving (Generic)

-- | Password authentication provider implementation
data PasswordAuthProvider = PasswordAuthProvider
  { passwordConfig :: PasswordConfig
  , passwordAttemptStore :: AttemptStore
  } deriving (Generic)

-- | State storage interface for OAuth flows
data StateStore = StateStore
  { storeState :: Text -> ProviderState -> IO ()
  , retrieveState :: Text -> IO (Maybe ProviderState)
  , cleanupExpiredStates :: IO ()
  }

-- | Attempt tracking for password authentication
data AttemptStore = AttemptStore
  { recordAttempt :: Text -> Bool -> IO () -- email, success
  , getAttemptCount :: Text -> IO Int
  , isAccountLocked :: Text -> IO (Maybe UTCTime) -- returns unlock time if locked
  , lockAccount :: Text -> UTCTime -> IO ()
  , unlockAccount :: Text -> IO ()
  }

-- | Create Google OAuth2 provider
createGoogleProvider :: GoogleConfig -> StateStore -> GoogleOAuthProvider
createGoogleProvider config stateStore = GoogleOAuthProvider
  { googleConfig = config
  , googleStateStore = stateStore
  }

-- | Create password authentication provider
createPasswordProvider :: PasswordConfig -> AttemptStore -> PasswordAuthProvider
createPasswordProvider config attemptStore = PasswordAuthProvider
  { passwordConfig = config
  , passwordAttemptStore = attemptStore
  }

-- Google OAuth2 Provider Implementation

-- | Google OAuth2 endpoints
googleAuthUrl :: Text
googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth"

googleTokenUrl :: Text
googleTokenUrl = "https://oauth2.googleapis.com/token"

googleUserInfoUrl :: Text
googleUserInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo"

-- | Google OAuth2 provider instance
instance AuthProvider GoogleOAuthProvider where
  initiateAuth provider maybeUserId = do
    -- Generate secure random state
    state <- generateSecureState
    nonce <- generateNonce
    currentTime <- liftIO getCurrentTime
    
    let config = googleConfig provider
        stateStore = googleStateStore provider
        redirectUri = googleRedirectUri config
        scopes = T.intercalate " " (googleScopes config)
        
        -- Create provider state
        providerState = ProviderState
          { stateValue = state
          , stateNonce = nonce
          , stateCreatedAt = currentTime
          , stateRedirectUri = redirectUri
          }
    
    -- Store state for later validation
    liftIO $ storeState stateStore state providerState
    
    -- Build authorization URL
    let authUrl = buildGoogleAuthUrl config state scopes redirectUri
        redirect = AuthRedirect
          { redirectUrl = authUrl
          , redirectState = state
          }
    
    return $ AuthRedirectResult redirect

  handleCallback provider callbackData = do
    case (callbackCode callbackData, callbackState callbackData) of
      (Just code, Just state) -> do
        -- Validate state parameter
        stateValidation <- validateState (googleStateStore provider) state
        case stateValidation of
          Left err -> return $ AuthFailure err
          Right providerState -> do
            -- Exchange authorization code for access token
            tokenResult <- exchangeCodeForToken (googleConfig provider) code (stateRedirectUri providerState)
            case tokenResult of
              Left err -> return $ AuthFailure err
              Right accessToken -> do
                -- Fetch user profile information
                userResult <- fetchGoogleUserInfo accessToken
                case userResult of
                  Left err -> return $ AuthFailure err
                  Right userInfo -> do
                    -- Create session token (placeholder - would integrate with session manager)
                    sessionToken <- generateSessionToken userInfo
                    return $ AuthSuccess userInfo sessionToken
      
      (Nothing, _) -> 
        case callbackError callbackData of
          Just "access_denied" -> return $ AuthFailure $ ProviderError "google" "User denied access"
          Just err -> return $ AuthFailure $ ProviderError "google" err
          Nothing -> return $ AuthFailure $ ProviderError "google" "Missing authorization code"
      
      (_, Nothing) -> return $ AuthFailure $ ProviderError "google" "Missing state parameter"

  validateSession provider sessionToken = do
    -- For now, this is a placeholder implementation
    -- In a real implementation, this would validate the session token
    -- against the session store and return user information
    return $ Left InvalidToken

-- | Build Google OAuth2 authorization URL
buildGoogleAuthUrl :: GoogleConfig -> Text -> Text -> Maybe Text -> Text
buildGoogleAuthUrl config state scopes maybeRedirectUri =
  let baseUrl = googleAuthUrl
      clientId = googleClientId config
      redirectUri = case maybeRedirectUri of
        Just uri -> uri
        Nothing -> "http://localhost:8080/auth/callback/google" -- default
      responseType = "code"
      accessType = "offline"
      
      params = 
        [ ("client_id", clientId)
        , ("redirect_uri", redirectUri)
        , ("response_type", responseType)
        , ("scope", scopes)
        , ("state", state)
        , ("access_type", accessType)
        , ("prompt", "consent")
        ]
      
      queryString = T.intercalate "&" $ map (\(k, v) -> k <> "=" <> urlEncodeText v) params
  in baseUrl <> "?" <> queryString

-- | URL encode text
urlEncodeText :: Text -> Text
urlEncodeText = T.pack . BS.unpack . urlEncode False . TE.encodeUtf8

-- | Generate secure random state
generateSecureState :: MonadIO m => m Text
generateSecureState = do
  randomBytes <- liftIO $ getRandomBytes 32
  return $ TE.decodeUtf8 $ B64.encode randomBytes

-- | Generate nonce for additional security
generateNonce :: MonadIO m => m Text
generateNonce = do
  randomBytes <- liftIO $ getRandomBytes 16
  return $ TE.decodeUtf8 $ B64.encode randomBytes

-- | Validate OAuth state parameter
validateState :: MonadIO m => StateStore -> Text -> m (Either AuthError ProviderState)
validateState stateStore state = do
  maybeState <- liftIO $ retrieveState stateStore state
  case maybeState of
    Nothing -> return $ Left $ ProviderError "google" "Invalid or expired state parameter"
    Just providerState -> do
      currentTime <- liftIO getCurrentTime
      let stateAge = diffUTCTime currentTime (stateCreatedAt providerState)
      if stateAge > 600 -- 10 minutes expiry
        then return $ Left $ ProviderError "google" "State parameter expired"
        else return $ Right providerState

-- | Exchange authorization code for access token
exchangeCodeForToken :: MonadIO m => GoogleConfig -> Text -> Maybe Text -> m (Either AuthError Text)
exchangeCodeForToken config code maybeRedirectUri = do
  let clientId = googleClientId config
      clientSecret = googleClientSecret config
      redirectUri = case maybeRedirectUri of
        Just uri -> uri
        Nothing -> "http://localhost:8080/auth/callback/google"
      
      requestBody = object
        [ "client_id" .= clientId
        , "client_secret" .= clientSecret
        , "code" .= code
        , "grant_type" .= ("authorization_code" :: Text)
        , "redirect_uri" .= redirectUri
        ]
  
  result <- liftIO $ try $ do
    request <- parseRequest $ T.unpack googleTokenUrl
    let request' = setRequestMethod "POST"
                 $ setRequestHeader "Content-Type" ["application/json"]
                 $ setRequestBodyJSON requestBody
                 $ request
    
    response <- httpLBS request'
    return (getResponseStatusCode response, getResponseBody response)
  
  case result of
    Left (ex :: SomeException) -> 
      return $ Left $ NetworkError $ "Failed to exchange code for token: " <> T.pack (show ex)
    Right (statusCode', body) -> 
      if statusCode' == 200
        then parseTokenResponse body
        else return $ Left $ ProviderError "google" $ "Token exchange failed with status: " <> T.pack (show statusCode')

-- | Parse token response from Google
parseTokenResponse :: MonadIO m => ByteString -> m (Either AuthError Text)
parseTokenResponse body = do
  case decode body of
    Nothing -> return $ Left $ ProviderError "google" "Failed to parse token response"
    Just tokenData -> 
      case parseMaybe (.: "access_token") tokenData of
        Nothing -> return $ Left $ ProviderError "google" "No access token in response"
        Just accessToken -> return $ Right accessToken

-- | Fetch user information from Google
fetchGoogleUserInfo :: MonadIO m => Text -> m (Either AuthError UserInfo)
fetchGoogleUserInfo accessToken = do
  result <- liftIO $ try $ do
    request <- parseRequest $ T.unpack googleUserInfoUrl
    let request' = setRequestHeader "Authorization" [TE.encodeUtf8 $ "Bearer " <> accessToken] request
    
    response <- httpLBS request'
    return (getResponseStatusCode response, getResponseBody response)
  
  case result of
    Left (ex :: SomeException) -> 
      return $ Left $ NetworkError $ "Failed to fetch user info: " <> T.pack (show ex)
    Right (statusCode', body) -> 
      if statusCode' == 200
        then parseUserInfoResponse body
        else return $ Left $ ProviderError "google" $ "User info fetch failed with status: " <> T.pack (show statusCode')

-- | Parse user info response from Google
parseUserInfoResponse :: MonadIO m => ByteString -> m (Either AuthError UserInfo)
parseUserInfoResponse body = do
  case decode body of
    Nothing -> return $ Left $ ProviderError "google" "Failed to parse user info response"
    Just userData -> do
      let parseUser = do
            email <- userData .: "email"
            providerId <- userData .: "id"
            name <- userData .:? "name"
            picture <- userData .:? "picture"
            return $ UserInfo
              { userEmail = email
              , userName = name
              , userAvatar = picture
              , userProviderId = providerId
              , userProviderName = "google"
              , userMetadata = []
              }
      
      case parseMaybe (const parseUser) userData of
        Nothing -> return $ Left $ ProviderError "google" "Failed to parse user data"
        Just userInfo -> return $ Right userInfo

-- | Generate session token (placeholder implementation)
generateSessionToken :: MonadIO m => UserInfo -> m SessionToken
generateSessionToken userInfo = do
  -- This is a placeholder - in a real implementation, this would
  -- integrate with the session manager to create a proper session
  randomBytes <- liftIO $ getRandomBytes 32
  let token = TE.decodeUtf8 $ B64.encode randomBytes
  return $ SessionToken token

-- Password Authentication Provider Implementation

-- | Password authentication provider instance
instance AuthProvider PasswordAuthProvider where
  initiateAuth provider maybeUserId = do
    -- Password authentication doesn't use redirects - this should not be called
    -- for password auth. Return an error.
    return $ AuthFailure $ ConfigurationError "Password authentication does not support redirect-based initiation"

  handleCallback provider callbackData = do
    -- Password authentication doesn't use callbacks - this should not be called
    -- for password auth. Return an error.
    return $ AuthFailure $ ConfigurationError "Password authentication does not support callback handling"

  validateSession provider sessionToken = do
    -- For now, this is a placeholder implementation
    -- In a real implementation, this would validate the session token
    -- against the session store and return user information
    return $ Left InvalidToken

-- | Authenticate user with email and password
authenticatePassword :: MonadIO m => PasswordAuthProvider -> Text -> Text -> m AuthResult
authenticatePassword provider email password = do
  let config = passwordConfig provider
      attemptStore = passwordAttemptStore provider
  
  -- Check if account is locked
  lockStatus <- liftIO $ isAccountLocked attemptStore email
  case lockStatus of
    Just unlockTime -> do
      currentTime <- liftIO getCurrentTime
      if currentTime < unlockTime
        then return $ AuthFailure $ AccountLocked unlockTime
        else do
          liftIO $ unlockAccount attemptStore email -- Auto-unlock expired locks
          -- Continue with authentication after unlocking
          authenticatePasswordInternal provider email password
    Nothing -> authenticatePasswordInternal provider email password

-- | Internal password authentication logic
authenticatePasswordInternal :: MonadIO m => PasswordAuthProvider -> Text -> Text -> m AuthResult
authenticatePasswordInternal provider email password = do
  let config = passwordConfig provider
      attemptStore = passwordAttemptStore provider
  
  -- Validate password (this would typically involve database lookup)
  -- For now, this is a placeholder that would integrate with the database layer
  passwordValid <- validateUserPassword email password
  
  if passwordValid
    then do
      -- Record successful attempt
      liftIO $ recordAttempt attemptStore email True
      
      -- Create user info (placeholder - would come from database)
      let userInfo = UserInfo
            { userEmail = email
            , userName = Nothing
            , userAvatar = Nothing
            , userProviderId = email -- Use email as provider ID for password auth
            , userProviderName = "password"
            , userMetadata = []
            }
      
      -- Generate session token
      sessionToken <- generateSessionToken userInfo
      return $ AuthSuccess userInfo sessionToken
    else do
      -- Record failed attempt
      liftIO $ recordAttempt attemptStore email False
      
      -- Check if we should lock the account
      attemptCount <- liftIO $ getAttemptCount attemptStore email
      if attemptCount >= passwordMaxAttempts config
        then do
          currentTime <- liftIO getCurrentTime
          let lockDuration = durationToSeconds (passwordLockoutDuration config)
              unlockTime = addUTCTime (fromIntegral lockDuration) currentTime
          liftIO $ lockAccount attemptStore email unlockTime
          return $ AuthFailure $ AccountLocked unlockTime
        else return $ AuthFailure $ InvalidCredentials "Invalid email or password"

-- | Register new user with password
registerPassword :: MonadIO m => PasswordAuthProvider -> Text -> Text -> m AuthResult
registerPassword provider email password = do
  let config = passwordConfig provider
  
  -- Validate password strength
  passwordValidation <- validatePasswordStrength config password
  case passwordValidation of
    Left err -> return $ AuthFailure err
    Right _ -> do
      -- Hash password
      hashedPassword <- hashPassword password
      case hashedPassword of
        Left err -> return $ AuthFailure err
        Right hash -> do
          -- Store user in database (placeholder - would integrate with database layer)
          userCreated <- createUser email hash
          if userCreated
            then do
              let userInfo = UserInfo
                    { userEmail = email
                    , userName = Nothing
                    , userAvatar = Nothing
                    , userProviderId = email
                    , userProviderName = "password"
                    , userMetadata = []
                    }
              sessionToken <- generateSessionToken userInfo
              return $ AuthSuccess userInfo sessionToken
            else return $ AuthFailure $ ProviderError "password" "Failed to create user account"

-- | Validate password strength according to configuration
validatePasswordStrength :: MonadIO m => PasswordConfig -> Text -> m (Either AuthError ())
validatePasswordStrength config password = do
  let minLength = passwordMinLength config
      requireSpecial = passwordRequireSpecial config
      requireNumbers = passwordRequireNumbers config
      requireUppercase = passwordRequireUppercase config
      
      passwordText = T.unpack password
      
      -- Check minimum length
      lengthValid = T.length password >= minLength
      
      -- Check for special characters
      specialValid = not requireSpecial || any (`elem` ("!@#$%^&*()_+-=[]{}|;:,.<>?" :: String)) passwordText
      
      -- Check for numbers
      numbersValid = not requireNumbers || any (`elem` ("0123456789" :: String)) passwordText
      
      -- Check for uppercase letters
      uppercaseValid = not requireUppercase || any (`elem` ("ABCDEFGHIJKLMNOPQRSTUVWXYZ" :: String)) passwordText
  
  if not lengthValid
    then return $ Left $ InvalidCredentials $ "Password must be at least " <> T.pack (show minLength) <> " characters long"
    else if not specialValid
      then return $ Left $ InvalidCredentials "Password must contain at least one special character"
      else if not numbersValid
        then return $ Left $ InvalidCredentials "Password must contain at least one number"
        else if not uppercaseValid
          then return $ Left $ InvalidCredentials "Password must contain at least one uppercase letter"
          else return $ Right ()

-- | Hash password using bcrypt
hashPassword :: MonadIO m => Text -> m (Either AuthError Text)
hashPassword password = do
  result <- liftIO $ hashPasswordUsingPolicy slowerBcryptHashingPolicy (TE.encodeUtf8 password)
  case result of
    Nothing -> return $ Left $ ProviderError "password" "Failed to hash password"
    Just hash -> return $ Right $ TE.decodeUtf8 hash

-- | Convert Duration to seconds (helper function)
durationToSeconds :: Duration -> Int
durationToSeconds (Duration value unit) = case unit of
  "seconds" -> value
  "minutes" -> value * 60
  "hours" -> value * 3600
  "days" -> value * 86400
  _ -> value -- default to seconds

-- Placeholder functions that would integrate with the database layer

-- | Validate user password against stored hash (placeholder)
-- In a real implementation, this would integrate with the database layer
validateUserPassword :: MonadIO m => Text -> Text -> m Bool
validateUserPassword email password = do
  -- This would typically:
  -- 1. Look up user by email in database
  -- 2. Get stored password hash
  -- 3. Validate password against hash using bcrypt
  -- For now, we'll simulate a simple check for demonstration
  -- In a real implementation, this would use the database adapter
  if email == "test@example.com" && password == "password123"
    then return True
    else return False

-- | Create new user in database (placeholder)
-- In a real implementation, this would integrate with the database layer
createUser :: MonadIO m => Text -> Text -> m Bool
createUser email hashedPassword = do
  -- This would typically:
  -- 1. Check if user already exists
  -- 2. Insert new user record with hashed password
  -- 3. Return success/failure
  -- For now, we'll simulate successful user creation for demonstration
  -- In a real implementation, this would use the database adapter
  liftIO $ putStrLn $ "Creating user with email: " <> T.unpack email
  liftIO $ putStrLn $ "Password hash: " <> T.unpack (T.take 20 hashedPassword) <> "..."
  return True

-- In-Memory Implementations for Development and Testing

-- | In-memory state store implementation for OAuth flows
data InMemoryStateStore = InMemoryStateStore
  { stateMap :: TVar (Map Text ProviderState)
  }

-- | Create an in-memory state store
createInMemoryStateStore :: IO StateStore
createInMemoryStateStore = do
  stateMapVar <- newTVarIO Map.empty
  let store = InMemoryStateStore stateMapVar
  return StateStore
    { storeState = \key state -> atomically $ modifyTVar' stateMapVar (Map.insert key state)
    , retrieveState = \key -> atomically $ do
        stateMap' <- readTVar stateMapVar
        return $ Map.lookup key stateMap'
    , cleanupExpiredStates = do
        currentTime <- getCurrentTime
        atomically $ modifyTVar' stateMapVar $ Map.filter $ \state ->
          let age = diffUTCTime currentTime (stateCreatedAt state)
          in age <= 600 -- Keep states for 10 minutes
    }

-- | In-memory attempt store implementation for password authentication
data InMemoryAttemptStore = InMemoryAttemptStore
  { attemptMap :: TVar (Map Text Int) -- email -> attempt count
  , lockMap :: TVar (Map Text UTCTime) -- email -> unlock time
  }

-- | Create an in-memory attempt store
createInMemoryAttemptStore :: IO AttemptStore
createInMemoryAttemptStore = do
  attemptMapVar <- newTVarIO Map.empty
  lockMapVar <- newTVarIO Map.empty
  let store = InMemoryAttemptStore attemptMapVar lockMapVar
  return AttemptStore
    { recordAttempt = \email success -> atomically $ do
        if success
          then do
            -- Reset attempt count on successful login
            modifyTVar' attemptMapVar (Map.delete email)
            modifyTVar' lockMapVar (Map.delete email)
          else do
            -- Increment attempt count on failed login
            modifyTVar' attemptMapVar $ \attempts ->
              Map.insertWith (+) email 1 attempts
    , getAttemptCount = \email -> atomically $ do
        attempts <- readTVar attemptMapVar
        return $ Map.findWithDefault 0 email attempts
    , isAccountLocked = \email -> do
        currentTime <- getCurrentTime
        atomically $ do
          locks <- readTVar lockMapVar
          case Map.lookup email locks of
            Nothing -> return Nothing
            Just unlockTime -> do
              if currentTime >= unlockTime
                then do
                  -- Auto-cleanup expired locks
                  modifyTVar' lockMapVar (Map.delete email)
                  modifyTVar' attemptMapVar (Map.delete email)
                  return Nothing
                else return $ Just unlockTime
    , lockAccount = \email unlockTime -> atomically $ do
        modifyTVar' lockMapVar (Map.insert email unlockTime)
    , unlockAccount = \email -> atomically $ do
        modifyTVar' lockMapVar (Map.delete email)
        modifyTVar' attemptMapVar (Map.delete email)
    }

-- | Helper function to create a Google OAuth provider with in-memory state store
createGoogleProviderWithMemoryStore :: GoogleConfig -> IO GoogleOAuthProvider
createGoogleProviderWithMemoryStore config = do
  stateStore <- createInMemoryStateStore
  return $ createGoogleProvider config stateStore

-- | Helper function to create a password auth provider with in-memory attempt store
createPasswordProviderWithMemoryStore :: PasswordConfig -> IO PasswordAuthProvider
createPasswordProviderWithMemoryStore config = do
  attemptStore <- createInMemoryAttemptStore
  return $ createPasswordProvider config attemptStore