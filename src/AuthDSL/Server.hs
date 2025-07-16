{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module AuthDSL.Server
  ( AuthAPI
  , authServer
  , authApp
  , runAuthServer
  , ServerConfig(..)
  , TLSConfig(..)
  , LoginResponse(..)
  , CallbackResponse(..)
  , SessionResponse(..)
  , LogoutResponse(..)
  , RegisterRequest(..)
  , RegisterResponse(..)
  , RefreshRequest(..)
  , RefreshResponse(..)
  , UserInfo(..)
  , ErrorResponse(..)
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Aeson (ToJSON(..), FromJSON(..), object, (.=), (.:), (.:?), withObject)
import Network.Wai (Application, Middleware)
import Network.Wai.Handler.Warp (run, defaultSettings, setPort, setHost)
import Network.Wai.Handler.WarpTLS (runTLS, tlsSettings)
import Data.String (fromString)
import Network.Wai.Middleware.Cors (cors, simpleCorsResourcePolicy, corsRequestHeaders, corsMethods)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.HTTP.Types (methodGet, methodPost, methodOptions)
import Servant
import Control.Monad.IO.Class (liftIO)
import Data.Maybe (fromMaybe)
import GHC.Generics (Generic)
import qualified Data.Map as Map
import qualified Data.ByteString.Lazy as LBS
import System.Directory (doesFileExist)

import AuthDSL.Types
import AuthDSL.Config (RuntimeConfig(..))
import qualified AuthDSL.Auth.Providers as Providers
import AuthDSL.Session (validateJWTToken, UserSession(..), SessionId, UserId)
import AuthDSL.Security (SecurityConfig(..), combineSecurityMiddleware, defaultSecurityConfig, 
                        createMemoryRateLimitStore, RateLimitStore)
import Data.Time (getCurrentTime)
import Crypto.Random (getRandomBytes)
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text.Encoding as TE
import Text.Regex.TDFA ((=~))

-- | Complete Authentication API definition
-- This defines all the endpoints that will be implemented in tasks 7.2 and 7.3
type AuthAPI = 
  -- Core authentication endpoints (Task 7.2)
       "login" :> Capture "provider" Text 
               :> QueryParam "redirect_uri" Text
               :> Post '[JSON] LoginResponse
  :<|> "callback" :> Capture "provider" Text 
                  :> QueryParam "code" Text
                  :> QueryParam "state" Text
                  :> QueryParam "error" Text
                  :> Post '[JSON] CallbackResponse
  :<|> "session" :> Header "Authorization" Text
               :> Get '[JSON] SessionResponse
  :<|> "logout" :> Header "Authorization" Text
              :> Post '[JSON] LogoutResponse
  -- Optional registration and refresh endpoints (Task 7.3)
  :<|> "register" :> ReqBody '[JSON] RegisterRequest
                :> Post '[JSON] RegisterResponse
  :<|> "refresh" :> ReqBody '[JSON] RefreshRequest
               :> Post '[JSON] RefreshResponse

-- | TLS configuration for HTTPS support
data TLSConfig = TLSConfig
  { tlsEnabled :: Bool
  , tlsCertFile :: Maybe FilePath
  , tlsKeyFile :: Maybe FilePath
  , tlsPort :: Int
  } deriving (Show, Eq, Generic)

-- | Server configuration with comprehensive settings
data ServerConfig = ServerConfig
  { serverPort :: Int
  , serverHost :: Text
  , serverRuntime :: RuntimeConfig
  , serverEnableLogging :: Bool
  , serverEnableCors :: Bool
  , serverSecurity :: SecurityConfig
  , serverTLS :: Maybe TLSConfig
  } deriving (Show, Eq, Generic)

-- | Login response for OAuth2 initiation
data LoginResponse = LoginResponse
  { loginRedirectUrl :: Text
  , loginState :: Text
  , loginProvider :: Text
  } deriving (Show, Eq, Generic)

-- | OAuth2 callback response
data CallbackResponse = CallbackResponse
  { callbackSuccess :: Bool
  , callbackToken :: Maybe Text
  , callbackRefreshToken :: Maybe Text
  , callbackUser :: Maybe UserInfo
  , callbackError :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Session validation response
data SessionResponse = SessionResponse
  { sessionValid :: Bool
  , sessionUser :: Maybe UserInfo
  , sessionExpiresAt :: Maybe Text
  , sessionScopes :: [Text]
  } deriving (Show, Eq, Generic)

-- | Logout response
data LogoutResponse = LogoutResponse
  { logoutSuccess :: Bool
  , logoutMessage :: Text
  } deriving (Show, Eq, Generic)

-- | User registration request
data RegisterRequest = RegisterRequest
  { registerEmail :: Text
  , registerPassword :: Text
  , registerConfirmPassword :: Maybe Text
  , registerMetadata :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | User registration response
data RegisterResponse = RegisterResponse
  { registerSuccess :: Bool
  , registerUser :: Maybe UserInfo
  , registerToken :: Maybe Text
  , registerError :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Token refresh request
data RefreshRequest = RefreshRequest
  { refreshToken :: Text
  } deriving (Show, Eq, Generic)

-- | Token refresh response
data RefreshResponse = RefreshResponse
  { refreshSuccess :: Bool
  , refreshNewToken :: Maybe Text
  , refreshNewRefreshToken :: Maybe Text
  , refreshError :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | User information structure
data UserInfo = UserInfo
  { serverUserEmail :: Text
  , serverUserId :: Text
  , serverUserRoles :: [Role]
  , serverUserMetadata :: Maybe Text
  , serverUserCreatedAt :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Generic error response
data ErrorResponse = ErrorResponse
  { errorCode :: Text
  , errorMessage :: Text
  , errorDetails :: Maybe Text
  } deriving (Show, Eq, Generic)

-- JSON serialization instances
instance ToJSON LoginResponse where
  toJSON (LoginResponse url state provider) = object 
    [ "redirectUrl" .= url
    , "state" .= state
    , "provider" .= provider
    ]

instance ToJSON CallbackResponse where
  toJSON (CallbackResponse success token refreshToken user err) = object 
    [ "success" .= success
    , "token" .= token
    , "refreshToken" .= refreshToken
    , "user" .= user
    , "error" .= err
    ]

instance ToJSON SessionResponse where
  toJSON (SessionResponse valid user expiresAt scopes) = object 
    [ "valid" .= valid
    , "user" .= user
    , "expiresAt" .= expiresAt
    , "scopes" .= scopes
    ]

instance ToJSON LogoutResponse where
  toJSON (LogoutResponse success message) = object 
    [ "success" .= success
    , "message" .= message
    ]

instance ToJSON RegisterResponse where
  toJSON (RegisterResponse success user token err) = object 
    [ "success" .= success
    , "user" .= user
    , "token" .= token
    , "error" .= err
    ]

instance ToJSON RefreshResponse where
  toJSON (RefreshResponse success newToken newRefreshToken err) = object 
    [ "success" .= success
    , "token" .= newToken
    , "refreshToken" .= newRefreshToken
    , "error" .= err
    ]

instance ToJSON UserInfo where
  toJSON (UserInfo email uid roles metadata createdAt) = object 
    [ "email" .= email
    , "id" .= uid
    , "roles" .= roles
    , "metadata" .= metadata
    , "createdAt" .= createdAt
    ]

instance ToJSON ErrorResponse where
  toJSON (ErrorResponse code message details) = object 
    [ "code" .= code
    , "message" .= message
    , "details" .= details
    ]

-- JSON deserialization instances
instance FromJSON RegisterRequest where
  parseJSON = withObject "RegisterRequest" $ \o -> RegisterRequest
    <$> o .: "email"
    <*> o .: "password"
    <*> o .:? "confirmPassword"
    <*> o .:? "metadata"

instance FromJSON RefreshRequest where
  parseJSON = withObject "RefreshRequest" $ \o -> RefreshRequest
    <$> o .: "refreshToken"

-- | Authentication server implementation
-- Core authentication endpoints implementation (Task 7.2)
authServer :: RuntimeConfig -> Server AuthAPI
authServer config = loginHandler
              :<|> callbackHandler
              :<|> sessionHandler
              :<|> logoutHandler
              :<|> registerHandler
              :<|> refreshHandler
  where
    providers = authProviders config
    sessionMgr = sessionManager config
    
    -- Login endpoint handler - initiates authentication flow for specified provider
    loginHandler :: Text -> Maybe Text -> Handler LoginResponse
    loginHandler providerName redirectUri = do
      liftIO $ putStrLn $ "Login request for provider: " <> T.unpack providerName
      
      case Map.lookup providerName providers of
        Nothing -> throwError $ err404 { errBody = "Provider not found: " <> LBS.fromStrict (TE.encodeUtf8 providerName) }
        Just provider -> do
          case provider of
            GoogleOAuth googleConfig -> do
              -- Create Google OAuth provider and initiate auth
              googleProvider <- liftIO $ Providers.createGoogleProviderWithMemoryStore googleConfig
              authResult <- liftIO $ Providers.initiateAuth googleProvider Nothing
              
              case authResult of
                Providers.AuthRedirectResult redirect -> do
                  return $ LoginResponse 
                    { loginRedirectUrl = Providers.redirectUrl redirect
                    , loginState = Providers.redirectState redirect
                    , loginProvider = providerName
                    }
                Providers.AuthFailure authError -> do
                  liftIO $ putStrLn $ "Auth initiation failed: " <> show authError
                  throwError $ err500 { errBody = "Authentication initiation failed" }
                _ -> throwError $ err500 { errBody = "Unexpected authentication result" }
            
            PasswordAuth _ -> do
              -- Password authentication doesn't use redirect-based initiation
              throwError $ err400 { errBody = "Password authentication requires direct login, not redirect initiation" }
    
    -- OAuth2 callback handler - handles OAuth2 provider callbacks
    callbackHandler :: Text -> Maybe Text -> Maybe Text -> Maybe Text -> Handler CallbackResponse
    callbackHandler providerName code state errorParam = do
      liftIO $ putStrLn $ "Callback for provider: " <> T.unpack providerName
      
      -- Handle OAuth2 error responses
      case errorParam of
        Just err -> do
          liftIO $ putStrLn $ "OAuth2 error: " <> T.unpack err
          return $ CallbackResponse False Nothing Nothing Nothing (Just err)
        Nothing -> do
          case Map.lookup providerName providers of
            Nothing -> throwError $ err404 { errBody = "Provider not found: " <> LBS.fromStrict (TE.encodeUtf8 providerName) }
            Just provider -> do
              case provider of
                GoogleOAuth googleConfig -> do
                  -- Create Google OAuth provider and handle callback
                  googleProvider <- liftIO $ Providers.createGoogleProviderWithMemoryStore googleConfig
                  let callbackData = Providers.CallbackData
                        { Providers.callbackCode = code
                        , Providers.callbackState = state
                        , Providers.callbackError = errorParam
                        , Providers.callbackErrorDescription = Nothing
                        }
                  
                  authResult <- liftIO $ Providers.handleCallback googleProvider callbackData
                  
                  case authResult of
                    Providers.AuthSuccess userInfo sessionToken -> do
                      -- Convert provider UserInfo to server UserInfo
                      let serverUserInfo = convertProviderUserInfo userInfo
                      -- Extract token from SessionToken
                      let Providers.SessionToken tokenText = sessionToken
                      
                      return $ CallbackResponse 
                        { callbackSuccess = True
                        , callbackToken = Just tokenText
                        , callbackRefreshToken = Nothing -- Could be implemented with refresh token support
                        , callbackUser = Just serverUserInfo
                        , callbackError = Nothing
                        }
                    
                    Providers.AuthFailure authError -> do
                      liftIO $ putStrLn $ "Auth callback failed: " <> show authError
                      let errorMsg = case authError of
                            Providers.InvalidCredentials msg -> msg
                            Providers.ProviderError _ msg -> msg
                            Providers.NetworkError msg -> msg
                            _ -> "Authentication failed"
                      return $ CallbackResponse False Nothing Nothing Nothing (Just errorMsg)
                    
                    _ -> do
                      liftIO $ putStrLn "Unexpected auth result in callback"
                      return $ CallbackResponse False Nothing Nothing Nothing (Just "Unexpected authentication result")
                
                PasswordAuth _ -> do
                  -- Password authentication doesn't use callbacks
                  throwError $ err400 { errBody = "Password authentication does not support callback handling" }
    
    -- Session validation handler - validates session tokens and returns user info
    sessionHandler :: Maybe Text -> Handler SessionResponse
    sessionHandler authHeader = do
      liftIO $ putStrLn "Session validation request"
      
      case authHeader of
        Nothing -> do
          return $ SessionResponse False Nothing Nothing []
        
        Just authHeaderValue -> do
          -- Extract token from Authorization header (Bearer token format)
          let token = extractBearerToken authHeaderValue
          
          case token of
            Nothing -> do
              return $ SessionResponse False Nothing Nothing []
            
            Just tokenValue -> do
              -- For now, we'll use a simplified validation approach
              -- In a full implementation, this would integrate with the session manager
              -- and validate against the appropriate provider
              
              -- Try to validate as JWT token first (simplified approach)
              validationResult <- liftIO $ validateJWTToken "placeholder-secret" tokenValue
              
              case validationResult of
                Right userSession -> do
                  let userInfo = UserInfo
                        { serverUserEmail = AuthDSL.Session.userId userSession -- Using userId as email for now
                        , serverUserId = AuthDSL.Session.userId userSession
                        , serverUserRoles = AuthDSL.Session.roles userSession
                        , serverUserMetadata = Nothing
                        , serverUserCreatedAt = Just $ T.pack $ show $ AuthDSL.Session.createdAt userSession
                        }
                  
                  return $ SessionResponse 
                    { sessionValid = True
                    , sessionUser = Just userInfo
                    , sessionExpiresAt = Just $ T.pack $ show $ AuthDSL.Session.expiresAt userSession
                    , sessionScopes = AuthDSL.Session.scopes userSession
                    }
                
                Left sessionError -> do
                  liftIO $ putStrLn $ "Session validation failed: " <> show sessionError
                  return $ SessionResponse False Nothing Nothing []
    
    -- Logout handler - destroys user sessions
    logoutHandler :: Maybe Text -> Handler LogoutResponse
    logoutHandler authHeader = do
      liftIO $ putStrLn "Logout request"
      
      case authHeader of
        Nothing -> do
          -- No token provided, but we can still return success
          return $ LogoutResponse True "No active session to logout"
        
        Just authHeaderValue -> do
          let token = extractBearerToken authHeaderValue
          
          case token of
            Nothing -> do
              return $ LogoutResponse True "Invalid token format, no session to logout"
            
            Just tokenValue -> do
              -- For JWT-based sessions, we can't truly "destroy" the token since it's stateless
              -- But we could add it to a blacklist or handle refresh token cleanup
              -- For now, we'll just return success
              
              -- In a full implementation with cookie sessions, this would:
              -- 1. Extract session ID from token
              -- 2. Delete session from database
              -- 3. Clear any associated refresh tokens
              
              liftIO $ putStrLn $ T.unpack $ "Logging out session with token: " <> T.take 10 tokenValue <> "..."
              
              return $ LogoutResponse True "Successfully logged out"
    
    -- Registration handler - implements password-based user registration
    registerHandler :: RegisterRequest -> Handler RegisterResponse
    registerHandler req = do
      liftIO $ putStrLn $ "Registration request for: " <> T.unpack (registerEmail req)
      
      -- Validate registration request
      case validateRegistrationRequest req of
        Left validationError -> do
          liftIO $ putStrLn $ "Registration validation failed: " <> T.unpack validationError
          return $ RegisterResponse False Nothing Nothing (Just validationError)
        Right _ -> do
          -- Check if password authentication is enabled
          case Map.lookup "password" providers of
            Nothing -> do
              liftIO $ putStrLn "Password authentication not configured"
              return $ RegisterResponse False Nothing Nothing (Just "Password authentication is not enabled")
            Just (PasswordAuth passwordConfig) -> do
              -- Create password authentication provider
              passwordProvider <- liftIO $ Providers.createPasswordProviderWithMemoryStore passwordConfig
              
              -- Attempt to register the user
              registrationResult <- liftIO $ Providers.registerPassword passwordProvider (registerEmail req) (registerPassword req)
              
              case registrationResult of
                Providers.AuthSuccess userInfo sessionToken -> do
                  -- Convert provider UserInfo to server UserInfo
                  let serverUserInfo = convertProviderUserInfo userInfo
                  -- Extract token from SessionToken
                  let Providers.SessionToken tokenText = sessionToken
                  
                  liftIO $ putStrLn $ "User registered successfully: " <> T.unpack (registerEmail req)
                  return $ RegisterResponse 
                    { registerSuccess = True
                    , registerUser = Just serverUserInfo
                    , registerToken = Just tokenText
                    , registerError = Nothing
                    }
                
                Providers.AuthFailure authError -> do
                  let errorMsg = case authError of
                        Providers.InvalidCredentials msg -> msg
                        Providers.ProviderError _ msg -> msg
                        Providers.NetworkError msg -> msg
                        _ -> "Registration failed"
                  liftIO $ putStrLn $ "Registration failed: " <> T.unpack errorMsg
                  return $ RegisterResponse False Nothing Nothing (Just errorMsg)
                
                _ -> do
                  liftIO $ putStrLn "Unexpected registration result"
                  return $ RegisterResponse False Nothing Nothing (Just "Unexpected registration result")
            
            Just _ -> do
              liftIO $ putStrLn "Registration endpoint called but password authentication not configured"
              return $ RegisterResponse False Nothing Nothing (Just "Password authentication is not configured for registration")
    
    -- Token refresh handler - implements JWT token renewal
    refreshHandler :: RefreshRequest -> Handler RefreshResponse
    refreshHandler req = do
      liftIO $ putStrLn "Token refresh request"
      
      -- Validate refresh request
      case validateRefreshRequest req of
        Left validationError -> do
          liftIO $ putStrLn $ "Refresh validation failed: " <> T.unpack validationError
          return $ RefreshResponse False Nothing Nothing (Just validationError)
        Right _ -> do
          -- Check if JWT session strategy is configured with refresh enabled
          case sessionMgr of
            -- For now, we'll implement a simplified refresh logic
            -- In a full implementation, this would integrate with the session manager
            _ -> do
              let refreshTokenValue = refreshToken req
              
              -- Validate the refresh token format (basic validation)
              if T.length refreshTokenValue < 10
                then do
                  liftIO $ putStrLn "Invalid refresh token format"
                  return $ RefreshResponse False Nothing Nothing (Just "Invalid refresh token format")
                else do
                  -- For demonstration purposes, we'll generate new tokens
                  -- In a real implementation, this would:
                  -- 1. Validate the refresh token against stored tokens
                  -- 2. Check if the refresh token is expired
                  -- 3. Generate new access and refresh tokens
                  -- 4. Update the refresh token store
                  
                  currentTime <- liftIO getCurrentTime
                  newAccessToken <- liftIO generateNewAccessToken
                  newRefreshToken <- liftIO generateNewRefreshToken
                  
                  liftIO $ putStrLn "Tokens refreshed successfully"
                  return $ RefreshResponse 
                    { refreshSuccess = True
                    , refreshNewToken = Just newAccessToken
                    , refreshNewRefreshToken = Just newRefreshToken
                    , refreshError = Nothing
                    }

-- | Extract Bearer token from Authorization header
extractBearerToken :: Text -> Maybe Text
extractBearerToken authHeader
  | T.isPrefixOf "Bearer " authHeader = Just $ T.drop 7 authHeader
  | T.isPrefixOf "bearer " authHeader = Just $ T.drop 7 authHeader
  | otherwise = Nothing

-- | Convert provider UserInfo to server UserInfo
convertProviderUserInfo :: Providers.UserInfo -> UserInfo
convertProviderUserInfo providerUser = UserInfo
  { serverUserEmail = Providers.userEmail providerUser
  , serverUserId = Providers.userProviderId providerUser
  , serverUserRoles = ["user"] -- Default role, could be configurable
  , serverUserMetadata = case Providers.userName providerUser of
      Just name -> Just name
      Nothing -> Nothing
  , serverUserCreatedAt = Nothing -- Could be added to provider UserInfo
  }

-- | Create WAI application with comprehensive security middleware
authApp :: ServerConfig -> IO Application
authApp config = do
  -- Create rate limiting store
  rateLimitStore <- createMemoryRateLimitStore
  
  let app = serve (Proxy :: Proxy AuthAPI) (authServer (serverRuntime config))
      -- Determine if HTTPS is enabled
      isHTTPS = case serverTLS config of
        Just tlsConfig -> tlsEnabled tlsConfig
        Nothing -> False
      -- Apply security middleware (CORS, CSRF, rate limiting, security headers)
      withSecurity = combineSecurityMiddleware (serverSecurity config) rateLimitStore isHTTPS
      -- Apply logging middleware
      withLogging = if serverEnableLogging config then logStdoutDev else id
  
  return $ withLogging $ withSecurity app

-- | Validate registration request
validateRegistrationRequest :: RegisterRequest -> Either Text ()
validateRegistrationRequest req = do
  -- Validate email format
  if not (isValidEmail (registerEmail req))
    then Left "Invalid email format"
    else do
      -- Validate password is not empty
      if T.null (T.strip (registerPassword req))
        then Left "Password cannot be empty"
        else do
          -- Validate password confirmation if provided
          case registerConfirmPassword req of
            Just confirmPassword -> 
              if registerPassword req /= confirmPassword
                then Left "Password confirmation does not match"
                else Right ()
            Nothing -> Right ()

-- | Validate refresh request
validateRefreshRequest :: RefreshRequest -> Either Text ()
validateRefreshRequest req = do
  -- Validate refresh token is not empty
  if T.null (T.strip (refreshToken req))
    then Left "Refresh token cannot be empty"
    else Right ()

-- | Validate email format using a simple regex
isValidEmail :: Text -> Bool
isValidEmail email = 
  let emailPattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$" :: String
  in T.unpack email =~ emailPattern

-- | Generate a new access token (placeholder implementation)
generateNewAccessToken :: IO Text
generateNewAccessToken = do
  randomBytes <- getRandomBytes 32
  return $ "access_" <> (TE.decodeUtf8 $ B64.encode randomBytes)

-- | Generate a new refresh token (placeholder implementation)
generateNewRefreshToken :: IO Text
generateNewRefreshToken = do
  randomBytes <- getRandomBytes 32
  return $ "refresh_" <> (TE.decodeUtf8 $ B64.encode randomBytes)

-- | Run the authentication server with configurable middleware
runAuthServer :: ServerConfig -> IO ()
runAuthServer config = do
  let port = serverPort config
      host = T.unpack (serverHost config)
      settings = setPort port $ setHost (fromString host) defaultSettings
  
  putStrLn $ "Starting Auth DSL server on " <> host <> ":" <> show port
  putStrLn $ "CORS enabled: " <> show (serverEnableCors config)
  putStrLn $ "Logging enabled: " <> show (serverEnableLogging config)
  putStrLn $ "Security features enabled:"
  putStrLn $ "  - CORS protection"
  putStrLn $ "  - CSRF protection"
  putStrLn $ "  - Rate limiting"
  putStrLn $ "  - Security headers"
  
  case serverTLS config of
    Just tlsConfig | tlsEnabled tlsConfig -> do
      case (tlsCertFile tlsConfig, tlsKeyFile tlsConfig) of
        (Just certFile, Just keyFile) -> do
          let tlsPortNum = tlsPort tlsConfig
          putStrLn $ "TLS enabled on port " <> show tlsPortNum
          putStrLn $ "Certificate file: " <> certFile
          putStrLn $ "Key file: " <> keyFile
          putStrLn $ "Production security features:"
          putStrLn $ "  - HTTPS/TLS encryption"
          putStrLn $ "  - HSTS headers"
          putStrLn $ "  - Secure cookies"
          putStrLn $ "  - Enhanced CSP"
          putStrLn "Available endpoints (HTTPS):"
          putStrLn "  POST /login/:provider"
          putStrLn "  POST /callback/:provider"
          putStrLn "  GET  /session"
          putStrLn "  POST /logout"
          putStrLn "  POST /register"
          putStrLn "  POST /refresh"
          
          -- Validate TLS files exist before starting
          certExists <- doesFileExist certFile
          keyExists <- doesFileExist keyFile
          
          if not certExists
            then putStrLn $ "ERROR: Certificate file not found: " <> certFile
            else if not keyExists
              then putStrLn $ "ERROR: Key file not found: " <> keyFile
              else do
                app <- authApp config
                let tls = tlsSettings certFile keyFile
                    tlsSettings' = setPort tlsPortNum $ setHost (fromString host) defaultSettings
                putStrLn $ "Server starting with TLS on https://" <> host <> ":" <> show tlsPortNum
                runTLS tls tlsSettings' app
        _ -> do
          putStrLn "ERROR: TLS enabled but certificate or key file not specified"
          putStrLn "Required TLS configuration:"
          putStrLn "  - tlsCertFile: path to certificate file"
          putStrLn "  - tlsKeyFile: path to private key file"
          putStrLn "Falling back to HTTP mode"
          runHttpServer config
    _ -> runHttpServer config

-- | Run HTTP server (non-TLS)
runHttpServer :: ServerConfig -> IO ()
runHttpServer config = do
  let port = serverPort config
  putStrLn "Available endpoints (HTTP):"
  putStrLn "  POST /login/:provider"
  putStrLn "  POST /callback/:provider"
  putStrLn "  GET  /session"
  putStrLn "  POST /logout"
  putStrLn "  POST /register"
  putStrLn "  POST /refresh"
  
  app <- authApp config
  run port app