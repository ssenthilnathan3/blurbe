{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module AuthDSL.Security
  ( SecurityConfig(..)
  , CORSPolicy(..)
  , CSRFConfig(..)
  , RateLimitConfig(..)
  , RateLimitRule(..)
  , SecurityHeadersConfig(..)
  , HSSTConfig(..)
  , CSPConfig(..)
  , SecurityMiddleware
  , corsMiddleware
  , csrfMiddleware
  , rateLimitMiddleware
  , securityHeadersMiddleware
  , combineSecurityMiddleware
  , defaultSecurityConfig
  , defaultCORSPolicy
  , defaultCSRFConfig
  , defaultSecurityHeadersConfig
  , defaultHSTSConfig
  , defaultCSPConfig
  , generateCSRFToken
  , validateCSRFToken
  , CSRFToken(..)
  , RateLimitStore(..)
  , createMemoryRateLimitStore
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Builder as Builder
import Data.Time (UTCTime, getCurrentTime, addUTCTime, diffUTCTime)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Control.Concurrent.STM (STM, TVar, newTVarIO, readTVar, writeTVar, atomically)
import Control.Monad.IO.Class (liftIO)
import Network.Wai (Application, Middleware, Request, Response, requestHeaders, requestMethod, pathInfo)
import Network.Wai.Internal (Response(..))
import Network.HTTP.Types (Status, status200, status403, status429, status400)
import Network.HTTP.Types.Header (Header, hOrigin, hContentType)
import Network.HTTP.Types.Method (methodOptions)
import qualified Data.CaseInsensitive as CI
import Crypto.Random (getRandomBytes)
import qualified Data.ByteString.Base64 as B64
import qualified Crypto.Hash as Hash
import qualified Crypto.MAC.HMAC as HMAC
import Data.Word (Word8)
import Text.Read (readMaybe)

-- | Comprehensive security configuration
data SecurityConfig = SecurityConfig
  { secCORS :: CORSPolicy
  , secCSRF :: CSRFConfig
  , secRateLimit :: RateLimitConfig
  , secHeaders :: Bool -- Enable security headers
  } deriving (Show, Eq)

-- | CORS policy configuration
data CORSPolicy = CORSPolicy
  { corsAllowedOrigins :: [Text] -- Allowed origins, ["*"] for all
  , corsAllowedMethods :: [Text] -- Allowed HTTP methods
  , corsAllowedHeaders :: [Text] -- Allowed headers
  , corsMaxAge :: Int -- Preflight cache duration in seconds
  , corsAllowCredentials :: Bool -- Allow credentials
  } deriving (Show, Eq)

-- | CSRF protection configuration
data CSRFConfig = CSRFConfig
  { csrfEnabled :: Bool
  , csrfSecret :: Text -- Secret key for CSRF token generation
  , csrfHeaderName :: Text -- Header name for CSRF token
  , csrfCookieName :: Text -- Cookie name for CSRF token
  , csrfExemptPaths :: [Text] -- Paths exempt from CSRF protection
  , csrfTokenLength :: Int -- Length of CSRF token in bytes
  } deriving (Show, Eq)

-- | Rate limiting configuration
data RateLimitConfig = RateLimitConfig
  { rateLimitEnabled :: Bool
  , rateLimitRules :: [RateLimitRule] -- Rate limiting rules per endpoint
  , rateLimitGlobal :: Maybe RateLimitRule -- Global rate limit
  } deriving (Show, Eq)

-- | Rate limiting rule for specific endpoints
data RateLimitRule = RateLimitRule
  { rlPath :: Text -- Path pattern (supports wildcards)
  , rlMethods :: [Text] -- HTTP methods to apply rate limiting
  , rlMaxRequests :: Int -- Maximum requests allowed
  , rlWindowSeconds :: Int -- Time window in seconds
  , rlIdentifier :: Text -- How to identify clients ("ip", "user", "session")
  } deriving (Show, Eq)

-- | CSRF token wrapper
newtype CSRFToken = CSRFToken Text deriving (Show, Eq)

-- | Rate limiting storage interface
data RateLimitStore = RateLimitStore
  { rlsGet :: Text -> IO (Maybe (Int, UTCTime)) -- Get request count and window start
  , rlsSet :: Text -> Int -> UTCTime -> IO () -- Set request count and window start
  , rlsIncrement :: Text -> UTCTime -> IO Int -- Increment and return new count
  , rlsCleanup :: IO () -- Clean up expired entries
  }

-- | Security middleware type
type SecurityMiddleware = Middleware

-- | Default security configuration
defaultSecurityConfig :: SecurityConfig
defaultSecurityConfig = SecurityConfig
  { secCORS = defaultCORSPolicy
  , secCSRF = defaultCSRFConfig
  , secRateLimit = defaultRateLimitConfig
  , secHeaders = True
  }

-- | Default CORS policy
defaultCORSPolicy :: CORSPolicy
defaultCORSPolicy = CORSPolicy
  { corsAllowedOrigins = ["http://localhost:3000", "http://localhost:8080"]
  , corsAllowedMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  , corsAllowedHeaders = ["Content-Type", "Authorization", "X-CSRF-Token", "X-Requested-With"]
  , corsMaxAge = 86400 -- 24 hours
  , corsAllowCredentials = True
  }

-- | Default CSRF configuration
defaultCSRFConfig :: CSRFConfig
defaultCSRFConfig = CSRFConfig
  { csrfEnabled = True
  , csrfSecret = "default-csrf-secret-change-in-production"
  , csrfHeaderName = "X-CSRF-Token"
  , csrfCookieName = "csrf-token"
  , csrfExemptPaths = ["login", "callback", "session", "register", "refresh", "logout"] -- Auth endpoints exempt from CSRF
  , csrfTokenLength = 32
  }

-- | Default rate limiting configuration
defaultRateLimitConfig :: RateLimitConfig
defaultRateLimitConfig = RateLimitConfig
  { rateLimitEnabled = True
  , rateLimitRules = 
      [ -- Login endpoint rate limiting
        RateLimitRule "/login" ["POST"] 5 300 "ip" -- 5 attempts per 5 minutes per IP
      , -- Registration rate limiting
        RateLimitRule "/register" ["POST"] 3 3600 "ip" -- 3 attempts per hour per IP
      , -- General API rate limiting
        RateLimitRule "/api/*" ["GET", "POST", "PUT", "DELETE"] 100 3600 "ip" -- 100 requests per hour per IP
      ]
  , rateLimitGlobal = Just $ RateLimitRule "*" ["*"] 1000 3600 "ip" -- 1000 requests per hour per IP globally
  }

-- | CORS middleware implementation
corsMiddleware :: CORSPolicy -> SecurityMiddleware
corsMiddleware policy app req respond = do
  let origin = lookup hOrigin (requestHeaders req)
      method = requestMethod req
  
  if method == methodOptions
    then -- Handle preflight requests
      respond $ preflightResponse policy origin
    else -- Handle actual requests
      app req $ \response -> do
        let responseWithCORS = addCORSHeaders policy origin response
        respond responseWithCORS

-- | Add CORS headers to response
addCORSHeaders :: CORSPolicy -> Maybe ByteString -> Response -> Response
addCORSHeaders policy origin response = 
  case response of
    ResponseFile status headers file part -> 
      ResponseFile status (corsHeaders ++ headers) file part
    ResponseBuilder status headers builder -> 
      ResponseBuilder status (corsHeaders ++ headers) builder
    ResponseStream status headers stream -> 
      ResponseStream status (corsHeaders ++ headers) stream
    ResponseRaw action response' -> 
      ResponseRaw action (addCORSHeaders policy origin response')
  where
    corsHeaders = buildCORSHeaders policy origin

-- | Build CORS headers
buildCORSHeaders :: CORSPolicy -> Maybe ByteString -> [Header]
buildCORSHeaders CORSPolicy{..} origin = 
  [ ("Access-Control-Allow-Origin", allowedOrigin)
  , ("Access-Control-Allow-Methods", TE.encodeUtf8 $ T.intercalate ", " corsAllowedMethods)
  , ("Access-Control-Allow-Headers", TE.encodeUtf8 $ T.intercalate ", " corsAllowedHeaders)
  , ("Access-Control-Max-Age", TE.encodeUtf8 $ T.pack $ show corsMaxAge)
  ] ++ credentialsHeader
  where
    allowedOrigin = case origin of
      Just originHeader -> 
        if "*" `elem` corsAllowedOrigins || 
           any (\allowed -> TE.encodeUtf8 allowed == originHeader) corsAllowedOrigins
        then originHeader
        else "null"
      Nothing -> TE.encodeUtf8 $ head corsAllowedOrigins
    
    credentialsHeader = 
      if corsAllowCredentials 
      then [("Access-Control-Allow-Credentials", "true")]
      else []

-- | Handle preflight requests
preflightResponse :: CORSPolicy -> Maybe ByteString -> Response
preflightResponse policy origin = 
  ResponseBuilder status200 (buildCORSHeaders policy origin) mempty

-- | CSRF middleware implementation
csrfMiddleware :: CSRFConfig -> SecurityMiddleware
csrfMiddleware config app req respond = do
  if not (csrfEnabled config)
    then app req respond
    else do
      let method = requestMethod req
          path = T.intercalate "/" (pathInfo req)
      
      if method `elem` ["GET", "HEAD", "OPTIONS"] || isCSRFExemptPath path (csrfExemptPaths config)
        then -- Safe methods or exempt paths, just add CSRF token to response
          app req $ \response -> do
            csrfToken <- generateCSRFToken config
            let responseWithCSRF = addCSRFTokenToResponse config csrfToken response
            respond responseWithCSRF
        else -- Unsafe methods, validate CSRF token
          case extractCSRFToken config req of
            Nothing -> respond $ csrfErrorResponse "Missing CSRF token"
            Just token -> do
              isValid <- validateCSRFToken config token
              if isValid
                then app req respond
                else respond $ csrfErrorResponse "Invalid CSRF token"

-- | Extract CSRF token from request
extractCSRFToken :: CSRFConfig -> Request -> Maybe CSRFToken
extractCSRFToken config req = 
  -- Try header first, then form data
  case lookup (CI.mk $ TE.encodeUtf8 $ csrfHeaderName config) (requestHeaders req) of
    Just headerValue -> Just $ CSRFToken $ TE.decodeUtf8 headerValue
    Nothing -> Nothing -- Could also check form data or cookies

-- | Add CSRF token to response (as cookie)
addCSRFTokenToResponse :: CSRFConfig -> CSRFToken -> Response -> Response
addCSRFTokenToResponse config (CSRFToken token) response =
  case response of
    ResponseFile status headers file part -> 
      ResponseFile status (csrfCookieHeader : headers) file part
    ResponseBuilder status headers builder -> 
      ResponseBuilder status (csrfCookieHeader : headers) builder
    ResponseStream status headers stream -> 
      ResponseStream status (csrfCookieHeader : headers) stream
    ResponseRaw action response' -> 
      ResponseRaw action (addCSRFTokenToResponse config (CSRFToken token) response')
  where
    csrfCookieHeader = ("Set-Cookie", TE.encodeUtf8 $ 
      csrfCookieName config <> "=" <> token <> "; HttpOnly; SameSite=Strict; Path=/")

-- | CSRF error response
csrfErrorResponse :: Text -> Response
csrfErrorResponse message = 
  ResponseBuilder status403 [(hContentType, "application/json")] $
    Builder.lazyByteString $ LBS.fromStrict $ TE.encodeUtf8 $ 
      "{\"error\":\"CSRF_TOKEN_INVALID\",\"message\":\"" <> message <> "\"}"

-- | Generate CSRF token
generateCSRFToken :: CSRFConfig -> IO CSRFToken
generateCSRFToken config = do
  randomBytes <- getRandomBytes (csrfTokenLength config)
  let token = TE.decodeUtf8 $ B64.encode randomBytes
  return $ CSRFToken token

-- | Validate CSRF token
validateCSRFToken :: CSRFConfig -> CSRFToken -> IO Bool
validateCSRFToken config (CSRFToken token) = do
  -- For now, we'll implement a simple validation
  -- In production, this should validate against a stored token or HMAC
  return $ T.length token >= fromIntegral (csrfTokenLength config)

-- | Check if a path is exempt from CSRF protection
isCSRFExemptPath :: Text -> [Text] -> Bool
isCSRFExemptPath path exemptPaths = 
  any (\exemptPath -> 
    -- Check if the path starts with the exempt path
    -- This allows /login/google to match "login"
    T.isPrefixOf exemptPath path || path == exemptPath
  ) exemptPaths

-- | Rate limiting middleware implementation
rateLimitMiddleware :: RateLimitStore -> RateLimitConfig -> SecurityMiddleware
rateLimitMiddleware store config app req respond = do
  if not (rateLimitEnabled config)
    then app req respond
    else do
      let path = T.intercalate "/" (pathInfo req)
          method = TE.decodeUtf8 $ requestMethod req
          clientId = extractClientIdentifier req "ip" -- Default to IP-based identification
      
      -- Check applicable rate limit rules
      applicableRules <- findApplicableRules config path method
      
      -- Check each rule
      rateCheckResults <- mapM (checkRateLimit store clientId) applicableRules
      
      if any not rateCheckResults
        then respond $ rateLimitErrorResponse
        else app req respond

-- | Find applicable rate limiting rules
findApplicableRules :: RateLimitConfig -> Text -> Text -> IO [RateLimitRule]
findApplicableRules config path method = do
  let pathRules = filter (matchesPath path . rlPath) (rateLimitRules config)
      methodRules = filter (matchesMethod method . rlMethods) pathRules
      globalRules = case rateLimitGlobal config of
        Just rule -> [rule]
        Nothing -> []
  return $ methodRules ++ globalRules

-- | Check if path matches rule pattern
matchesPath :: Text -> Text -> Bool
matchesPath path pattern
  | pattern == "*" = True
  | T.isSuffixOf "/*" pattern = T.isPrefixOf (T.dropEnd 2 pattern) path
  | otherwise = path == pattern

-- | Check if method matches rule methods
matchesMethod :: Text -> [Text] -> Bool
matchesMethod method methods = "*" `elem` methods || method `elem` methods

-- | Check rate limit for a specific rule
checkRateLimit :: RateLimitStore -> Text -> RateLimitRule -> IO Bool
checkRateLimit store clientId rule = do
  currentTime <- getCurrentTime
  let key = clientId <> ":" <> rlPath rule
      windowStart = addUTCTime (fromIntegral $ negate $ rlWindowSeconds rule) currentTime
  
  -- Get current count for this client and rule
  maybeCount <- rlsGet store key
  
  case maybeCount of
    Nothing -> do
      -- First request in window
      rlsSet store key 1 currentTime
      return True
    Just (count, lastTime) -> do
      if diffUTCTime currentTime lastTime > fromIntegral (rlWindowSeconds rule)
        then do
          -- Window expired, reset counter
          rlsSet store key 1 currentTime
          return True
        else do
          if count >= rlMaxRequests rule
            then return False -- Rate limit exceeded
            else do
              -- Increment counter
              newCount <- rlsIncrement store key currentTime
              return $ newCount <= rlMaxRequests rule

-- | Extract client identifier from request
extractClientIdentifier :: Request -> Text -> Text
extractClientIdentifier req identifierType = 
  case identifierType of
    "ip" -> extractIPAddress req
    "user" -> extractUserIdentifier req
    "session" -> extractSessionIdentifier req
    _ -> extractIPAddress req -- Default to IP

-- | Extract IP address from request
extractIPAddress :: Request -> Text
extractIPAddress req = 
  case lookup "X-Forwarded-For" (requestHeaders req) of
    Just forwardedFor -> T.takeWhile (/= ',') $ TE.decodeUtf8 forwardedFor
    Nothing -> case lookup "X-Real-IP" (requestHeaders req) of
      Just realIP -> TE.decodeUtf8 realIP
      Nothing -> "unknown" -- Fallback

-- | Extract user identifier from request (placeholder)
extractUserIdentifier :: Request -> Text
extractUserIdentifier req = 
  case lookup "Authorization" (requestHeaders req) of
    Just authHeader -> T.take 10 $ TE.decodeUtf8 authHeader -- Use first 10 chars of auth header
    Nothing -> extractIPAddress req -- Fallback to IP

-- | Extract session identifier from request (placeholder)
extractSessionIdentifier :: Request -> Text
extractSessionIdentifier req = 
  case lookup "Cookie" (requestHeaders req) of
    Just cookie -> T.take 10 $ TE.decodeUtf8 cookie -- Use first 10 chars of cookie
    Nothing -> extractIPAddress req -- Fallback to IP

-- | Rate limit error response
rateLimitErrorResponse :: Response
rateLimitErrorResponse = 
  ResponseBuilder status429 [(hContentType, "application/json")] $
    Builder.lazyByteString $ LBS.fromStrict $ TE.encodeUtf8 $ 
      "{\"error\":\"RATE_LIMIT_EXCEEDED\",\"message\":\"Too many requests. Please try again later.\"}"

-- | Security headers configuration
data SecurityHeadersConfig = SecurityHeadersConfig
  { shcHSTS :: Maybe HSSTConfig
  , shcCSP :: Maybe CSPConfig
  , shcFrameOptions :: Text
  , shcContentTypeOptions :: Bool
  , shcXSSProtection :: Bool
  , shcReferrerPolicy :: Text
  , shcPermissionsPolicy :: Maybe Text
  } deriving (Show, Eq)

-- | HTTP Strict Transport Security configuration
data HSSTConfig = HSSTConfig
  { hstsMaxAge :: Int -- seconds
  , hstsIncludeSubDomains :: Bool
  , hstsPreload :: Bool
  } deriving (Show, Eq)

-- | Content Security Policy configuration
data CSPConfig = CSPConfig
  { cspDefaultSrc :: [Text]
  , cspScriptSrc :: [Text]
  , cspStyleSrc :: [Text]
  , cspImgSrc :: [Text]
  , cspConnectSrc :: [Text]
  , cspFontSrc :: [Text]
  , cspObjectSrc :: [Text]
  , cspMediaSrc :: [Text]
  , cspFrameSrc :: [Text]
  , cspReportUri :: Maybe Text
  } deriving (Show, Eq)

-- | Default security headers configuration for production
defaultSecurityHeadersConfig :: Bool -> SecurityHeadersConfig
defaultSecurityHeadersConfig isHTTPS = SecurityHeadersConfig
  { shcHSTS = if isHTTPS then Just defaultHSTSConfig else Nothing
  , shcCSP = Just defaultCSPConfig
  , shcFrameOptions = "DENY"
  , shcContentTypeOptions = True
  , shcXSSProtection = True
  , shcReferrerPolicy = "strict-origin-when-cross-origin"
  , shcPermissionsPolicy = Just "geolocation=(), microphone=(), camera=()"
  }

-- | Default HSTS configuration
defaultHSTSConfig :: HSSTConfig
defaultHSTSConfig = HSSTConfig
  { hstsMaxAge = 31536000 -- 1 year
  , hstsIncludeSubDomains = True
  , hstsPreload = False -- Should be explicitly enabled
  }

-- | Default CSP configuration
defaultCSPConfig :: CSPConfig
defaultCSPConfig = CSPConfig
  { cspDefaultSrc = ["'self'"]
  , cspScriptSrc = ["'self'", "'unsafe-inline'"] -- Allow inline scripts for development
  , cspStyleSrc = ["'self'", "'unsafe-inline'"] -- Allow inline styles
  , cspImgSrc = ["'self'", "data:", "https:"]
  , cspConnectSrc = ["'self'"]
  , cspFontSrc = ["'self'", "https:", "data:"]
  , cspObjectSrc = ["'none'"]
  , cspMediaSrc = ["'self'"]
  , cspFrameSrc = ["'none'"]
  , cspReportUri = Nothing
  }

-- | Security headers middleware with configuration
securityHeadersMiddleware :: SecurityHeadersConfig -> SecurityMiddleware
securityHeadersMiddleware config app req respond = 
  app req $ \response -> do
    let responseWithHeaders = addSecurityHeaders config response
    respond responseWithHeaders

-- | Add security headers to response
addSecurityHeaders :: SecurityHeadersConfig -> Response -> Response
addSecurityHeaders config response = 
  case response of
    ResponseFile status headers file part -> 
      ResponseFile status (securityHeaders ++ headers) file part
    ResponseBuilder status headers builder -> 
      ResponseBuilder status (securityHeaders ++ headers) builder
    ResponseStream status headers stream -> 
      ResponseStream status (securityHeaders ++ headers) stream
    ResponseRaw action response' -> 
      ResponseRaw action (addSecurityHeaders config response')
  where
    securityHeaders = buildSecurityHeaders config

-- | Build security headers from configuration
buildSecurityHeaders :: SecurityHeadersConfig -> [Header]
buildSecurityHeaders SecurityHeadersConfig{..} = 
  hstsHeaders ++ cspHeaders ++ otherHeaders
  where
    hstsHeaders = case shcHSTS of
      Just hstsConfig -> [buildHSTSHeader hstsConfig]
      Nothing -> []
    
    cspHeaders = case shcCSP of
      Just cspConfig -> [buildCSPHeader cspConfig]
      Nothing -> []
    
    otherHeaders = 
      [ ("X-Frame-Options", TE.encodeUtf8 shcFrameOptions)
      , ("Referrer-Policy", TE.encodeUtf8 shcReferrerPolicy)
      ] ++ 
      (if shcContentTypeOptions then [("X-Content-Type-Options", "nosniff")] else []) ++
      (if shcXSSProtection then [("X-XSS-Protection", "1; mode=block")] else []) ++
      case shcPermissionsPolicy of
        Just policy -> [("Permissions-Policy", TE.encodeUtf8 policy)]
        Nothing -> []

-- | Build HSTS header
buildHSTSHeader :: HSSTConfig -> Header
buildHSTSHeader HSSTConfig{..} = 
  let maxAgeDirective = "max-age=" <> T.pack (show hstsMaxAge)
      subDomainsDirective = if hstsIncludeSubDomains then "; includeSubDomains" else ""
      preloadDirective = if hstsPreload then "; preload" else ""
      headerValue = maxAgeDirective <> subDomainsDirective <> preloadDirective
  in ("Strict-Transport-Security", TE.encodeUtf8 headerValue)

-- | Build CSP header
buildCSPHeader :: CSPConfig -> Header
buildCSPHeader CSPConfig{..} = 
  let directives = 
        [ ("default-src", cspDefaultSrc)
        , ("script-src", cspScriptSrc)
        , ("style-src", cspStyleSrc)
        , ("img-src", cspImgSrc)
        , ("connect-src", cspConnectSrc)
        , ("font-src", cspFontSrc)
        , ("object-src", cspObjectSrc)
        , ("media-src", cspMediaSrc)
        , ("frame-src", cspFrameSrc)
        ]
      formatDirective (name, sources) = name <> " " <> T.intercalate " " sources
      cspValue = T.intercalate "; " $ map formatDirective directives
      reportDirective = case cspReportUri of
        Just uri -> "; report-uri " <> uri
        Nothing -> ""
      fullCSP = cspValue <> reportDirective
  in ("Content-Security-Policy", TE.encodeUtf8 fullCSP)

-- | Combine all security middleware
combineSecurityMiddleware :: SecurityConfig -> RateLimitStore -> Bool -> SecurityMiddleware
combineSecurityMiddleware config store isHTTPS = 
  corsMiddleware (secCORS config) .
  csrfMiddleware (secCSRF config) .
  rateLimitMiddleware store (secRateLimit config) .
  (if secHeaders config then securityHeadersMiddleware (defaultSecurityHeadersConfig isHTTPS) else id)

-- | Create in-memory rate limit store
createMemoryRateLimitStore :: IO RateLimitStore
createMemoryRateLimitStore = do
  storeVar <- newTVarIO Map.empty
  return RateLimitStore
    { rlsGet = \key -> atomically $ do
        store <- readTVar storeVar
        return $ Map.lookup key store
    , rlsSet = \key count time -> atomically $ do
        store <- readTVar storeVar
        writeTVar storeVar $ Map.insert key (count, time) store
    , rlsIncrement = \key time -> atomically $ do
        store <- readTVar storeVar
        case Map.lookup key store of
          Just (count, _) -> do
            let newCount = count + 1
            writeTVar storeVar $ Map.insert key (newCount, time) store
            return newCount
          Nothing -> do
            writeTVar storeVar $ Map.insert key (1, time) store
            return 1
    , rlsCleanup = do
        currentTime <- getCurrentTime
        atomically $ do
          store <- readTVar storeVar
          let cleanStore = Map.filter (\(_, time) -> 
                diffUTCTime currentTime time < 3600) store -- Keep entries for 1 hour
          writeTVar storeVar cleanStore
    }