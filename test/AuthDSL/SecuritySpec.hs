{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.SecuritySpec (spec) where

import Test.Hspec
import Test.Hspec.Wai
import Test.Hspec.Wai.JSON
import Network.Wai (Application)
import Network.Wai.Test (SResponse, simpleHeaders)
import Network.HTTP.Types (hContentType, methodOptions, methodGet)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.CaseInsensitive as CI

import AuthDSL.Security
import AuthDSL.Server (ServerConfig(..), authApp, TLSConfig(..))
import AuthDSL.Config (RuntimeConfig(..), HttpConfig(..), CORSConfig(..), SessionManagerConfig(..), DatabaseConnectionConfig(..))
import AuthDSL.Types (AuthProvider(..), GoogleConfig(..), PasswordConfig(..), SessionStrategy(..), DatabaseType(..), JWTConfig(..))
import qualified Data.Map as Map

-- | Test application with security middleware
testApp :: Bool -> IO Application
testApp isHTTPS = do
  let config = ServerConfig
        { serverPort = 8080
        , serverHost = "localhost"
        , serverRuntime = defaultRuntimeConfig
        , serverEnableLogging = False
        , serverEnableCors = True
        , serverSecurity = defaultSecurityConfig
        , serverTLS = if isHTTPS 
            then Just $ TLSConfig True (Just "cert.pem") (Just "key.pem") 443
            else Nothing
        }
  authApp config

spec :: Spec
spec = do
  describe "Security Headers" $ do
    context "HTTP mode" $ do
      with (testApp False) $ do
        it "includes basic security headers" $ do
          get "/session" `shouldRespondWith` 200
          
        it "includes X-Content-Type-Options header" $ do
          response <- get "/session"
          liftIO $ response `shouldSatisfy` hasHeader "X-Content-Type-Options" "nosniff"
          
        it "includes X-Frame-Options header" $ do
          response <- get "/session"
          liftIO $ response `shouldSatisfy` hasHeader "X-Frame-Options" "DENY"
          
        it "includes X-XSS-Protection header" $ do
          response <- get "/session"
          liftIO $ response `shouldSatisfy` hasHeader "X-XSS-Protection" "1; mode=block"
          
        it "includes Referrer-Policy header" $ do
          response <- get "/session"
          liftIO $ response `shouldSatisfy` hasHeader "Referrer-Policy" "strict-origin-when-cross-origin"
          
        it "does not include HSTS header in HTTP mode" $ do
          response <- get "/session"
          liftIO $ response `shouldSatisfy` not . hasHeaderName "Strict-Transport-Security"

    context "HTTPS mode" $ do
      with (testApp True) $ do
        it "includes HSTS header in HTTPS mode" $ do
          response <- get "/session"
          liftIO $ response `shouldSatisfy` hasHeaderName "Strict-Transport-Security"
          
        it "includes CSP header" $ do
          response <- get "/session"
          liftIO $ response `shouldSatisfy` hasHeaderName "Content-Security-Policy"
          
        it "includes Permissions-Policy header" $ do
          response <- get "/session"
          liftIO $ response `shouldSatisfy` hasHeaderName "Permissions-Policy"

  describe "CORS Headers" $ do
    with (testApp False) $ do
      it "handles preflight requests" $ do
        request methodOptions "/" [("Origin", "http://localhost:3000")] ""
          `shouldRespondWith` 200
          
      it "includes CORS headers in responses" $ do
        response <- request methodGet "/session" [("Origin", "http://localhost:3000")] ""
        liftIO $ response `shouldSatisfy` hasHeaderName "Access-Control-Allow-Origin"

  describe "Security Configuration" $ do
    it "creates default security headers config for HTTP" $ do
      let config = defaultSecurityHeadersConfig False
      shcHSTS config `shouldBe` Nothing
      shcCSP config `shouldSatisfy` (/= Nothing)
      shcFrameOptions config `shouldBe` "DENY"
      
    it "creates default security headers config for HTTPS" $ do
      let config = defaultSecurityHeadersConfig True
      shcHSTS config `shouldSatisfy` (/= Nothing)
      shcCSP config `shouldSatisfy` (/= Nothing)
      shcFrameOptions config `shouldBe` "DENY"

  describe "HSTS Configuration" $ do
    it "creates default HSTS config" $ do
      let hstsConfig = defaultHSTSConfig
      hstsMaxAge hstsConfig `shouldBe` 31536000
      hstsIncludeSubDomains hstsConfig `shouldBe` True
      hstsPreload hstsConfig `shouldBe` False

  describe "CSP Configuration" $ do
    it "creates default CSP config" $ do
      let cspConfig = defaultCSPConfig
      cspDefaultSrc cspConfig `shouldBe` ["'self'"]
      cspObjectSrc cspConfig `shouldBe` ["'none'"]
      cspFrameSrc cspConfig `shouldBe` ["'none'"]

-- Helper functions for testing headers
hasHeader :: ByteString -> ByteString -> SResponse -> Bool
hasHeader name expectedValue response = 
  case lookup (CI.mk name) (simpleHeaders response) of
    Just actualValue -> actualValue == expectedValue
    Nothing -> False

hasHeaderName :: ByteString -> SResponse -> Bool
hasHeaderName name response = 
  any ((== CI.mk name) . fst) (simpleHeaders response)

-- Default runtime config for testing
defaultRuntimeConfig :: RuntimeConfig
defaultRuntimeConfig = RuntimeConfig
  { httpConfig = HttpConfig 8080 "localhost" False defaultCORSConfig
  , authProviders = Map.empty
  , sessionManager = SessionManagerConfig (StoreJWT defaultJWTConfig) 3600 False
  , databaseConnection = DatabaseConnectionConfig SQLite "test.db" 10
  }

-- Default CORS config for testing
defaultCORSConfig :: CORSConfig
defaultCORSConfig = CORSConfig
  { corsOrigins = ["*"]
  , corsMethods = ["GET", "POST"]
  , corsHeaders = ["Content-Type"]
  }

-- Default JWT config for testing
defaultJWTConfig :: JWTConfig
defaultJWTConfig = JWTConfig
  { jwtSecret = "test-secret"
  , jwtAlgorithm = "HS256"
  , jwtIssuer = Nothing
  , jwtAudience = Nothing
  , jwtRefreshEnabled = False
  }