{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module AuthDSL.ServerSpec (spec) where

import Test.Hspec
import Test.Hspec.Wai
import Test.Hspec.Wai.JSON
import Network.Wai.Test (SResponse)
import Data.Aeson (object, (.=), encode)
import qualified Data.Map as Map
import qualified Data.Text as T

import AuthDSL.Server
import AuthDSL.Types
import AuthDSL.Config
import AuthDSL.Security (defaultSecurityConfig)

-- | Test configuration for server testing
testConfig :: RuntimeConfig
testConfig = RuntimeConfig
  { httpConfig = HttpConfig
      { httpPort = 8080
      , httpHost = "localhost"
      , httpTLS = False
      , httpCORS = CORSConfig
          { corsOrigins = ["*"]
          , corsMethods = ["GET", "POST", "OPTIONS"]
          , corsHeaders = ["Content-Type", "Authorization"]
          }
      }
  , authProviders = Map.fromList
      [ ("google", GoogleOAuth $ GoogleConfig
          { googleClientId = "test-client-id"
          , googleClientSecret = "test-client-secret"
          , googleScopes = ["openid", "email", "profile"]
          , googleRedirectUri = Just "http://localhost:8080/auth/callback/google"
          })
      , ("password", PasswordAuth $ PasswordConfig
          { passwordMinLength = 8
          , passwordRequireSpecial = True
          , passwordRequireNumbers = True
          , passwordRequireUppercase = True
          , passwordMaxAttempts = 5
          , passwordLockoutDuration = Duration 300 "seconds"
          })
      ]
  , sessionManager = SessionManagerConfig
      { sessionStrategy = StoreJWT $ JWTConfig
          { jwtSecret = "test-secret-key"
          , jwtAlgorithm = "HS256"
          , jwtIssuer = Just "auth-dsl-test"
          , jwtAudience = Just "auth-dsl-test"
          , jwtRefreshEnabled = True
          }
      , sessionExpiration = 3600
      , sessionSecure = False
      }
  , databaseConnection = DatabaseConnectionConfig
      { dbConnType = SQLite
      , dbConnString = ":memory:"
      , dbConnPoolSize = 5
      }
  }

spec :: Spec
spec = with (authApp $ ServerConfig 8080 "localhost" testConfig True True defaultSecurityConfig Nothing) $ do
  describe "Authentication Endpoints" $ do
    
    describe "POST /login/:provider" $ do
      it "should initiate Google OAuth2 flow" $ do
        post "/login/google" "" `shouldRespondWith` 200
      
      it "should return 404 for unknown provider" $ do
        post "/login/unknown" "" `shouldRespondWith` 404
      
      it "should return 400 for password provider (no redirect)" $ do
        post "/login/password" "" `shouldRespondWith` 400

    describe "POST /callback/:provider" $ do
      it "should handle Google OAuth2 callback with error" $ do
        post "/callback/google?error=access_denied" "" `shouldRespondWith` 200
      
      it "should return 404 for unknown provider" $ do
        post "/callback/unknown" "" `shouldRespondWith` 404
      
      it "should return 400 for password provider (no callback)" $ do
        post "/callback/password" "" `shouldRespondWith` 400

    describe "GET /session" $ do
      it "should return invalid session without Authorization header" $ do
        get "/session" `shouldRespondWith` 200
      
      it "should return invalid session with malformed Authorization header" $ do
        request "GET" "/session" [("Authorization", "InvalidToken")] "" `shouldRespondWith` 200

    describe "POST /logout" $ do
      it "should handle logout without Authorization header" $ do
        post "/logout" "" `shouldRespondWith` 200
      
      it "should handle logout with Authorization header" $ do
        request "POST" "/logout" [("Authorization", "Bearer test-token")] "" `shouldRespondWith` 200

    describe "POST /register" $ do
      it "should handle registration request" $ do
        let registerData = encode $ object 
              [ "email" .= ("test@example.com" :: T.Text)
              , "password" .= ("testpassword123" :: T.Text)
              ]
        request "POST" "/register" [("Content-Type", "application/json")] registerData `shouldRespondWith` 200

    describe "POST /refresh" $ do
      it "should handle refresh token request" $ do
        let refreshData = encode $ object 
              [ "refreshToken" .= ("test-refresh-token" :: T.Text)
              ]
        request "POST" "/refresh" [("Content-Type", "application/json")] refreshData `shouldRespondWith` 200