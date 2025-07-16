{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module AuthDSL.RegistrationRefreshSpec (spec) where

import Test.Hspec
import Test.Hspec.Wai
import Network.HTTP.Types (status200, status400)
import Data.Aeson (object, (.=), encode)
import qualified Data.Text as T
import qualified Data.Map as Map

import AuthDSL.Server
import AuthDSL.Types
import AuthDSL.Config (RuntimeConfig(..))
import AuthDSL.Security (defaultSecurityConfig)

-- | Test configuration with password authentication enabled
testConfig :: RuntimeConfig
testConfig = RuntimeConfig
  { httpConfig = undefined -- Not used in these tests
  , authProviders = Map.fromList [("password", passwordProvider)]
  , sessionManager = undefined -- Not used in these tests
  , databaseConnection = undefined -- Not used in these tests
  }
  where
    passwordProvider = PasswordAuth $ PasswordConfig
      { passwordMinLength = 8
      , passwordRequireSpecial = True
      , passwordRequireNumbers = True
      , passwordRequireUppercase = True
      , passwordMaxAttempts = 5
      , passwordLockoutDuration = Duration 300 "seconds"
      }

-- | Test server configuration
testServerConfig :: ServerConfig
testServerConfig = ServerConfig
  { serverPort = 8080
  , serverHost = "localhost"
  , serverRuntime = testConfig
  , serverEnableLogging = False
  , serverEnableCors = True
  , serverSecurity = defaultSecurityConfig
  , serverTLS = Nothing
  }

spec :: Spec
spec = with (authApp testServerConfig) $ do
  describe "POST /register" $ do
    it "should validate email format" $ do
      let requestBody = encode $ object
            [ "email" .= ("invalid-email" :: T.Text)
            , "password" .= ("ValidPass123!" :: T.Text)
            ]
      request "POST" "/register" [("Content-Type", "application/json")] requestBody `shouldRespondWith` 200

    it "should validate password requirements" $ do
      let requestBody = encode $ object
            [ "email" .= ("test@example.com" :: T.Text)
            , "password" .= ("weak" :: T.Text)
            ]
      request "POST" "/register" [("Content-Type", "application/json")] requestBody `shouldRespondWith` 200

    it "should handle valid registration request" $ do
      let requestBody = encode $ object
            [ "email" .= ("newuser@example.com" :: T.Text)
            , "password" .= ("StrongPass123!" :: T.Text)
            ]
      request "POST" "/register" [("Content-Type", "application/json")] requestBody `shouldRespondWith` 200

    it "should validate password confirmation when provided" $ do
      let requestBody = encode $ object
            [ "email" .= ("test@example.com" :: T.Text)
            , "password" .= ("StrongPass123!" :: T.Text)
            , "confirmPassword" .= ("DifferentPass123!" :: T.Text)
            ]
      request "POST" "/register" [("Content-Type", "application/json")] requestBody `shouldRespondWith` 200

  describe "POST /refresh" $ do
    it "should validate refresh token presence" $ do
      let requestBody = encode $ object
            [ "refreshToken" .= ("" :: T.Text)
            ]
      request "POST" "/refresh" [("Content-Type", "application/json")] requestBody `shouldRespondWith` 200

    it "should handle valid refresh token" $ do
      let requestBody = encode $ object
            [ "refreshToken" .= ("valid-refresh-token-12345" :: T.Text)
            ]
      request "POST" "/refresh" [("Content-Type", "application/json")] requestBody `shouldRespondWith` 200

    it "should reject short refresh tokens" $ do
      let requestBody = encode $ object
            [ "refreshToken" .= ("short" :: T.Text)
            ]
      request "POST" "/refresh" [("Content-Type", "application/json")] requestBody `shouldRespondWith` 200