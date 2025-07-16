{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.JWTSessionSpec (spec) where

import Test.Hspec
import Data.Time (getCurrentTime, addUTCTime)
import Control.Concurrent.STM (newTVarIO)
import qualified Data.Map as Map

import AuthDSL.Session
import AuthDSL.Types

spec :: Spec
spec = describe "JWT Session Manager" $ do
  it "creates and validates JWT sessions" $ do
    -- Create JWT configuration
    let jwtConfig = JWTConfig
          { jwtSecret = "test-secret-key"
          , jwtAlgorithm = "HS256"
          , jwtIssuer = Just "auth-dsl-test"
          , jwtAudience = Just "test-app"
          , jwtRefreshEnabled = True
          }
    
    -- Create JWT session manager
    manager <- createJWTSessionManager jwtConfig 3600
    
    -- Create a test session
    currentTime <- getCurrentTime
    let sessionMetadata = SessionMetadata
          { userAgent = Just "test-agent"
          , ipAddress = Just "127.0.0.1"
          , deviceId = Just "test-device"
          }
    
    -- Test session creation
    result <- createSession manager "test-user" ["read", "write"] ["user"] sessionMetadata
    case result of
      Left err -> expectationFailure $ "Failed to create session: " ++ show err
      Right session -> do
        -- Verify session properties
        userId session `shouldBe` "test-user"
        scopes session `shouldBe` ["read", "write"]
        roles session `shouldBe` ["user"]
        
        -- Test session validation
        let token = generateJWTToken jwtConfig (jwtSecretKey manager) session currentTime
        validationResult <- validateJWTToken (jwtSecretKey manager) (jwtTokenValue token)
        case validationResult of
          Left err -> expectationFailure $ "Failed to validate session: " ++ show err
          Right validatedSession -> do
            userId validatedSession `shouldBe` "test-user"
            scopes validatedSession `shouldBe` ["read", "write"]
            roles validatedSession `shouldBe` ["user"]

  it "handles refresh tokens when enabled" $ do
    -- Create JWT configuration with refresh enabled
    let jwtConfig = JWTConfig
          { jwtSecret = "test-secret-key"
          , jwtAlgorithm = "HS256"
          , jwtIssuer = Just "auth-dsl-test"
          , jwtAudience = Just "test-app"
          , jwtRefreshEnabled = True
          }
    
    -- Create JWT session manager
    manager <- createJWTSessionManager jwtConfig 3600
    
    -- Create a test session
    let sessionMetadata = SessionMetadata
          { userAgent = Just "test-agent"
          , ipAddress = Just "127.0.0.1"
          , deviceId = Just "test-device"
          }
    
    -- Test session creation
    result <- createSession manager "test-user" ["read"] ["user"] sessionMetadata
    case result of
      Left err -> expectationFailure $ "Failed to create session: " ++ show err
      Right session -> do
        -- Verify that refresh tokens are enabled
        refreshEnabled manager `shouldBe` True

  it "rejects invalid JWT tokens" $ do
    -- Create JWT configuration
    let jwtConfig = JWTConfig
          { jwtSecret = "test-secret-key"
          , jwtAlgorithm = "HS256"
          , jwtIssuer = Just "auth-dsl-test"
          , jwtAudience = Just "test-app"
          , jwtRefreshEnabled = False
          }
    
    -- Create JWT session manager
    manager <- createJWTSessionManager jwtConfig 3600
    
    -- Test with invalid token
    validationResult <- validateJWTToken (jwtSecretKey manager) "invalid-token"
    case validationResult of
      Left _ -> return () -- Expected
      Right _ -> expectationFailure "Should have rejected invalid token"

  it "handles expired tokens" $ do
    -- Create JWT configuration
    let jwtConfig = JWTConfig
          { jwtSecret = "test-secret-key"
          , jwtAlgorithm = "HS256"
          , jwtIssuer = Just "auth-dsl-test"
          , jwtAudience = Just "test-app"
          , jwtRefreshEnabled = False
          }
    
    -- Create JWT session manager
    manager <- createJWTSessionManager jwtConfig 1 -- 1 second expiration
    
    -- Create a test session
    currentTime <- getCurrentTime
    let sessionMetadata = SessionMetadata
          { userAgent = Just "test-agent"
          , ipAddress = Just "127.0.0.1"
          , deviceId = Just "test-device"
          }
        -- Create an expired session (expires in the past)
        expiredSession = UserSession
          { sessionId = "test-session"
          , userId = "test-user"
          , expiresAt = addUTCTime (-3600) currentTime -- Expired 1 hour ago
          , scopes = ["read"]
          , roles = ["user"]
          , metadata = sessionMetadata
          , createdAt = currentTime
          , lastAccessedAt = currentTime
          }
    
    -- Generate token for expired session
    let token = generateJWTToken jwtConfig (jwtSecretKey manager) expiredSession currentTime
    
    -- Test validation of expired token
    validationResult <- validateJWTToken (jwtSecretKey manager) (jwtTokenValue token)
    case validationResult of
      Left _ -> return () -- Expected - token should be expired
      Right _ -> expectationFailure "Should have rejected expired token"