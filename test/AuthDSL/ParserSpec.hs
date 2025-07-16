{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.ParserSpec (spec) where

import Test.Hspec
import Test.QuickCheck
import Data.Text (Text)
import qualified Data.Text as T
import Text.Megaparsec (errorBundlePretty)

import AuthDSL.Parser
import AuthDSL.Types

spec :: Spec
spec = describe "AuthDSL.Parser" $ do
  describe "Basic parsing" $ do
    it "parses empty configuration" $ do
      let result = parseAuthConfig ""
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          providers config `shouldBe` []
          protect config `shouldBe` []

    it "parses configuration with comments" $ do
      let input = "// This is a comment\n/* Block comment */\n"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          providers config `shouldBe` []

    it "parses single provider block" $ do
      let input = "provider google { client_id = \"test_id\" client_secret = \"test_secret\" }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          length (providers config) `shouldBe` 1

    it "parses multiple blocks" $ do
      let input = "provider google { client_id = \"test_id\" client_secret = \"test_secret\" }\nsession { }\ndatabase { }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          length (providers config) `shouldBe` 1

  describe "Whitespace handling" $ do
    it "handles various whitespace patterns" $ property prop_whitespaceHandling

  describe "Block structure" $ do
    it "requires proper block syntax" $ property prop_blockStructure

  describe "Provider parsing" $ do
    it "parses Google OAuth2 provider with required fields" $ do
      let input = "provider google { client_id = \"test_client_id\" client_secret = \"test_secret\" }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          length (providers config) `shouldBe` 1
          case head (providers config) of
            GoogleOAuth googleConfig -> do
              googleClientId googleConfig `shouldBe` "test_client_id"
              googleClientSecret googleConfig `shouldBe` "test_secret"
              googleScopes googleConfig `shouldBe` []
              googleRedirectUri googleConfig `shouldBe` Nothing
            _ -> expectationFailure "Expected GoogleOAuth provider"

    it "parses Google OAuth2 provider with optional fields" $ do
      let input = "provider google { client_id = \"test_id\" client_secret = \"test_secret\" scopes = [\"email\", \"profile\"] redirect_uri = \"http://localhost:3000/callback\" }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          length (providers config) `shouldBe` 1
          case head (providers config) of
            GoogleOAuth googleConfig -> do
              googleClientId googleConfig `shouldBe` "test_id"
              googleClientSecret googleConfig `shouldBe` "test_secret"
              googleScopes googleConfig `shouldBe` ["email", "profile"]
              googleRedirectUri googleConfig `shouldBe` Just "http://localhost:3000/callback"
            _ -> expectationFailure "Expected GoogleOAuth provider"

    it "parses password authentication provider with defaults" $ do
      let input = "provider password { }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          length (providers config) `shouldBe` 1
          case head (providers config) of
            PasswordAuth passwordConfig -> do
              passwordMinLength passwordConfig `shouldBe` 8
              passwordRequireSpecial passwordConfig `shouldBe` True
              passwordRequireNumbers passwordConfig `shouldBe` True
              passwordRequireUppercase passwordConfig `shouldBe` True
              passwordMaxAttempts passwordConfig `shouldBe` 5
            _ -> expectationFailure "Expected PasswordAuth provider"

    it "parses password authentication provider with custom settings" $ do
      let input = "provider password { min_length = 12 require_special = false max_attempts = 3 lockout_duration = 600 seconds }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          length (providers config) `shouldBe` 1
          case head (providers config) of
            PasswordAuth passwordConfig -> do
              passwordMinLength passwordConfig `shouldBe` 12
              passwordRequireSpecial passwordConfig `shouldBe` False
              passwordMaxAttempts passwordConfig `shouldBe` 3
              let Duration value unit = passwordLockoutDuration passwordConfig
              value `shouldBe` 600
              unit `shouldBe` "seconds"
            _ -> expectationFailure "Expected PasswordAuth provider"

    it "fails to parse Google provider without required fields" $ do
      let input = "provider google { }"
      let result = parseAuthConfig input
      case result of
        Left _ -> return () -- Expected to fail
        Right _ -> expectationFailure "Expected parse to fail for missing required fields"

    it "fails to parse unknown provider type" $ do
      let input = "provider unknown { }"
      let result = parseAuthConfig input
      case result of
        Left _ -> return () -- Expected to fail
        Right _ -> expectationFailure "Expected parse to fail for unknown provider type"

  describe "Session parsing" $ do
    it "parses session block with JWT strategy" $ do
      let input = "session { strategy = jwt { secret = \"my-secret\" algorithm = \"HS256\" } expiration = 3600 seconds }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          let sessionConfig = session config
          case strategy sessionConfig of
            StoreJWT jwtConfig -> do
              jwtSecret jwtConfig `shouldBe` "my-secret"
              jwtAlgorithm jwtConfig `shouldBe` "HS256"
            _ -> expectationFailure "Expected JWT strategy"

    it "parses session block with Cookie strategy" $ do
      let input = "session { strategy = cookie { name = \"auth_session\" path = \"/\" } secure = true }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          let sessionConfig = session config
          case strategy sessionConfig of
            StoreCookie cookieConfig -> do
              cookieName cookieConfig `shouldBe` "auth_session"
              cookiePath cookieConfig `shouldBe` "/"
            _ -> expectationFailure "Expected Cookie strategy"

    it "parses session block with defaults" $ do
      let input = "session { }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          let sessionConfig = session config
          secure sessionConfig `shouldBe` True
          httpOnly sessionConfig `shouldBe` True

  describe "Database parsing" $ do
    it "parses database block with SQLite" $ do
      let input = "database { type = sqlite connection_string = \"auth.db\" }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          let databaseConfig = database config
          dbType databaseConfig `shouldBe` SQLite
          dbConnectionString databaseConfig `shouldBe` "auth.db"

    it "parses database block with PostgreSQL" $ do
      let input = "database { type = postgresql connection_string = \"postgresql://localhost/auth\" pool_size = 20 }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          let databaseConfig = database config
          dbType databaseConfig `shouldBe` PostgreSQL
          dbConnectionString databaseConfig `shouldBe` "postgresql://localhost/auth"
          dbPoolSize databaseConfig `shouldBe` 20

    it "parses database block with Supabase" $ do
      let input = "database { type = supabase connection_string = \"https://project.supabase.co\" }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          let databaseConfig = database config
          dbType databaseConfig `shouldBe` Supabase
          dbConnectionString databaseConfig `shouldBe` "https://project.supabase.co"

  describe "Environment variable substitution" $ do
    it "parses strings with environment variable references" $ do
      let input = "database { connection_string = \"postgresql://${DB_HOST}:${DB_PORT}/auth\" }"
      let result = parseAuthConfig input
      case result of
        Left err -> expectationFailure $ "Parse failed: " ++ errorBundlePretty err
        Right config -> do
          let databaseConfig = database config
          dbConnectionString databaseConfig `shouldBe` "postgresql://${DB_HOST}:${DB_PORT}/auth"

-- | Property: Parser should handle various whitespace patterns
prop_whitespaceHandling :: Property
prop_whitespaceHandling = forAll genWhitespace $ \ws ->
  let input = ws <> "provider google { client_id = \"test\" client_secret = \"test\" }" <> ws
      result = parseAuthConfig input
  in case result of
    Left _ -> False
    Right config -> length (providers config) == 1

-- | Property: Block structure should be validated
prop_blockStructure :: Property
prop_blockStructure = forAll genValidBlock $ \block ->
  let result = parseAuthConfig block
  in case result of
    Left _ -> False
    Right _ -> True

-- | Generate various whitespace patterns
genWhitespace :: Gen Text
genWhitespace = do
  spaces <- listOf (elements [' ', '\t', '\n', '\r'])
  return $ T.pack spaces

-- | Generate valid block structures
genValidBlock :: Gen Text
genValidBlock = oneof
  [ return "session { strategy = \"jwt\" }"
  , return "database { type = \"sqlite\" connection_string = \"test.db\" }"
  , return "protect \"/api\" { methods = [\"GET\"] }"
  ]

-- | Generate invalid block structures for negative testing
genInvalidBlock :: Gen Text
genInvalidBlock = oneof
  [ return "provider {" -- missing closing brace
  , return "provider }" -- missing opening brace
  , return "provider" -- missing braces entirely
  , return "{ }" -- missing block name
  ]

-- | Property: Invalid blocks should fail to parse
prop_invalidBlocksFail :: Property
prop_invalidBlocksFail = forAll genInvalidBlock $ \block ->
  let result = parseAuthConfig block
  in case result of
    Left _ -> True
    Right _ -> False