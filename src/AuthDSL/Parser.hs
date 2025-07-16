{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.Parser
  ( parseAuthConfig
  , parseAuthConfigFile
  ) where

import Control.Monad (void, when)
import Control.Monad.Fail (MonadFail(fail))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Data.Void (Void)
import Text.Megaparsec (Parsec, ParseErrorBundle, (<|>))
import Text.Megaparsec.Char (alphaNumChar, char, letterChar, space1, string)
import qualified Text.Megaparsec.Char.Lexer as L
import qualified Text.Megaparsec as P

import AuthDSL.Types

-- | Parser type for auth.dl files
type Parser = Parsec Void Text

-- | Parse auth configuration from text
parseAuthConfig :: Text -> Either (ParseErrorBundle Text Void) AuthConfig
parseAuthConfig input = P.parse authConfigParser "auth.dl" input

-- | Parse auth configuration from file
parseAuthConfigFile :: FilePath -> IO (Either (ParseErrorBundle Text Void) AuthConfig)
parseAuthConfigFile filepath = do
  content <- T.readFile filepath
  return $ parseAuthConfig content

-- | Space consumer that handles whitespace and comments
sc :: Parser ()
sc = L.space
  space1
  (L.skipLineComment "//")
  (L.skipBlockComment "/*" "*/")

-- | Lexeme parser that consumes trailing whitespace
lexeme :: Parser a -> Parser a
lexeme = L.lexeme sc

-- | Symbol parser that consumes trailing whitespace
symbol :: Text -> Parser Text
symbol = L.symbol sc

-- | Parse identifiers (alphanumeric with underscores)
identifier :: Parser Text
identifier = lexeme $ do
  first <- letterChar <|> char '_'
  rest <- P.many (alphaNumChar <|> char '_')
  return $ T.pack (first : rest)

-- | Parse string literals with double quotes (supports environment variable substitution)
stringLiteral :: Parser Text
stringLiteral = lexeme $ do
  void $ char '"'
  content <- P.many parseStringContent
  void $ char '"'
  return $ T.concat content

-- | Parse string content (regular characters or environment variables)
parseStringContent :: Parser Text
parseStringContent = 
  parseEnvVar <|> parseRegularChar

-- | Parse environment variable reference like ${VAR_NAME}
parseEnvVar :: Parser Text
parseEnvVar = do
  void $ string "${"
  varName <- P.some (alphaNumChar <|> char '_')
  void $ char '}'
  return $ "${" <> T.pack varName <> "}"

-- | Parse regular character (not quote or env var start)
parseRegularChar :: Parser Text
parseRegularChar = do
  c <- P.satisfy (\ch -> ch /= '"' && ch /= '$')
  return $ T.singleton c

-- | Parse integer literals
integerLiteral :: Parser Int
integerLiteral = lexeme L.decimal

-- | Parse boolean literals
booleanLiteral :: Parser Bool
booleanLiteral = lexeme $ 
  (True <$ symbol "true") <|> (False <$ symbol "false")

-- | Parse block structure: blockName { ... }
block :: Text -> Parser a -> Parser a
block blockName contentParser = do
  void $ symbol blockName
  void $ symbol "{"
  content <- contentParser
  void $ symbol "}"
  return content

-- | Main parser for AuthConfig
authConfigParser :: Parser AuthConfig
authConfigParser = do
  sc -- consume initial whitespace
  blocks <- P.many parseTopLevelBlock
  P.eof
  
  -- Extract different block types from parsed blocks
  let providers = [p | ProviderBlock p <- blocks]
      sessions = [s | SessionBlock s <- blocks]
      databases = [d | DatabaseBlock d <- blocks]
      protects = [pr | ProtectBlock pr <- blocks]
  
  -- Use first session/database config or defaults
  let sessionConfig = case sessions of
        (s:_) -> s
        [] -> defaultSessionConfig
      databaseConfig = case databases of
        (d:_) -> d
        [] -> defaultDatabaseConfig
  
  return $ AuthConfig
    { providers = providers
    , session = sessionConfig
    , database = databaseConfig
    , protect = protects
    }

-- | Top-level block types
data TopLevelBlock
  = ProviderBlock AuthProvider
  | SessionBlock SessionConfig
  | DatabaseBlock DatabaseConfig
  | ProtectBlock ProtectRule
  deriving (Show, Eq)

-- | Parse any top-level block
parseTopLevelBlock :: Parser TopLevelBlock
parseTopLevelBlock = 
  (ProviderBlock <$> parseProviderBlock) <|>
  (SessionBlock <$> parseSessionBlock) <|>
  (DatabaseBlock <$> parseDatabaseBlock) <|>
  (ProtectBlock <$> parseProtectBlock)

-- | Parse provider block
parseProviderBlock :: Parser AuthProvider
parseProviderBlock = do
  void $ symbol "provider"
  providerType <- identifier
  case providerType of
    "google" -> GoogleOAuth <$> parseGoogleConfig
    "password" -> PasswordAuth <$> parsePasswordConfig
    _ -> fail $ "Unknown provider type: " <> T.unpack providerType

-- | Parse Google OAuth2 configuration
parseGoogleConfig :: Parser GoogleConfig
parseGoogleConfig = do
  void $ symbol "{"
  fields <- P.many parseGoogleField
  void $ symbol "}"
  
  -- Extract fields with defaults
  let clientId = getField "client_id" fields ""
      clientSecret = getField "client_secret" fields ""
      scopes = getListField "scopes" fields []
      redirectUri = getOptionalField "redirect_uri" fields
  
  -- Validate required fields
  when (T.null clientId) $ fail "client_id is required for Google provider"
  when (T.null clientSecret) $ fail "client_secret is required for Google provider"
  
  return $ GoogleConfig
    { googleClientId = clientId
    , googleClientSecret = clientSecret
    , googleScopes = scopes
    , googleRedirectUri = redirectUri
    }

-- | Parse individual Google configuration field
parseGoogleField :: Parser (Text, ConfigValue)
parseGoogleField = do
  fieldName <- identifier
  void $ symbol "="
  value <- parseConfigValue
  sc -- consume trailing whitespace
  return (fieldName, value)

-- | Parse password authentication configuration
parsePasswordConfig :: Parser PasswordConfig
parsePasswordConfig = do
  void $ symbol "{"
  fields <- P.many parsePasswordField
  void $ symbol "}"
  
  -- Extract fields with defaults
  let minLength = getIntField "min_length" fields 8
      requireSpecial = getBoolField "require_special" fields True
      requireNumbers = getBoolField "require_numbers" fields True
      requireUppercase = getBoolField "require_uppercase" fields True
      maxAttempts = getIntField "max_attempts" fields 5
      lockoutDuration = getDurationField "lockout_duration" fields (Duration 300 "seconds")
  
  return $ PasswordConfig
    { passwordMinLength = minLength
    , passwordRequireSpecial = requireSpecial
    , passwordRequireNumbers = requireNumbers
    , passwordRequireUppercase = requireUppercase
    , passwordMaxAttempts = maxAttempts
    , passwordLockoutDuration = lockoutDuration
    }

-- | Parse individual password configuration field
parsePasswordField :: Parser (Text, ConfigValue)
parsePasswordField = do
  fieldName <- identifier
  void $ symbol "="
  value <- parseConfigValue
  sc -- consume trailing whitespace
  return (fieldName, value)

-- | Configuration value types
data ConfigValue
  = StringValue Text
  | IntValue Int
  | BoolValue Bool
  | ListValue [Text]
  | DurationValue Duration
  | StrategyValue SessionStrategy
  | DatabaseTypeValue DatabaseType
  deriving (Show, Eq)

-- | Parse configuration values
parseConfigValue :: Parser ConfigValue
parseConfigValue = 
  (DurationValue <$> P.try parseDuration) <|>
  (StringValue <$> stringLiteral) <|>
  (IntValue <$> integerLiteral) <|>
  (BoolValue <$> booleanLiteral) <|>
  (ListValue <$> parseStringList)

-- | Parse string lists like ["scope1", "scope2"]
parseStringList :: Parser [Text]
parseStringList = do
  void $ symbol "["
  items <- stringLiteral `P.sepBy` symbol ","
  void $ symbol "]"
  return items

-- | Parse duration values like "5 minutes"
parseDuration :: Parser Duration
parseDuration = do
  value <- integerLiteral
  unit <- identifier
  -- Validate that the unit is a valid time unit
  if unit `elem` ["seconds", "minutes", "hours", "days"]
    then return $ Duration value unit
    else fail $ "Invalid time unit: " <> T.unpack unit

-- | Helper functions to extract typed values from field lists
getField :: Text -> [(Text, ConfigValue)] -> Text -> Text
getField name fields defaultVal = 
  case lookup name fields of
    Just (StringValue val) -> val
    _ -> defaultVal

getIntField :: Text -> [(Text, ConfigValue)] -> Int -> Int
getIntField name fields defaultVal = 
  case lookup name fields of
    Just (IntValue val) -> val
    _ -> defaultVal

getBoolField :: Text -> [(Text, ConfigValue)] -> Bool -> Bool
getBoolField name fields defaultVal = 
  case lookup name fields of
    Just (BoolValue val) -> val
    _ -> defaultVal

getListField :: Text -> [(Text, ConfigValue)] -> [Text] -> [Text]
getListField name fields defaultVal = 
  case lookup name fields of
    Just (ListValue val) -> val
    _ -> defaultVal

getDurationField :: Text -> [(Text, ConfigValue)] -> Duration -> Duration
getDurationField name fields defaultVal = 
  case lookup name fields of
    Just (DurationValue val) -> val
    _ -> defaultVal

getOptionalField :: Text -> [(Text, ConfigValue)] -> Maybe Text
getOptionalField name fields = 
  case lookup name fields of
    Just (StringValue val) -> Just val
    _ -> Nothing

getSessionStrategy :: Text -> [(Text, ConfigValue)] -> SessionStrategy -> SessionStrategy
getSessionStrategy name fields defaultVal = 
  case lookup name fields of
    Just (StrategyValue val) -> val
    _ -> defaultVal

getOptionalDurationField :: Text -> [(Text, ConfigValue)] -> Maybe Duration
getOptionalDurationField name fields = 
  case lookup name fields of
    Just (DurationValue val) -> Just val
    _ -> Nothing

getDatabaseType :: Text -> [(Text, ConfigValue)] -> DatabaseType -> DatabaseType
getDatabaseType name fields defaultVal = 
  case lookup name fields of
    Just (DatabaseTypeValue val) -> val
    _ -> defaultVal

-- | Parse session block
parseSessionBlock :: Parser SessionConfig
parseSessionBlock = block "session" $ do
  fields <- P.many parseSessionField
  
  -- Extract fields with defaults
  let strategy = getSessionStrategy "strategy" fields (StoreJWT defaultJWTConfig)
      expiration = getDurationField "expiration" fields (Duration 3600 "seconds")
      secure = getBoolField "secure" fields True
      sameSite = getField "same_site" fields "Strict"
      httpOnly = getBoolField "http_only" fields True
  
  return $ SessionConfig
    { strategy = strategy
    , expiration = expiration
    , secure = secure
    , sameSite = sameSite
    , httpOnly = httpOnly
    }

-- | Parse individual session configuration field
parseSessionField :: Parser (Text, ConfigValue)
parseSessionField = do
  fieldName <- identifier
  void $ symbol "="
  value <- parseSessionValue fieldName
  sc -- consume trailing whitespace
  return (fieldName, value)

-- | Parse session-specific values (handles strategy blocks)
parseSessionValue :: Text -> Parser ConfigValue
parseSessionValue "strategy" = StrategyValue <$> parseSessionStrategy
parseSessionValue _ = parseConfigValue

-- | Parse session strategy (JWT or Cookie)
parseSessionStrategy :: Parser SessionStrategy
parseSessionStrategy = do
  -- Try parsing as string literal first, then as identifier with config block
  strategyType <- stringLiteral <|> identifier
  case strategyType of
    "jwt" -> do
      -- Check if there's a config block following
      maybeConfig <- P.optional parseJWTConfig
      case maybeConfig of
        Just config -> return $ StoreJWT config
        Nothing -> return $ StoreJWT defaultJWTConfig
    "cookie" -> do
      -- Check if there's a config block following
      maybeConfig <- P.optional parseCookieConfig
      case maybeConfig of
        Just config -> return $ StoreCookie config
        Nothing -> return $ StoreCookie defaultCookieConfig
    _ -> fail $ "Unknown session strategy: " <> T.unpack strategyType

-- | Parse JWT configuration
parseJWTConfig :: Parser JWTConfig
parseJWTConfig = do
  void $ symbol "{"
  fields <- P.many parseJWTField
  void $ symbol "}"
  
  let secret = getField "secret" fields "your-secret-key"
      algorithm = getField "algorithm" fields "HS256"
      issuer = getOptionalField "issuer" fields
      audience = getOptionalField "audience" fields
      refreshEnabled = getBoolField "refresh_enabled" fields True
  
  return $ JWTConfig
    { jwtSecret = secret
    , jwtAlgorithm = algorithm
    , jwtIssuer = issuer
    , jwtAudience = audience
    , jwtRefreshEnabled = refreshEnabled
    }

-- | Parse JWT configuration field
parseJWTField :: Parser (Text, ConfigValue)
parseJWTField = do
  fieldName <- identifier
  void $ symbol "="
  value <- parseConfigValue
  sc
  return (fieldName, value)

-- | Parse Cookie configuration
parseCookieConfig :: Parser CookieConfig
parseCookieConfig = do
  void $ symbol "{"
  fields <- P.many parseCookieField
  void $ symbol "}"
  
  let name = getField "name" fields "auth_session"
      domain = getOptionalField "domain" fields
      path = getField "path" fields "/"
      maxAge = getOptionalDurationField "max_age" fields
  
  return $ CookieConfig
    { cookieName = name
    , cookieDomain = domain
    , cookiePath = path
    , cookieMaxAge = maxAge
    }

-- | Parse Cookie configuration field
parseCookieField :: Parser (Text, ConfigValue)
parseCookieField = do
  fieldName <- identifier
  void $ symbol "="
  value <- parseConfigValue
  sc
  return (fieldName, value)

-- | Parse database block
parseDatabaseBlock :: Parser DatabaseConfig
parseDatabaseBlock = block "database" $ do
  fields <- P.many parseDatabaseField
  
  -- Extract fields with defaults
  let dbType = getDatabaseType "type" fields SQLite
      connectionString = getField "connection_string" fields "auth.db"
      poolSize = getIntField "pool_size" fields 10
      timeout = getDurationField "timeout" fields (Duration 30 "seconds")
  
  return $ DatabaseConfig
    { dbType = dbType
    , dbConnectionString = connectionString
    , dbPoolSize = poolSize
    , dbTimeout = timeout
    }

-- | Parse individual database configuration field
parseDatabaseField :: Parser (Text, ConfigValue)
parseDatabaseField = do
  fieldName <- identifier
  void $ symbol "="
  value <- parseDatabaseValue fieldName
  sc -- consume trailing whitespace
  return (fieldName, value)

-- | Parse database-specific values (handles type field)
parseDatabaseValue :: Text -> Parser ConfigValue
parseDatabaseValue "type" = DatabaseTypeValue <$> parseDatabaseType
parseDatabaseValue _ = parseConfigValue

-- | Parse database type
parseDatabaseType :: Parser DatabaseType
parseDatabaseType = do
  dbTypeStr <- stringLiteral <|> identifier
  case dbTypeStr of
    "sqlite" -> return SQLite
    "postgresql" -> return PostgreSQL
    "supabase" -> return Supabase
    _ -> fail $ "Unknown database type: " <> T.unpack dbTypeStr

-- | Parse protect block
parseProtectBlock :: Parser ProtectRule
parseProtectBlock = do
  void $ symbol "protect"
  path <- stringLiteral
  void $ symbol "{"
  fields <- P.many parseProtectField
  void $ symbol "}"
  
  let methods = getListField "methods" fields ["GET", "POST"]
      roles = getListField "roles" fields []
      scopes = getListField "scopes" fields []
  
  return $ ProtectRule
    { protectPath = path
    , protectMethods = methods
    , protectRoles = roles
    , protectScopes = scopes
    }

-- | Parse protect field
parseProtectField :: Parser (Text, ConfigValue)
parseProtectField = do
  fieldName <- identifier
  void $ symbol "="
  value <- parseConfigValue
  sc -- consume trailing whitespace
  return (fieldName, value)

-- | Default session configuration
defaultSessionConfig :: SessionConfig
defaultSessionConfig = SessionConfig
  { strategy = StoreJWT defaultJWTConfig
  , expiration = Duration 3600 "seconds"
  , secure = True
  , sameSite = "Strict"
  , httpOnly = True
  }

-- | Default JWT configuration
defaultJWTConfig :: JWTConfig
defaultJWTConfig = JWTConfig
  { jwtSecret = "your-secret-key"
  , jwtAlgorithm = "HS256"
  , jwtIssuer = Nothing
  , jwtAudience = Nothing
  , jwtRefreshEnabled = True
  }

-- | Default cookie configuration
defaultCookieConfig :: CookieConfig
defaultCookieConfig = CookieConfig
  { cookieName = "auth_session"
  , cookieDomain = Nothing
  , cookiePath = "/"
  , cookieMaxAge = Just (Duration 3600 "seconds")
  }

-- | Default database configuration
defaultDatabaseConfig :: DatabaseConfig
defaultDatabaseConfig = DatabaseConfig
  { dbType = SQLite
  , dbConnectionString = "auth.db"
  , dbPoolSize = 10
  , dbTimeout = Duration 30 "seconds"
  }