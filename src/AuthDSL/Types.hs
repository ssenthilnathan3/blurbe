{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.Types
  ( AuthConfig(..)
  , AuthProvider(..)
  , SessionConfig(..)
  , SessionStrategy(..)
  , DatabaseConfig(..)
  , ProtectRule(..)
  , GoogleConfig(..)
  , PasswordConfig(..)
  , JWTConfig(..)
  , CookieConfig(..)
  , DatabaseType(..)
  , Duration(..)
  , ProviderName
  , Scope
  , Role
  ) where

import Data.Text (Text)
import GHC.Generics (Generic)

-- | Main configuration type representing the entire auth.dl file
data AuthConfig = AuthConfig
  { providers :: [AuthProvider]
  , session :: SessionConfig
  , database :: DatabaseConfig
  , protect :: [ProtectRule]
  } deriving (Show, Eq, Generic)

-- | Authentication provider configuration
data AuthProvider 
  = GoogleOAuth GoogleConfig
  | PasswordAuth PasswordConfig
  deriving (Show, Eq, Generic)

-- | Google OAuth2 provider configuration
data GoogleConfig = GoogleConfig
  { googleClientId :: Text
  , googleClientSecret :: Text
  , googleScopes :: [Scope]
  , googleRedirectUri :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Password-based authentication configuration
data PasswordConfig = PasswordConfig
  { passwordMinLength :: Int
  , passwordRequireSpecial :: Bool
  , passwordRequireNumbers :: Bool
  , passwordRequireUppercase :: Bool
  , passwordMaxAttempts :: Int
  , passwordLockoutDuration :: Duration
  } deriving (Show, Eq, Generic)

-- | Session management configuration
data SessionConfig = SessionConfig
  { strategy :: SessionStrategy
  , expiration :: Duration
  , secure :: Bool
  , sameSite :: Text
  , httpOnly :: Bool
  } deriving (Show, Eq, Generic)

-- | Session storage strategy
data SessionStrategy 
  = StoreJWT JWTConfig
  | StoreCookie CookieConfig
  deriving (Show, Eq, Generic)

-- | JWT configuration
data JWTConfig = JWTConfig
  { jwtSecret :: Text
  , jwtAlgorithm :: Text
  , jwtIssuer :: Maybe Text
  , jwtAudience :: Maybe Text
  , jwtRefreshEnabled :: Bool
  } deriving (Show, Eq, Generic)

-- | Cookie-based session configuration
data CookieConfig = CookieConfig
  { cookieName :: Text
  , cookieDomain :: Maybe Text
  , cookiePath :: Text
  , cookieMaxAge :: Maybe Duration
  } deriving (Show, Eq, Generic)

-- | Database configuration
data DatabaseConfig = DatabaseConfig
  { dbType :: DatabaseType
  , dbConnectionString :: Text
  , dbPoolSize :: Int
  , dbTimeout :: Duration
  } deriving (Show, Eq, Generic)

-- | Supported database types
data DatabaseType
  = SQLite
  | PostgreSQL
  | Supabase
  deriving (Show, Eq, Generic)

-- | Route protection rules
data ProtectRule = ProtectRule
  { protectPath :: Text
  , protectMethods :: [Text]
  , protectRoles :: [Role]
  , protectScopes :: [Scope]
  } deriving (Show, Eq, Generic)

-- | Duration type for time-based configurations
data Duration = Duration
  { durationValue :: Int
  , durationUnit :: Text -- "seconds", "minutes", "hours", "days"
  } deriving (Show, Eq, Generic)

-- | Type aliases for clarity
type ProviderName = Text
type Scope = Text
type Role = Text