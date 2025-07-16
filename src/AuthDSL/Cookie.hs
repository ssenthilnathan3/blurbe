{-# LANGUAGE OverloadedStrings #-}

module AuthDSL.Cookie
  ( CookieSettings(..)
  , SessionCookie(..)
  , createSessionCookie
  , parseSessionCookie
  , expireSessionCookie
  , cookieToHeader
  , defaultCookieSettings
  , productionCookieSettings
  , developmentCookieSettings
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime, formatTime, defaultTimeLocale)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as LBS
import Data.ByteString.Builder (toLazyByteString)
import Network.HTTP.Types (Header)
import Web.Cookie (SetCookie(..), renderSetCookie, parseCookies, SameSiteOption, def, sameSiteStrict, sameSiteLax, sameSiteNone)

import AuthDSL.Types (CookieConfig, Duration(..))
import qualified AuthDSL.Types as Types
import AuthDSL.Session (SessionId)

-- | Cookie settings for session management
data CookieSettings = CookieSettings
  { cookieName :: Text
  , cookieDomain :: Maybe Text
  , cookiePath :: Text
  , cookieSecure :: Bool
  , cookieHttpOnly :: Bool
  , cookieSameSite :: Text
  , cookieMaxAge :: Maybe Int -- seconds
  } deriving (Show, Eq)

-- | Session cookie data
data SessionCookie = SessionCookie
  { sessionCookieId :: SessionId
  , sessionCookieSettings :: CookieSettings
  } deriving (Show, Eq)

-- | Production-ready cookie settings for secure environments
productionCookieSettings :: CookieConfig -> CookieSettings
productionCookieSettings config = CookieSettings
  { cookieName = Types.cookieName config
  , cookieDomain = Types.cookieDomain config
  , cookiePath = Types.cookiePath config
  , cookieSecure = True -- Always secure in production
  , cookieHttpOnly = True -- Always true for security
  , cookieSameSite = "Strict" -- Strict for maximum security in production
  , cookieMaxAge = durationToSeconds <$> Types.cookieMaxAge config
  }
  where
    durationToSeconds (Duration value unit) = case unit of
      "seconds" -> value
      "minutes" -> value * 60
      "hours" -> value * 3600
      "days" -> value * 86400
      _ -> value

-- | Development cookie settings (less restrictive for local development)
developmentCookieSettings :: CookieConfig -> CookieSettings
developmentCookieSettings config = CookieSettings
  { cookieName = Types.cookieName config
  , cookieDomain = Types.cookieDomain config
  , cookiePath = Types.cookiePath config
  , cookieSecure = False -- Allow HTTP in development
  , cookieHttpOnly = True -- Always true for security
  , cookieSameSite = "Lax" -- Lax for easier development
  , cookieMaxAge = durationToSeconds <$> Types.cookieMaxAge config
  }
  where
    durationToSeconds (Duration value unit) = case unit of
      "seconds" -> value
      "minutes" -> value * 60
      "hours" -> value * 3600
      "days" -> value * 86400
      _ -> value

-- | Create default cookie settings from CookieConfig
defaultCookieSettings :: CookieConfig -> Bool -> CookieSettings
defaultCookieSettings config isHTTPS = 
  if isHTTPS 
    then productionCookieSettings config
    else developmentCookieSettings config

-- | Create a session cookie with the given session ID
createSessionCookie :: SessionId -> CookieSettings -> SessionCookie
createSessionCookie sessionId settings = SessionCookie
  { sessionCookieId = sessionId
  , sessionCookieSettings = settings
  }

-- | Parse session cookie from request headers
parseSessionCookie :: CookieSettings -> ByteString -> Maybe SessionId
parseSessionCookie settings cookieHeader = do
  let cookies = parseCookies cookieHeader
      cookieNameBS = TE.encodeUtf8 (cookieName settings)
  cookieValue <- lookup cookieNameBS cookies
  return $ TE.decodeUtf8 cookieValue

-- | Create an expired session cookie for logout
expireSessionCookie :: CookieSettings -> SessionCookie
expireSessionCookie settings = SessionCookie
  { sessionCookieId = ""
  , sessionCookieSettings = settings { cookieMaxAge = Just 0 }
  }

-- | Convert session cookie to HTTP Set-Cookie header
cookieToHeader :: SessionCookie -> Header
cookieToHeader sessionCookie = 
  let settings = sessionCookieSettings sessionCookie
      setCookie = def
        { setCookieName = TE.encodeUtf8 (cookieName settings)
        , setCookieValue = TE.encodeUtf8 (sessionCookieId sessionCookie)
        , setCookiePath = Just $ TE.encodeUtf8 (cookiePath settings)
        , setCookieExpires = Nothing -- Use Max-Age instead
        , setCookieMaxAge = fromIntegral <$> cookieMaxAge settings
        , setCookieDomain = TE.encodeUtf8 <$> cookieDomain settings
        , setCookieHttpOnly = cookieHttpOnly settings
        , setCookieSecure = cookieSecure settings
        , setCookieSameSite = parseSameSite (cookieSameSite settings)
        }
  in ("Set-Cookie", LBS.toStrict $ toLazyByteString $ renderSetCookie setCookie)

-- | Parse SameSite attribute
parseSameSite :: Text -> Maybe SameSiteOption
parseSameSite sameSite = case T.toLower sameSite of
  "strict" -> Just sameSiteStrict
  "lax" -> Just sameSiteLax
  "none" -> Just sameSiteNone
  _ -> Just sameSiteLax -- Default to Lax