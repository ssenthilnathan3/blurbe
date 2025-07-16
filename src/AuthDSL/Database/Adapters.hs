{-# LANGUAGE ExistentialQuantification #-}

module AuthDSL.Database.Adapters
  ( AnyDatabaseAdapter(..)
  , createDatabaseAdapterFromConfig
  ) where

import AuthDSL.Database
import AuthDSL.Types (DatabaseType(..), DatabaseConfig(..))
import qualified AuthDSL.Database.SQLite as SQLite
import qualified AuthDSL.Database.PostgreSQL as PostgreSQL
import qualified AuthDSL.Database.Supabase as Supabase

-- | Existential type wrapper for any database adapter
data AnyDatabaseAdapter = forall a. DatabaseAdapter a => AnyDatabaseAdapter a

instance DatabaseAdapter AnyDatabaseAdapter where
  createUser (AnyDatabaseAdapter adapter) = createUser adapter
  getUserById (AnyDatabaseAdapter adapter) = getUserById adapter
  getUserByEmail (AnyDatabaseAdapter adapter) = getUserByEmail adapter
  updateUser (AnyDatabaseAdapter adapter) = updateUser adapter
  deleteUser (AnyDatabaseAdapter adapter) = deleteUser adapter
  createSession (AnyDatabaseAdapter adapter) = createSession adapter
  getSession (AnyDatabaseAdapter adapter) = getSession adapter
  updateSession (AnyDatabaseAdapter adapter) = updateSession adapter
  deleteSession (AnyDatabaseAdapter adapter) = deleteSession adapter
  deleteExpiredSessions (AnyDatabaseAdapter adapter) = deleteExpiredSessions adapter
  addUserProvider (AnyDatabaseAdapter adapter) = addUserProvider adapter
  removeUserProvider (AnyDatabaseAdapter adapter) = removeUserProvider adapter
  getUserByProvider (AnyDatabaseAdapter adapter) = getUserByProvider adapter

-- | Create database adapter from configuration
createDatabaseAdapterFromConfig :: DatabaseConfig -> IO (Either DatabaseError AnyDatabaseAdapter)
createDatabaseAdapterFromConfig config = do
  dbConnResult <- createDatabaseAdapter config
  case dbConnResult of
    Left err -> return $ Left err
    Right dbConn -> 
      case dbType config of
        SQLite -> do
          result <- SQLite.createSQLiteAdapter dbConn
          case result of
            Left err -> return $ Left err
            Right adapter -> return $ Right $ AnyDatabaseAdapter adapter
        PostgreSQL -> do
          result <- PostgreSQL.createPostgreSQLAdapter dbConn
          case result of
            Left err -> return $ Left err
            Right adapter -> return $ Right $ AnyDatabaseAdapter adapter
        Supabase -> do
          result <- Supabase.createSupabaseAdapter dbConn
          case result of
            Left err -> return $ Left err
            Right adapter -> return $ Right $ AnyDatabaseAdapter adapter