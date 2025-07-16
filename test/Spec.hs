import Test.Hspec

import qualified AuthDSL.ParserSpec as ParserSpec
import qualified AuthDSL.ConfigSpec as ConfigSpec
import qualified AuthDSL.DatabaseSpec as DatabaseSpec
import qualified AuthDSL.Database.AdaptersSpec as AdaptersSpec
import qualified AuthDSL.JWTSessionSpec as JWTSessionSpec
import qualified AuthDSL.ServerSpec as ServerSpec
import qualified AuthDSL.RegistrationRefreshSpec as RegistrationRefreshSpec
import qualified AuthDSL.SecuritySpec as SecuritySpec

main :: IO ()
main = hspec $ do
  ParserSpec.spec
  ConfigSpec.spec
  DatabaseSpec.spec
  AdaptersSpec.spec
  JWTSessionSpec.spec
  ServerSpec.spec
  RegistrationRefreshSpec.spec
  SecuritySpec.spec