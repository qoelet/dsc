module Web.Csrf (
  Csrf (..)
, CsrfCheckResult (..)
, mkCsrf
, getCsrf
, runCheck
) where

import           Codec.Crypto.SimpleAES
import           Data.ByteString
import           Data.ByteString.Base64
import           Data.String.Conversions

newtype Token = MkToken ByteString
  deriving (Eq, Show)

data CsrfCheckResult = Invalid | Valid
  deriving (Eq, Show)

data Csrf = Csrf {
  cookie :: Token
, formToken :: Token
, validationResult :: Maybe CsrfCheckResult
} deriving (Eq, Show)

runCheck :: Key -> Csrf -> Csrf
runCheck key csrf@(Csrf (MkToken c) (MkToken t) _) = csrf { validationResult = Just result }
  where
    result = case (decode c, decode t) of
      (Right c', Right t') ->
        if decryptMsg ECB key (cs c') == decryptMsg ECB key (cs t')
          then Valid
          else Invalid
      _ -> Invalid

getCsrf :: Key -> IO Csrf
getCsrf key = do
  secret <- randomKey
  c <- encryptMsg ECB key (cs secret)
  t <- encryptMsg ECB key (cs secret)
  return $ Csrf (MkToken (encode . cs $ c)) (MkToken (encode . cs $ t)) Nothing

mkCsrf :: Key -> ByteString -> ByteString -> Csrf
mkCsrf key c t = runCheck key (Csrf (MkToken c) (MkToken t) Nothing)
