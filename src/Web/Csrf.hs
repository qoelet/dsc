module Web.Csrf (
  Csrf (..)
, CsrfCheckResult (..)
, mkCsrf
, getCsrf
, runCheck
, unMkToken
) where

import           Codec.Crypto.SimpleAES
import           Data.ByteString
import           Data.ByteString.Base64.URL
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

runCheck :: ByteString -> Csrf -> Csrf
runCheck keyBS csrf@(Csrf (MkToken c) (MkToken t) _) = csrf { validationResult = Just result }
  where
    key :: ByteString
    key = decodeLenient keyBS

    result :: CsrfCheckResult
    result = case (decode c, decode t) of
      (Right c', Right t') ->
        if decryptMsg ECB key (cs c') == decryptMsg ECB key (cs t')
          then Valid
          else Invalid
      _ -> Invalid

getCsrf :: ByteString -> IO Csrf
getCsrf key = do
  secret <- randomKey
  c <- encryptMsg ECB (decodeLenient key) (cs secret)
  t <- encryptMsg ECB (decodeLenient key) (cs secret)
  return $ Csrf
    (MkToken (encode . cs $ c))
    (MkToken (encode . cs $ t))
    Nothing

mkCsrf :: ByteString -> ByteString -> ByteString -> Csrf
mkCsrf keyBS c t
  = runCheck keyBS (Csrf (MkToken c) (MkToken t) Nothing)

unMkToken :: Token -> ByteString
unMkToken (MkToken x) = x
