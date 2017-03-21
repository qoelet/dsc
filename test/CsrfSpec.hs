{-# LANGUAGE OverloadedStrings #-}

module CsrfSpec where

import           Codec.Crypto.SimpleAES
import           Data.ByteString.Base64.URL
import           Data.String.Conversions
import           Test.Hspec
import           Test.QuickCheck
import           Test.QuickCheck.Monadic as Q

import           Web.Csrf

spec :: Spec
spec = do
  describe "getCsrf" $
    it "should generating matching tokens" $
      property propGetCsrfShouldAlwaysBeValid
  describe "runCheck" $
    it "should invalidate if csrf tokens do not match" $
      property propTokenMisMatchShouldBeInvalid

propGetCsrfShouldAlwaysBeValid :: Property
propGetCsrfShouldAlwaysBeValid = Q.monadicIO $ do
  testKey <- Q.run randomKey
  myCsrf <- Q.run (getCsrf (encode testKey))
  Q.assert $ validationResult (runCheck (encode testKey) myCsrf) == Just Valid

propTokenMisMatchShouldBeInvalid :: Property
propTokenMisMatchShouldBeInvalid = Q.monadicIO $ do
  testKey <- Q.run randomKey
  secret <- Q.run randomKey
  cookieToken <- Q.run $ encryptMsg ECB testKey (cs secret)
  let badToken = "Foo"
      myCsrf = mkCsrf testKey (encode . cs $ cookieToken) badToken
  Q.assert $ validationResult (runCheck (encode testKey) myCsrf) == Just Invalid
