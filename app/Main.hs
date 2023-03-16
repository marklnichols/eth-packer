{-# LANGUAGE OverloadedStrings#-}

module Main where

import Crypto.Hash.Keccak (keccak256)
import qualified Crypto.Secp256k1 as SC
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Builder as Bldr
import qualified Data.ByteString.Lazy.Char8 as C8 (pack)
import qualified Data.ByteString as StrictBS
import qualified Data.Serialize
import qualified Data.Text
import Text.Hex (decodeHex, encodeHex)
import Text.Show
import Numeric
import GHC.RTS.Flags (MiscFlags(tickInterval))
import Debug.Trace

txTypeHash :: String
txTypeHash = "0x3ee892349ae4bbe61dce18f95115b5dc02daf49204cc602458cd4c1f540d56d7"

nameHash :: String
nameHash = "0xb7a0bfa1b79f2443f4d73ebb9259cddbcd510b18be6fc4da7d1aa7b1786e73e6"

versionHash :: String
versionHash = "0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6"

eip712DomainTypeHash :: String
eip712DomainTypeHash = "0xd87cd6ef79d4e2b95e15ce8abf732db51ec771f1ca2edccf22a46c729ac56472"

salt :: String
salt = "0x251543af6a222378665a76fe38dbceae4871a070b7fdaf5c6c30cf758dc33cc0"

chainId :: Int
chainId = 1

sha3NullS :: ByteString
sha3NullS = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

zeroAddr :: String
zeroAddr = "0x0000000000000000000000000000000000000000"

main :: IO ()
main = do
  putStrLn "Step by step: "
  let msigAddr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
  let domainSep = domainData msigAddr
  printBS domainSep "domain separator (hash) "

  let nonce = 0;
  let destinationAddr = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";
  let value = 1000000000000000;
  let dataStr = "";
  let executor = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
  let gasLimit = 21000;
  let pk0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

  let transInput = txInput nonce destinationAddr value dataStr executor gasLimit
  printBS transInput "txInput hash"

  let theInput = input domainSep transInput
  printBS theInput "input (hash)"

  putStrLn "One single step: "
  let result = packData msigAddr nonce destinationAddr value dataStr executor gasLimit
  printBS result "input (hash)"

  putStrLn "signing: "
  let theSig = ecSign result pk0 31337
  printBS theSig "signature"

packData :: String -> Int -> String -> Int -> String -> String -> Int -> ByteString
packData multiSigAddr nonce destinationAddr value dataStr executor gasLimit =
  let dd = domainData multiSigAddr
      txi = txInput nonce destinationAddr value dataStr executor gasLimit
  in input dd txi

domainData :: String -> B.ByteString
domainData multiSigAddr =
  let dd =
        drop 2 eip712DomainTypeHash
        ++ take 2 (drop 2 nameHash)
        ++ take 2 (drop 2 versionHash)
        ++ padBefore (hexStr chainId) '0' 64
        ++ padBefore (take 2 (drop 2 multiSigAddr)) '0' 64
        ++ take 2 (drop 2 salt)
  in withPrefix $ hash dd

txInput :: Int -> String -> Int -> String -> String -> Int -> ByteString
txInput nonce destinationAddr value dataStr executor gasLimit =
  let txIn =
        let dataSlice =
              let hashedData = if null dataStr then sha3NullS
                               else hash dataStr
              in B.take 2 hashedData
        in txTypeHash
          ++ padBefore (take 2 (drop 2 destinationAddr)) '0' 64
          ++ padBefore (hexStr value) '0' 64
          ++ show dataSlice
          ++ padBefore (hexStr nonce) '0' 64
          ++ padBefore (take 2 (drop 2 executor)) '0' 64
          ++ padBefore (hexStr gasLimit) '0' 64
  in withPrefix $ hash txIn

input :: ByteString -> ByteString -> ByteString
input domainSeparator txInputHash =
  let theInput =
        Bldr.lazyByteString "19"
        <> "01"
        <> Bldr.lazyByteString (B.take 2 domainSeparator)
        <> Bldr.lazyByteString (B.take 2 txInputHash)
  in withPrefix $ hashBS $ Bldr.toLazyByteString theInput

hash :: String -> ByteString
hash s = hashBS (C8.pack s)

hashBS :: ByteString -> ByteString
hashBS bs =
  let hashed = keccak256 $ B.toStrict bs
      builder = Bldr.byteStringHex hashed
  in Bldr.toLazyByteString builder


{-
newtype Msg = Msg { getMsg :: ByteString }
signMsg :: SecKey -> Msg -> Sig

-- Import 32-byte ByteString as SecKey.
secKey :: ByteString -> Maybe SecKey

newtype Sig = Sig {getSig :: ByteString }

getMsg :: Msg -> ByteString
-}

-- Returns the ECDSA signature of a message hash.
-- the 2nd param is a String instead of ByteString just to make it easier in the repl
ecSign :: ByteString -> String -> Int -> ByteString
ecSign msgHash privateKeyStr chainId =
  let privateKey =
        case decodeHex (Data.Text.pack (drop 2 privateKeyStr)) of
          Nothing -> error "could not decode the string in a ByteString of hex values"
          Just pk -> pk
  -- let privateKey =
  --       B.toStrict $ C8.pack (drop 2 privateKeyStr)

      hash' = B.toStrict $ B.drop 2 msgHash -- remove the 0x prefix

  -- in case SC.secKey privateKey of
      str = "length of privateKey: " ++ (show (StrictBS.length privateKey))
      temp = SC.secKey privateKey
  in case (trace str temp) of

      Nothing -> error "error creating secret key"
      Just sk ->
        case SC.msg hash' of
          Nothing -> error "error creating Msg"
          Just m ->
            let sig = SC.signMsg sk m
            in Data.Serialize.encodeLazy sig

    -- sig = secp256k1.sign(msgHash, privateKey);
    -- var recovery = sig.recovery;
    -- var ret = {
    --     r: sig.signature.slice(0, 32),
    --     s: sig.signature.slice(32, 64),
    --     v: chainId ? recovery + (chainId * 2 + 35) : recovery + 27,
    -- };
    -- return ret;


printBS :: ByteString -> String -> IO ()
printBS bs contextStr = do
  putStrLn $ contextStr ++ ": "
  B.putStr bs
  putStrLn "\n"

withPrefix :: ByteString -> ByteString
withPrefix s = "0x" <> s

hexStr :: Int -> String
hexStr n = (showHex n) ""

padBefore :: String -> Char -> Int -> String
padBefore str ch finalLen =
  let padLen = finalLen - length str
  in replicate padLen ch ++ str
