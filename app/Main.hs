{-# LANGUAGE OverloadedStrings#-}

module Main where

import Crypto.Hash.Keccak (keccak256)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Builder as Bldr
import Data.ByteString.Lazy.Char8 (pack)
import Text.Hex (encodeHex)
import Text.Show
import Numeric
import GHC.RTS.Flags (MiscFlags(tickInterval))

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

zeroAddr :: String
zeroAddr = "0x0000000000000000000000000000000000000000"

main :: IO ()
main = do
  putStrLn "Step by step: "
  let msigAddr = "AAAAA"
  let domainSep = domainData msigAddr
  printBS domainSep "domain separator (hash) "

  let nonce = 1234;
  let destinationAddr = "0xBBBB";
  let value = 10;
  let dataStr = "0xCCCC";
  let executor = "0xDDDD";
  let gasLimit = 1;

  let transInput = txInput nonce destinationAddr value dataStr executor gasLimit
  printBS transInput "txInput hash"

  let theInput = input domainSep transInput
  printBS theInput "input (hash)"

  putStrLn "One single step: "
  let result = packData msigAddr nonce destinationAddr value dataStr executor gasLimit
  printBS result "input (hash)"

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
        ++ padBefore (take 2 multiSigAddr) '0' 64
        ++ take 2 (drop 2 salt)
  in withPrefix $ hash dd

txInput :: Int -> String -> Int -> String -> String -> Int -> ByteString
txInput nonce destinationAddr value dataStr executor gasLimit =
  let ti =
        let hashedData = hash dataStr
            dataSlice = B.take 2 hashedData
        in txTypeHash
          ++ padBefore (take 2 (drop 2 destinationAddr)) '0' 64
          ++ padBefore (hexStr value) '0' 64
          ++ show dataSlice
          ++ padBefore (hexStr nonce) '0' 64
          ++ padBefore (take 2 (drop 2 executor)) '0' 64
          ++ padBefore (hexStr gasLimit) '0' 64
  in withPrefix $ hash ti

input :: ByteString -> ByteString -> ByteString
input domainSeparator txInputHash =
  let theInput =
        Bldr.lazyByteString "19"
        <> "01"
        <> Bldr.lazyByteString (B.take 2 domainSeparator)
        <> Bldr.lazyByteString (B.take 2 txInputHash)
  in withPrefix $ hashBS $ Bldr.toLazyByteString theInput

hash :: String -> ByteString
hash s = hashBS (pack s)

hashBS :: ByteString -> ByteString
hashBS bs =
  let hashed = keccak256 $ B.toStrict bs
      builder = Bldr.byteStringHex hashed
  in Bldr.toLazyByteString builder

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
