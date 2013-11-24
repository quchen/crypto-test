import Crypto.Random
import Codec.Crypto.RSA as RSA
import Codec.Crypto.AES as AES
import Text.Printf
import Data.Binary
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import Data.List



-- | Show a 'BSL.ByteString' in byte block format, i.e. @9B C4 15 0D AC EB 1E@
showHex :: BSL.ByteString -> String
showHex = intercalate " " . BSL.foldr go []
      where go x xs = printf "%02X" x : xs



main = do
      g <- (newGenIO :: IO SystemRandom)


      let msg = "Hello, World!"
      printf "\ESC[32mMessage:\ESC[0m %s\n" msg

      putStr "\n"

      (public, private, g') <- rsa g msg

      putStr "\n"

      (key, iv, g'') <- aes g' msg

      putStr "\n"

      hybrid g'' msg key iv private public

      return ()



aes :: (CryptoRandomGen gen)
    => gen
    -> String
    -> IO (BS.ByteString, BS.ByteString, gen)
aes g msg = do

      putStrLn "\ESC[32mAES:\ESC[0m"
      putStr "\n"
      putStrLn "1. Generate key and initialization vector (IV) randomly"
      putStrLn "2. Encrypt message"
      putStrLn "3. Decrypt message"

      let unsafeFromRight (Right x) = x
          unsafeFromRight _         = error "unsafeFromRight"

          (key, g') = unsafeFromRight (genBytes 32 g)
          (iv, g'') = unsafeFromRight (genBytes 16 g')

          mode = CTR
          encrypted = AES.crypt mode key iv Encrypt (encode msg)
          decrypted :: String
          decrypted = decode (AES.crypt mode key iv Decrypt encrypted)

      printf "\ESC[31mIV:\ESC[0m %s\n\
             \\ESC[31mKey:\ESC[0m %s\n\
             \\ESC[31mEncrypted:\ESC[0m %s\n\
             \\ESC[31mDecrypted:\ESC[0m %s\n"
             (showHex (BSL.fromStrict iv))
             (showHex (BSL.fromStrict key))
             (showHex encrypted)
             (decrypted)

      return (key, iv, g'')



rsa :: CryptoRandomGen gen
    => gen
    -> String
    -> IO (PublicKey, PrivateKey, gen)
rsa g msg = do

      putStrLn "\ESC[32mRSA:\ESC[0m"
      putStr "\n"
      putStrLn "1. Generate RSA key pair"
      putStrLn "2. Encrypt/decrypt"
      putStrLn "2.1 Encrypt message with public key"
      putStrLn "2.2 Decrypt message with public key"
      putStrLn "3. Sign/verify"
      putStrLn "3.1 Sign message with private key"
      putStrLn "3.2 Verify message with public key"
      putStr "\n"

      let (public, private, g') = generateKeyPair g 1024

      printf "\ESC[31mPublic:\ESC[0m %s\n\
             \\ESC[31mPrivate:\ESC[0m %s\n"
             (show public)
             (show private)

      let (encrypted, _g'') = RSA.encrypt g public (encode msg)
          decrypted :: String
          decrypted         = decode (RSA.decrypt private encrypted)
          signature         = sign private (encode msg)
          verified          = verify public (encode msg) signature
          verifiedWrong     = verify public (encode (msg ++ "!")) signature

      printf "\ESC[31mEncrypted:\ESC[0m %s\n\
             \\ESC[31mDecrypted:\ESC[0m %s\n\
             \\ESC[31mSigned:\ESC[0m %s\n\
             \\ESC[31mSignature:\ESC[0m %s\n\
             \\ESC[31mSignature of modified message:\ESC[0m %s\n"
             (showHex encrypted)
             (decrypted)
             (showHex signature)
             (if verified      then "OK" else "WRONG")
             (if verifiedWrong then "OK" else "WRONG")

      return (public, private, g')



hybrid :: (CryptoRandomGen gen)
       => gen
       -> String
       -> BS.ByteString
       -> BS.ByteString
       -> PrivateKey
       -> PublicKey
       -> IO ()
hybrid g msg key iv private public = do

      putStrLn "\ESC[32mHybrid:\ESC[0m"
      putStr "\n"
      -- Keys are provided to the function as parameters from before, so they
      -- don't actually have to be generated here.
      putStrLn "1. Generate AES key and initialization vector (IV) randomly"
      putStrLn "3. Encrypt message using AES"
      putStrLn "2. Generate RSA key pair"
      putStrLn "4. Encrypt AES key+IV using RSA public key"
      putStrLn "5. Send AES-encrypted message and RSA-encrypted AES key"
      putStrLn "6. Decrypt AES key+IV using RSA private key"
      putStrLn "7. Decrypt message using AES key+IV"
      putStr "\n"

      let encrypted = AES.crypt mode key iv Encrypt (encode msg)
          mode = CTR
          (encryptedKey, g') = RSA.encrypt g public (encode (key, iv))
          (decryptedKey, decryptedIV) = decode (RSA.decrypt private encryptedKey)
                                      :: (BS.ByteString, BS.ByteString)
          decrypted :: String
          decrypted = decode (AES.crypt mode decryptedKey iv Decrypt encrypted)

      printf "\ESC[31mIV (AES):\ESC[0m %s\n\
             \\ESC[31mKey (AES):\ESC[0m %s\n\
             \\ESC[31mEncrypted message (AES):\ESC[0m %s\n\
             \\ESC[31mEncrypted AES key+IV (RSA):\ESC[0m %s\n\
             \\ESC[31mDecrypted AES IV (RSA):\ESC[0m %s\n\
             \\ESC[31mDecrypted AES key (RSA):\ESC[0m %s\n\
             \\ESC[31mDecrypted message (AES):\ESC[0m %s\n"
             (showHex (BSL.fromStrict iv))
             (showHex (BSL.fromStrict key))
             (showHex encrypted)
             (showHex encryptedKey)
             (showHex (BSL.fromStrict decryptedIV))
             (showHex (BSL.fromStrict decryptedKey))
             (decrypted)