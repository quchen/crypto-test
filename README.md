Crypto test
===========

[![Build Status](https://travis-ci.org/quchen/crypto-test.png?branch=master)](https://travis-ci.org/quchen/crypto-test)

This is a short example program demonstrating AES, RSA and AES+RSA hybrid encryption in Haskell. The Travis build linked above also shows the program output in the `after_success` section.

Installation: `cabal install aes rsa binary && ghc -O ./rsa-aes.hs`