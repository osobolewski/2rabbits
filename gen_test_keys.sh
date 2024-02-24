#!/bin/bash

mkdir keys -p &&
openssl ecparam -name secp256k1 -genkey -noout -out keys/ec-secp256k1-priv-key_enc.pem &&
openssl ec -in keys/ec-secp256k1-priv-key_enc.pem -pubout > keys/ec-secp256k1-pub-key_enc.pem &&
openssl ecparam -name secp256k1 -genkey -noout -out keys/ec-secp256k1-priv-key.pem &&
openssl ec -in keys/ec-secp256k1-priv-key.pem -pubout > keys/ec-secp256k1-pub-key.pem &&
echo Keys generated and written to ./keys