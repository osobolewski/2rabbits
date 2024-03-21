# 2rabbits
A Proof of Concept implementation of the Advanced Rejection Sampling Algorithm for covert information leakage.

# Building

Run the `install.sh` script;

Next, build with cmake. 
If you don't know how, you can use this (requires `gcc/clang` and `make`):
```bash
cmake -B build && cd build && make
```

or e.g. this for debug build (requires `gcc` and `Ninja`):

```bash
cmake -DCMAKE_BUILD_TYPE:STRING=Debug -DCMAKE_C_COMPILER:FILEPATH=/usr/bin/gcc -B ./build -G Ninja
cmake --build ./build --config Debug --target all --
```

# Watermarking tool

To use the watermarking tool, first build the binaries. Then, you can use:

```bash
./bin/watermarking help
```

to show options. In general, usage looks like this:

## Generating a lookup table

To generate a lookup table run the `watermarking` binary with `g` option:

```bash
watermarking [-v] g[enerate_lut] '/save/path' '/path/to/enc_key.pub' (m) [C] 'dual_key'
```

### Parameters:
1. `[-v]`: [OPTIONAL] verbose mode. `[-vv]` is debug mode
2. `'/save/path'`: Save location of the generated lookup table.
3. `'/path/to/enc_key.pub`': Path to PEM-encoded ECDSA public key used to encrypt the anamorphic message
4. `(m)`: Number of bits to be encrypted (width of the anamorphic channel). 0 < m < 17
5. `[C]`: [OPTIONAL] Number of records in a row of the lookup table. Default is 5
6. `'dual_key'`: String used as a dual key to encrypt the anamorphic message.

### Example usage: 

```bash
./bin/watermarking -v generate_lut lut.out ./keys/ec-secp256k1-pub-key_enc.pem 8 5 'Secret dual key'
```

The serialized lookup table is required for anamorphic signing.

## Signing and encrypting

To sign a message and encrypt a watermark, use the `watermarking` binary with option `s`:

```bash
watermarking [-v] s[ign] '/sign.bin' '/path/to/lut' '/path/to/sign_key.priv' '/path/to/enc_key.pub' '/path/to/sign_msg.txt' 'watermark' 'dual_key' ['delta']
```

### Parameters:
1. `[-v]`: [OPTIONAL] verbose mode. `[-vv]` is debug mode
2. `'/sign.bin'`: Save location of the generated signature
1. `'/path/to/lut'`: Path to a lookup table generated by the command `g`
2. `'/path/to/sign_key.priv'`: Path to PEM-encoded ECDSA signing key used to sign a message
3. `'/path/to/enc_key.pub'`: Path to PEM-encoded ECDSA public key used to encrypt the `'watermark'`
4. `'/path/to/sign_msg.txt'`: Path to file containing message to be signed with private key (can be binary)
5. `'watermark'`: Message to be encrypted inside of the signature
6. `'dual_key'`: String used as a dual key to encrypt the 'watermark'
7. `['delta']`: [OPTIONAL] Unique public string to be used for encryption. Default is the timestamp of the signature.

### Example usage

```bash
./bin/watermarking s sign.bin lut.out ./keys/ec-secp256k1-priv-key.pem ./keys/ec-secp256k1-pub-key_enc.pem msg.test 'bb' 'Secret dual key' 'Some unique public string 1'
```

The signature will verify with 'normal' openssl verification as well. You can check it with command like this:

```bash
$ openssl dgst -sha3-256 -verify ./keys/ec-secp256k1-pub-key.pem -signature sign.bin msg.test

Verified OK
```

## Verifying and decrypting

To verify the signature and decrypt the anamorphic message, run the `watermarking` binary with option `d`:

```bash
watermarking [-v] d[ecrypt] '/path/to/sign_key.pub' '/path/to/enc_key.priv' '/path/to/sig.bin' '/path/to/sign_msg.txt' (m) 'dual_key' 'delta'
```

### Parameters:
1. `[-v]`: [OPTIONAL] verbose mode. `[-vv]` is debug mode
2. `'/path/to/sign_key.pub'`: Path to PEM-encoded ECDSA signing public key used to verify the `'message_to_verify'`
3. `'/path/to/enc_key.priv'`: Path to PEM-encoded ECDSA private key used to decrypt the anamorphic message
4. `'/path/to/sig.bin'`: Path to file containing the signature to verify and decrypt from
5. `'/path/to/sign_msg.txt'`: Path to file containing message to be verified with the public key\
6. `(m)`: Number of bits to be decrypted (width of the anamorphic channel). 0 < m < 17
7. `'dual_key'`: String used as a dual key to decrypt the anamorphic message
8. `'delta'`: Public string to be used for decryption. By default its the timestamp of the signature

### Example usage

```bash
./bin/watermarking d ./keys/ec-secp256k1-pub-key.pem ./keys/ec-secp256k1-priv-key_enc.pem sign.bin msg.test 8 'Secret dual key' 'Some unique public string 1'
```
The recovered message should be the same as provided in the signing step. If its not, check if you're using the same `dual_key`, `delta`, `m`, lookup table, keys and of course sign message!

# Benchmarks

To run benchmarks and visualize, first build and cd into the benchmarks folder:

```bash
cd benchmarks
```

Then, run all of the benchmarks to generate output csv files:

```bash
./benchmark -ecdsa && ./benchmark -rs && ./benchmark -as 0 5 && ./benchmark -as 8 0
```

To visualize benchmark results, run the python script (requires `matplotlib`):
```bash
python visualize_benchmarks.py
```

# Tests

To run tests, first build the binaries and cd into the bin folder

```bash
cd ./bin
```

Then run the test binaries with no arguments (they can take some time):

```bash
./test* 
```

Make sure that the keys are generated in the `{root-git}/keys` directory!