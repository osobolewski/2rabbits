/* Rejection Sampling algorithm for covert information leakage. */
#pragma once
#include <openssl/ec.h>
#include <openssl/evp.h>

/* 
 * Encrypts m-bits of message msg using rejection sampling with a public key Y
 * \return randomness k to be used in higher level protocol 
 */
BIGNUM* rs_encrypt(int m, int msg, EC_POINT* Y, EC_GROUP* group);

/* Decrypts a bit from protocol P output r with a private scalar y */
int rs_decrypt(EC_POINT* r, BIGNUM* y);

