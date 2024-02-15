/* Rejection Sampling algorithm for covert information leakage. */
#include <openssl/ec.h>
#include <openssl/evp.h>

/* 
 * Encrypts m-bits of message msg using rejection sampling with a public key Y
 * \return randomness k to be used in higher level protocol 
 */
BIGNUM* rs_encrypt(int m, const char* msg, EC_POINT* Y, EC_GROUP* group);

/* 
 * Decrypts m-bits from protocol P output r with a private scalar y 
 * \return char array of plaintext bytes (it does not have to be a string)
*/
char* rs_decrypt(int m, EC_POINT* r, BIGNUM* y, EC_GROUP* group);
