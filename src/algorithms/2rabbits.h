/* 2rabbits algorithm for covert information leakage. */
#include <openssl/ec.h>
#include <openssl/evp.h>

/* 
 * Encrypts a bit b using 2rabbits with a public key Y
 * \return randomness k to be used in higher level protocol 
 */
BIGNUM* two_rabbits_encrypt(int b, EC_POINT* Y, EC_GROUP* group);

/* 
 * Decrypts a bit b from protocol P output r with a private scalar y 
 * \return plaintext bit b
*/
int two_rabbits_decrypt(EC_POINT* r, BIGNUM* y, EC_GROUP* group);
