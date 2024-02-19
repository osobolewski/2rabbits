/* Advanced sampling algorithm for covert information leakage. */
#include <openssl/ec.h>
#include <openssl/evp.h>

/*
 * Advanced sampling encryption
 */
BIGNUM* as_encrypt(char** lut, int m, const char* msg, EC_POINT* Y, EC_GROUP* group);

/*
 * Advanced sampling decryption
 */
const char* as_decrypt(char** lut, int m, EC_POINT* r, BIGNUM* y, EC_GROUP* group);

