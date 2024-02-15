/* Rejection Sampling algorithm for covert information leakage. */
#include <openssl/ec.h>
#include <openssl/evp.h>

/* 
 * Encrypts m-bits of message msg using rejection sampling with a public key Y
 * \return randomness k to be used in higher level protocol 
 */
BIGNUM* rs_encrypt(int m, const char* msg, EC_POINT* Y, EC_GROUP* group);

/* Decrypts a bit from protocol P output r with a private scalar y */
char* rs_decrypt(int m, EC_POINT* r, BIGNUM* y, EC_GROUP* group);

int compare_n_lsb(const char* a, size_t len_a, const char* b, size_t len_b, int n);

char* hash(char** inputs, int inputs_len, int* digest_len);

char* chrs2hex(const char* bytes, size_t len);