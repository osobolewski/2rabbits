#include <openssl/evp.h>

/*
 * Compares n least significant bits of char arrays a and b
 * \return 0 if the arrays are the same and 1 otherwise
 */
int compare_n_lsb(const char* a, size_t len_a, const char* b, size_t len_b, int n);

/*
 * Hash and array of input strings using some hash function.
 * Number of bytes outputted is written to digest_len
 * \return digest (array of chars)
 */
char* hash(char** inputs, int inputs_len, int* digest_len);

/*
 * Converts a char array to a hex string; 
 * \return a pointer to a static buffer with the hexstring
 */
char* chrs2hex(const char* bytes, size_t len);