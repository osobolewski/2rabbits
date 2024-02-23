#include <openssl/evp.h>
#include <openssl/ec.h>

/*
 * Compares n least significant bits of char arrays a and b
 * \return 0 if the arrays are the same and 1 otherwise
 */
int compare_n_lsb(const char* a, size_t len_a, const char* b, size_t len_b, int n);

/*
 * Hash and array of input char arrays (whose lengths are provided in 
 * inputs_lens array) using some hash function.
 * Number of bytes outputted is written to digest_len
 * \return digest (array of chars)
 */
char* hash(const char** inputs, int inputs_arr_len, const int* inputs_lens, int* digest_len);

/*
 * Converts a char array to a hex string; 
 * \return a pointer to a static buffer with the hexstring
 */
char* chr_2_hex(const char* bytes, size_t len);

char* BN_print_str(BIGNUM* a);

void BN_sort(BIGNUM** arr, int* indices, int len);

/*
 * Compares two char arrays of length len
 * \return res < 0 if c1 < c2, res = 0 if c1 == c2, res > 0 if c1 > c2
*/
int chr_cmp(const char* c1, const char* c2, int len);

/*
 * Sorts an array (of length arr_len) of char arrays (of length cmp_len)
 * if the indices argument is provided, the indices of the original array 
 * in terms of the sorted array are written there
 * indices must point to preallocated memory.
*/
void chr_sort(char** arr,  int arr_len, int cmp_len, int* indices);

int bit_2_byte_len(int bit_len);

char* recover_n_lsbs_str(const char* arr, int len, int n);

size_t recover_n_lsbs_size_t(const char* arr, int len, int n);

int point_2_buffer(char* buffer, size_t len, EC_POINT* point, EC_GROUP* group, BN_CTX* ctx);

size_t encoded_point_len(EC_POINT* point, EC_GROUP* group, BN_CTX* ctx);

char* encode_point(EC_POINT* point, size_t* enc_len, EC_GROUP* group, BN_CTX* ctx);

int recover_nth_lsbit(const char* arr, int len, int n);

void swap_endian(char* arr, int len);

int parse_evp_pkey(const EVP_PKEY* pkey, EC_GROUP** group, EC_POINT** public_key, BIGNUM** private_key);

int parse_pem_key(const char* path, EVP_PKEY** pkey, int priv);