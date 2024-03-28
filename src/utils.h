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

/*
 * Converts a hex string to a char array; 
 * \return a pointer to a dynamically allocated buffer with the char array, len written to out_len
 */
char* hex_2_chr(const char* hex, size_t* out_len);

/*
 * Prints bignum to a string (static buffer)
 * \return string bignum representation  
*/
char* BN_print_str(BIGNUM* a);

/*
 * Sorts an array arr of bignums, in ascending order
 * indices contains the list of indices from original array
*/
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

/*
 * Calculate byte length from bit length
 * \return length in bytes
*/
int bit_2_byte_len(int bit_len);

/*
 * Recover n least significant bytes from array arr
 * \return byte array containing n LSBs of arr 
*/
char* recover_n_lsbs_str(const char* arr, int len, int n);

/*
 * Recover n least significant bytes from array arr
 * and cast it as a size_t number
 * \return size_t number comprised of n LSBs of arr
*/
size_t recover_n_lsbs_size_t(const char* arr, int len, int n);

/*
 * Serialize point to a byte array buffer
 * \return positive value on success
*/
int point_2_buffer(char* buffer, size_t len, EC_POINT* point, EC_GROUP* group, BN_CTX* ctx);

/*
 * Calculate length for a encoding buffer for point
 * \return required length of encoding buffer
*/
size_t encoded_point_len(EC_POINT* point, EC_GROUP* group, BN_CTX* ctx);

/*
 * Encode a point. Length of the encoding buffer is written to enc_len
 * \return a dynamically allocated buffer for the encoding
*/
char* encode_point(EC_POINT* point, size_t* enc_len, EC_GROUP* group, BN_CTX* ctx);

/*
 * Recover the n-th least significant bit of arr
 * \return nth LSBs casted as an int
*/
int recover_nth_lsbit(const char* arr, int len, int n);

/*
 * Swaps endianesses of a byte array arr
*/
void swap_endian(char* arr, int len);

/*
 * Parse EVP_PKEY to recover group, public_key and private_key
 * \return positive value on success
*/
int parse_evp_pkey(const EVP_PKEY* pkey, EC_GROUP** group, EC_POINT** public_key, BIGNUM** private_key);

/*
 * Parse a PEM key to recover EVP_PKEY from it. 
 * To parse a private key, set the flag priv to 1
 * \return positive value on success
*/
int parse_pem_key(const char* path, EVP_PKEY** pkey, int priv);

/*
 * Save byte array in path
 * \return positive value on success
*/
int save_to_file(const char* in, unsigned int in_len, const char* path);

/*
 * Read a byte array from path
 * \return dynamically allocated buffer for the read bytes
*/
char* read_from_file(const char* path, unsigned int* out_len);

/*
 * Pack an array of binary integers into a long
 * \return packed long
*/
long pack_int(const unsigned int* arr, int len);

/*
 * Unpack a long into an array of binary integers
*/
void unpack_int(long packed, unsigned int* arr, int len);