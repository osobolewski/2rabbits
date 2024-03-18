/* Advanced sampling algorithm for covert information leakage. */
#include <openssl/ec.h>
#include <openssl/evp.h>

/*
 * Advanced sampling encryption
 */
BIGNUM* as_encrypt(BIGNUM*** lut, int m, int C, const char* msg, int msg_len, 
                    const char* delta, int delta_len, const char* dkey, int dkey_len, 
                    const EC_POINT* Y, EC_GROUP* group);

/*
 * Advanced sampling decryption
 */
char* as_decrypt(int m, const char* delta, int delta_len, const char* dkey, int dkey_len, EC_POINT*r, BIGNUM* y, EC_GROUP* group);

/*
 * Advanced sampling insert
 */
long long as_insert(BIGNUM*** lut, int m, int C, int C_hard_bound, const char* dkey, int dkey_len, EC_POINT* Y, EC_GROUP* group);

/*
 * Advanced sampling fill lookup table
 */
void as_fill(BIGNUM*** lut, int m, int C, const char* dkey, int dkey_len, EC_POINT* Y, EC_GROUP* group);

// ---- Lookup table manipulation functions ----

int lut_free_slots_row(BIGNUM** row, int C);

int lut_push(BIGNUM*** lut, int C, size_t row, BIGNUM* num);

BIGNUM*** lut_new(int m, int C);

void lut_free(BIGNUM*** lut, int m, int C);

BIGNUM* lut_pop(BIGNUM*** lut, int C, size_t row);

int lut_serialize(BIGNUM*** lut, int m, int C, char* out_arr, int* out_arr_len);

int lut_deserialize(BIGNUM*** lut, int* m, int* C, const char* in_arr, int in_arr_len);
