#include "utils.h"
#include "logger/logger.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>


char* chr_2_hex(const char* bytes, size_t len) {
    const char hex[] = "0123456789ABCDEF";

    static char result[255];
    result[0] = '\0';

    // very lazy
    for (int i = 0; i < (int)len && 1 < 255; ++i) {
        char byte[3];
        byte[0] = hex[(unsigned char)bytes[i] >> 4]; // upper nibble
        byte[1] = hex[(unsigned char)bytes[i] & (0b1111)]; // lower nibble
        byte[2] = '\0';
        strcat(result, byte);
    }
    result[2*len] = '\0';

    return result;
}

/* \return 0 if n least significant bits of a and b are the same and 1 otherwise*/
int compare_n_lsb(const char* a, size_t len_a, const char* b, size_t len_b, int n) {
    int bytes_to_check = n/8 + 1;

    // for first byte check only remainder bits
    int remainder = n % 8;

    unsigned char first_byte_a = a[len_a - bytes_to_check];
    unsigned char first_byte_b = b[len_b - bytes_to_check];

    int mask = (1 << remainder) - 1;

    int comparison = (first_byte_a & mask) ^ (first_byte_b & mask);

    for (int i = 1; i < bytes_to_check; ++i) {
        int index_a = len_a - bytes_to_check + i;
        int index_b = len_b - bytes_to_check + i;

        int c = a[index_a] ^ b[index_b];
        comparison = comparison | c;
    }

    return comparison != 0;
}

char* hash(const char** inputs, int inputs_arr_len, const int* inputs_lens, int* digest_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

    if (mdctx == NULL) {
        logger(LOG_ERR, "Hashing context creation failed", "RS");
        return NULL;
    }

	int ok;
	const EVP_MD* algo = EVP_sha3_256();

    ok = EVP_DigestInit_ex(mdctx, algo, NULL);
    if (ok <= 0) {
        EVP_MD_CTX_destroy(mdctx);
        logger(LOG_ERR, "Digest initialization failed", "RS");
        return NULL;
    }

    for (int i = 0; i < inputs_arr_len; ++i) {
        int l = inputs_lens[i];
        ok = EVP_DigestUpdate(mdctx, inputs[i], l);
        if (ok <= 0) {
            EVP_MD_CTX_destroy(mdctx);
            logger(LOG_ERR, "Digest update failed", "RS");
            return NULL;
        }
    }

    *digest_len = EVP_MD_size(algo);
    char* digest = (char*)malloc(*digest_len * sizeof(char));

    ok = EVP_DigestFinal_ex(mdctx, (unsigned char*)digest, (unsigned int*)digest_len);
    if (ok <= 0) {
        free(digest);
        EVP_MD_CTX_destroy(mdctx);
        logger(LOG_ERR, "Hash computation failed", "RS");
        return NULL;
    }
    EVP_MD_CTX_destroy(mdctx);

    return digest;
}

void parse_key(EVP_PKEY* pkey) {
    size_t pkey_len = 0;
    char* pkey_buffer;
    
    // get length of public key (it will be written to pkey_len)
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pkey_len);
    pkey_buffer = (char*)malloc(pkey_len * sizeof(char));

    // get raw public key into the buffer
    EVP_PKEY_get_raw_public_key(pkey, pkey_buffer, &pkey_len);

    // gey key params
    OSSL_PARAM* params;
    EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params);

    int* group_name = (int*)OSSL_PARAM_locate(params, "group")->data;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(*group_name);
    BIGNUM* p = (BIGNUM*)OSSL_PARAM_locate(params, "p")->data;

    EC_POINT* Y;
    EC_POINT_oct2point(group, Y, pkey_buffer, pkey_len, NULL);

    free(pkey_buffer);
    OSSL_PARAM_free(params);
    EC_GROUP_free(group);
    EC_POINT_free(Y);
}

char* BN_print_str(BIGNUM* a) {
    char* buffer;
    static char result[100]; 
    size_t buffer_size;

    FILE* file_stream = open_memstream(&buffer, &buffer_size);
    BN_print_fp(file_stream, a);
    fclose(file_stream); 

    strcpy(result, buffer);

    free(buffer);

    // return a static string
    return result;
}

int chr_cmp(const char* c1, const char* c2, int len) {
    while(len && (*c1 == *c2)) {
        c1++;
        c2++;
        len--;
    }
    return *(const unsigned char*)c1 - *(const unsigned char*)c2;
}

void swap(int* arr, int i, int j) {
    int tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
}

void chr_swap(char** arr, int i, int j) {
    char* tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
}

void chr_sort(char** arr,  int arr_len, int cmp_len, int* indices) {
    // if pointer indices is provided, returns an array of 
    // original indices in the sorted array
    // indices is expected to be allocated
    if (indices) {
        for (int i = 0; i < arr_len; ++i) {
            indices[i] = i;
        }
    }

    // bubble sort, the arrays are expected 
    // to be length 2 anyway
    for(int i = 0; i < arr_len - 1; i++){
        for(int j = 0; j < arr_len - i - 1; j++){
            if(chr_cmp(arr[i], arr[j+1], cmp_len) > 0){
                if (indices) {
                    swap(indices, i, j+1);
                }
                chr_swap(arr, i, j+1);
            }
        }
    }
}
