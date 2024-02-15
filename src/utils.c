#include "utils.h"
#include "logger/logger.h"
#include <string.h>


char* chrs2hex(const char* bytes, size_t len) {
    const char hex[] = "0123456789ABCDEF";

    static char result[255];
    result[0] = '\0';

    // very lazy
    for (int i = 0; i < len && 1 < 255; ++i) {
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

char* hash(char** inputs, int inputs_len, int* digest_len) {
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

    for (int i = 0; i < inputs_len; ++i) {
        int l = strlen(inputs[i]);
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