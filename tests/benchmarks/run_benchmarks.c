#include "../../src/algorithms/advanced_sampling.h"
#include "../../src/algorithms/rejection_sampling.h"
#include "../../src/anamorphic_ecdsa/ecdsa.h"
#include "../../src/logger/logger.h"
#include "../../src/utils.h"
#include <assert.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>

char* get_random_bits(int n) {
    int bytes = bit_2_byte_len(n);
    char* buf = (char*)malloc(bytes*sizeof(char));
    RAND_bytes((unsigned char*)buf, bytes);

    return buf;
}

int main(int argc, char* argv[]) {  
    set_verbose(LOG_INFO);
    logger(LOG_INFO, "Generating keys...", "BNCH");
    char print_buf[200];
    EVP_PKEY* signing_key = EVP_PKEY_new();
    EC_POINT* X = NULL;
    BIGNUM* x = NULL;
    EC_GROUP* group_1 = NULL;

    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1);
    EVP_PKEY_keygen(ctx, &signing_key);

    EVP_PKEY_CTX_free(ctx);
    parse_evp_pkey(signing_key, &group_1, &X, &x);

    EVP_PKEY* encryption_key = EVP_PKEY_new();
    EC_POINT* Y = NULL;
    BIGNUM* y = NULL;
    EC_GROUP* group_2 = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1);
    EVP_PKEY_keygen(ctx, &encryption_key);

    EVP_PKEY_CTX_free(ctx);
    parse_evp_pkey(encryption_key, &group_2, &Y, &y);

    logger(LOG_INFO, "Keys generated", "BNCH");

    int m = 8;
    int C = 5;
    int repetitions = 1000;

    const char dkey[] = "dual key";

    BIGNUM*** lut = lut_new(m, C);

    clock_t now = clock();
    as_fill(lut, m, C, dkey, strlen(dkey), Y, group_2);
    sprintf(print_buf, "as_fill time: %.3f s", (double)(clock() - now) / CLOCKS_PER_SEC);
    logger(LOG_INFO, print_buf, "BNCH");

    now = clock();
    for (int i = 0; i < repetitions; i++) {
        char str[12];
        char* enc;
        sprintf(str, "Message: %d", i);

        enc = get_random_bits(m);

        int sig_len;
        // insert
        as_insert(lut, m, C, 0, dkey, strlen(dkey), Y, group_2);
        // then sign
        char* sig = ecdsa_as_sign(signing_key, str, &sig_len, encryption_key, enc, strlen(enc), dkey, strlen(dkey), m, C, lut);
        free(sig);
        free(enc);
    }
    sprintf(print_buf, "%d as_sign time: %.3f s", repetitions, (double)(clock() - now) / CLOCKS_PER_SEC);
    logger(LOG_INFO, print_buf, "BNCH");

    now = clock();
    for (int i = 0; i < repetitions; i++) {
        char str[12];
        char* enc;

        enc = get_random_bits(m);

        sprintf(str, "Message: %d", i);
        int sig_len;
        char* sig = ecdsa_rs_sign(signing_key, str, &sig_len, encryption_key, "AA", 2, m);
        free(sig);
        free(enc);
    }
    sprintf(print_buf, "%d rs_sign time: %.3f s", repetitions, (double)(clock() - now) / CLOCKS_PER_SEC);
    logger(LOG_INFO, print_buf, "BNCH");

    now = clock();
    for (int i = 0; i < repetitions; i++) {
        char str[12];
        sprintf(str, "Message: %d", i);
        int sig_len;
        char* sig = ecdsa_sign(signing_key, str, &sig_len);
        free(sig);
    }
    sprintf(print_buf, "%d pure ecdsa_sign time: %.3f s", repetitions, (double)(clock() - now) / CLOCKS_PER_SEC);
    logger(LOG_INFO, print_buf, "BNCH");

    lut_free(lut, m, C);
    EVP_PKEY_free(signing_key);
    EVP_PKEY_free(encryption_key);
    EC_POINT_free(X);
    BN_free(x);
    EC_GROUP_free(group_1);
    EC_POINT_free(Y);
    BN_free(y);
    EC_GROUP_free(group_2);
}