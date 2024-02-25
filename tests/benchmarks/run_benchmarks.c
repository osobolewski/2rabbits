#include "../../src/algorithms/advanced_sampling.h"
#include "../../src/algorithms/rejection_sampling.h"
#include "../../src/anamorphic_ecdsa/ecdsa.h"
#include "../../src/logger/logger.h"
#include "../../src/utils.h"
#include <assert.h>
#include <string.h>
#include <time.h>


int main(int argc, char* argv[]) {  
    logger(LOG_INFO, "Generating keys...", "BNCH");
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

    int m = 12;
    int C = 5;

    const char dkey[] = "dual key";

    BIGNUM*** lut = lut_new(m, C);

    clock_t now = clock();
    as_fill(lut, m, C, dkey, strlen(dkey), Y, group_2);
    printf("as_fill time: %.3f ms\n", (double)(clock() - now) / CLOCKS_PER_SEC);

    now = clock();
    for (int i = 0; i < 1000; i++) {
        char str[12];
        sprintf(str, "Message: %d", i);
        int sig_len;
        as_insert(lut, m, C, 0, dkey, strlen(dkey), X, group_1);
        char* sig = ecdsa_as_sign(signing_key, str, &sig_len, encryption_key, "AA", 2, dkey, strlen(dkey), m, C, lut);
        free(sig);
    }
    printf("1000 as_sign time: %.3f ms\n", (double)(clock() - now) / CLOCKS_PER_SEC);

    now = clock();
    for (int i = 0; i < 1000; i++) {
        char str[12];
        sprintf(str, "Message: %d", i);
        int sig_len;
        char* sig = ecdsa_rs_sign(signing_key, str, &sig_len, encryption_key, "AA", 2, m);
        free(sig);
    }
    printf("1000 rs_sign time: %.3f ms\n", (double)(clock() - now) / CLOCKS_PER_SEC);

    now = clock();
    for (int i = 0; i < 1000; i++) {
        char str[12];
        sprintf(str, "Message: %d", i);
        int sig_len;
        char* sig = ecdsa_sign(signing_key, str, &sig_len);
        free(sig);
    }
    printf("1000 ecdsa_sign time: %.3f ms\n", (double)(clock() - now) / CLOCKS_PER_SEC);

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