#include "rejection_sampling.h"
#include <openssl/rand.h>

BIGNUM* rs_encrypt(int m, int msg, EC_POINT* Y, EC_GROUP* group) {
    BN_CTX *ctx;

    if (Y == NULL || group == NULL || m <= 0 || m >= (1 << 16)) {
        return NULL;
    }

    EC_POINT
}

int rs_decrypt(EC_POINT* r, BIGNUM y) {
    BIGNUM y = EC_KEY_get0_private_key(key_pair);
}

void parse_key(EVP_PKEY* pkey) {
    int pkey_len = 0;
    char* pkey_buffer;
    
    // get length of public key (it will be written to pkey_len)
    EVP_PKEY_get_raw_public_key(public_key, NULL, &pkey_len);
    pkey_buffer = malloc(pkey_len * sizeof(char));

    // get raw public key into the buffer
    EVP_PKEY_get_raw_public_key(public_key, pkey_buffer, &pkey_len);

    // gey key params
    OSSL_PARAM* params;
    EVP_PKEY_todata(public_key, EVP_PKEY_KEYPAIR, &params);

    char* group_name = OSSL_PARAM_locate(params, "group")->data;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(group_name);
    BIGNUM* p = OSSL_PARAM_locate(params, "p")->data;

    EC_POINT* Y;
    EC_POINT_oct2point(group, Y, pkey_buffer, pkey_len, NULL);

    free(pkey_buffer);
    free(k_buffer);
    OSSL_PARAM_free(params);
    EC_GROUP_free(group);
    EC_POINT_free(Y);
}
