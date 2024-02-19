#include "2rabbits.h"
#include "../logger/logger.h"
#include <openssl/rand.h>
#include "../utils.h"


BIGNUM* two_rabbits_encrypt(int b, EC_POINT* Y, EC_GROUP* group) {
    BIGNUM* kappa = BN_secure_new();
    BIGNUM* kappa_prim = BN_secure_new();
    BIGNUM* minus_one = BN_new();
    BIGNUM* order = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* zeta = EC_POINT_new(group);
    EC_POINT* zeta_prim = EC_POINT_new(group);
    int ok;

    #define TWOR_ENCRYPT_CLEANUP \
        EC_POINT_free(zeta);\
        EC_POINT_free(zeta_prim);\
        BN_CTX_free(ctx);\
        BN_free(order);\
        BN_free(kappa);\
        BN_free(kappa_prim);\
        BN_free(minus_one);

    if (Y == NULL || group == NULL || b < 0 || b > 1) {
        TWOR_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Encryption parameters invalid or unspecified", "2R");
        return NULL;
    }

    ok = EC_GROUP_get_order(group, order, ctx);
    if (!ok) {
        TWOR_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Get order failed for provided group", "2R");
        return NULL;
    }

    ok = BN_dec2bn(&minus_one, "-1");
    if (ok <= 0) {
        TWOR_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Creating a BIGNUM -1 failed", "2R");
        return NULL;
    }

    // kappa <-R {0, order}
    ok = BN_priv_rand_range(kappa, order);
    if (ok <= 0) {
        TWOR_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Get random kappa failed ", "2R");
        return NULL;
    }
    // kappa'_prim' = -kappa
    ok = BN_mod_mul(kappa_prim, kappa, minus_one, order, ctx);
    if (ok <= 0) {
        TWOR_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Get kappa' = -kappa failed ", "2R");
        return NULL;
    }

    // Zeta = kappa*Y
    ok = EC_POINT_mul(group, zeta, NULL, Y, kappa, ctx);
    if (ok <= 0) {
        TWOR_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Calculating Zeta = kappa*Y failed", "2R");
        return NULL;
    }

    // Zeta' = -1*Zeta = kappa_prim*Y
    ok = EC_POINT_mul(group, zeta_prim, NULL, zeta, minus_one, ctx);
    if (ok <= 0) {
        TWOR_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Calculating Zeta' = kappa'*Y failed", "2R");
        return NULL;
    }

    logger(LOG_DBG, "kappa:", "2R");
    logger(LOG_DBG, BN_print_str(kappa), "2R");

    logger(LOG_DBG, "kappa_prim:", "2R");
    logger(LOG_DBG, BN_print_str(kappa_prim), "2R");

    // parse points as bytes
    char* hashes[2];
    BIGNUM* labels[2] = {kappa, kappa_prim};
    EC_POINT* points[2] = {zeta, zeta_prim};
    int digest_len;

    for (int i = 0; i < 2; ++i) {
        size_t len;
        len = EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        char encoded_Zeta[len];

        ok = EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)encoded_Zeta, len, ctx);
        if (ok <= 0) {
            TWOR_ENCRYPT_CLEANUP;
            logger(LOG_ERR, "Serialization of Zeta failed", "2R");
            return NULL;
        }

        const char* input[2] = {encoded_Zeta, "00"};
        const int input_lens[2] = {(int)len, 3};
        char* digest = hash(input, 2, input_lens, &digest_len);

        hashes[i] = digest;
    }

    // sort hashes
    int indices[2];
    chr_sort(hashes, 2, digest_len, indices);

    for (int i = 0; i < 2; ++i) {
        logger(LOG_DBG, "Hash: ", "2R");
        logger(LOG_DBG, chr_2_hex(hashes[i], digest_len), "2R");
        free(hashes[i]);
    }    

    // select k = kappa_b
    BIGNUM* k;
    k = BN_dup(labels[indices[b]]);

    logger(LOG_DBG, "Found k:", "2R");
    logger(LOG_DBG, BN_print_str(k), "2R");

    TWOR_ENCRYPT_CLEANUP
    
    return k;
}

int two_rabbits_decrypt(EC_POINT* r, BIGNUM* y, EC_GROUP* group) {
    EC_POINT* rho = EC_POINT_new(group);
    EC_POINT* rho_prim = EC_POINT_new(group);
    BIGNUM* minus_one = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    int ok;

    #define TWOR_DECRYPT_CLEANUP \
        EC_POINT_free(rho);\
        EC_POINT_free(rho_prim);\
        BN_free(minus_one);\
        BN_CTX_free(ctx);

    if (r == NULL || group == NULL || y == NULL) {
        TWOR_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Decryption parameters invalid or unspecified", "2R");
        return -1;
    }

    BN_free(minus_one);
    ok = BN_dec2bn(&minus_one, "-1");
    if (ok <= 0) {
        TWOR_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Creating a BIGNUM -1 failed", "2R");
        return -1;
    }

    // calculate rho = y*r = k*Y
    ok = EC_POINT_mul(group, rho, NULL, r, y, ctx);
    if (ok <= 0) {
        TWOR_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Calculating rho = y*r failed", "2R");
        return -1;
    }

    // calculate rho' = -1*rho
    ok = EC_POINT_mul(group, rho_prim, NULL, rho, minus_one, ctx);
    if (ok <= 0) {
        TWOR_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Calculating rho' = -1*rho failed", "2R");
        return -1;
    }

    // parse points as bytes
    char* hashes[2];
    EC_POINT* points[2] = {rho, rho_prim};
    int digest_len;

    for (int i = 0; i < 2; ++i) {
        size_t len;
        len = EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        char encoded_rho[len];

        ok = EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)encoded_rho, len, ctx);
        if (ok <= 0) {
            TWOR_DECRYPT_CLEANUP;
            logger(LOG_ERR, "Serialization of rho failed", "2R");
            return -1;
        }

        const char* input[2] = {encoded_rho, "00"};
        const int input_lens[2] = {(int)len, 3};
        char* digest = hash(input, 2, input_lens, &digest_len);
        hashes[i] = digest;
    }

    int b = chr_cmp(hashes[0], hashes[1], digest_len) > 0;

    for (int i = 0; i < 2; ++i) {
        free(hashes[i]);
    }    
    TWOR_DECRYPT_CLEANUP

    return b;
}