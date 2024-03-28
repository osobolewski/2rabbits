#include "rejection_sampling.h"
#include <openssl/rand.h>
#include "../utils.h"
#include "../logger/logger.h"
#include <openssl/evp.h>
#include <string.h>


BIGNUM* rs_encrypt(int m, const char* msg, int msg_len, EC_POINT* Y, EC_GROUP* group) {
    BIGNUM* k = BN_secure_new();
    BIGNUM* order = BN_new();
    BIGNUM* one = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* R = EC_POINT_new(group);

    #define RS_ENCRYPT_CLEANUP \
        EC_POINT_free(R);\
        BN_CTX_free(ctx);\
        BN_free(order);\
        BN_free(k);\
        BN_free(one);

    int ok;

    if (Y == NULL || group == NULL || m <= 0 || m > 31) {
        RS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Encryption parameters invalid or unspecified", "RS");
        return NULL;
    }

    ok = EC_GROUP_get_order(group, order, ctx);
    if (!ok) {
        RS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Get order failed for provided group", "RS");
        return NULL;
    }

    ok = BN_dec2bn(&one, "1");
    if (ok <= 0) {
        RS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Creating a BIGNUM 1 failed", "RS");
        return NULL;
    }

    // generate a random k
    ok = BN_priv_rand_range(k, order);
    if (ok <= 0) {
        RS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Get random k failed ", "RS");
        return NULL;
    }

    int comparison;

    // calculate R = k*Y
    ok = EC_POINT_mul(group, R, NULL, Y, k, ctx);
    if (ok <= 0) {
        RS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Calculating R = k*Y failed", "RS");
        return NULL;
    }

    do {
        // parse point as bytes
        size_t len = encoded_point_len(R, group, ctx);
        char encoded_R[len];
        
        ok = point_2_buffer(encoded_R, len, R, group, ctx);
        if (ok <= 0) {
            RS_ENCRYPT_CLEANUP;
            logger(LOG_ERR, "Serialization of R failed", "RS");
            return NULL;
        }

        const char* input[2] = {encoded_R, "00"};
        int digest_len;
        const int input_lens[2] = {(int)len, 3};
        char* digest = hash(input, 2, input_lens, &digest_len);

        if (digest == NULL) {
            RS_ENCRYPT_CLEANUP;
            logger(LOG_ERR, "Hashing R failed", "RS");
            return NULL;
        }

        char* hex = chr_2_hex(msg, msg_len);
        logger(LOG_DBG, "Message:", "RS");
        logger(LOG_DBG, hex, "RS");

        hex = chr_2_hex(digest, digest_len);
        logger(LOG_DBG, "Hash digest:", "RS");
        logger(LOG_DBG, hex, "RS");

        comparison = compare_n_lsb(msg, msg_len, digest, digest_len, m);
        free(digest);
        
        if (comparison) {
            // k = k + 1
            ok = BN_add(k, k, one);
            if (ok <= 0) {
                RS_ENCRYPT_CLEANUP;
                logger(LOG_ERR, "Calculating k = k + 1 failed", "RS");
                return NULL;
            }

            // R = R + Y
            ok = EC_POINT_add(group, R, R, Y, ctx);
            
            if (ok <= 0) {
                RS_ENCRYPT_CLEANUP;
                logger(LOG_ERR, "Calculating R + Y failed", "RS");
                return NULL;
            }
        }
        
    } while (comparison);

    logger(LOG_DBG, "Found k:", "RS");
    logger(LOG_DBG, BN_print_str(k), "RS");
    
    EC_POINT_free(R);
    BN_CTX_free(ctx);
    BN_free(order);
    BN_free(one);

    return k;
}

char* rs_decrypt(int m, EC_POINT* r, BIGNUM* y, EC_GROUP* group) {
    EC_POINT* R = EC_POINT_new(group);
    BN_CTX* ctx = BN_CTX_new();

    int ok;

    #define RS_DECRYPT_CLEANUP \
        EC_POINT_free(R);\
        BN_CTX_free(ctx);

    if (r == NULL || group == NULL || y == NULL) {
        RS_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Decryption parameters invalid or unspecified", "RS");
        return NULL;
    }

    // calculate R = k*Y
    ok = EC_POINT_mul(group, R, NULL, r, y, ctx);
    if (ok <= 0) {
        RS_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Calculating R = y*r failed", "RS");
        return NULL;
    }

    // parse point as bytes
    size_t len = encoded_point_len(R, group, ctx);
    char encoded_R[len];
    ok = point_2_buffer(encoded_R, len, R, group, ctx);

    if (ok <= 0) {
        RS_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Serialization of R failed", "RS");
        return NULL;
    }

    const char* input[2] = {encoded_R, "00"};
    int digest_len;
    const int input_lens[2] = {(int)len, 3};
    char* digest = hash(input, 2, input_lens, &digest_len);

    const char* hex = chr_2_hex(digest, digest_len);
    logger(LOG_DBG, "Hash digest:", "RS");
    logger(LOG_DBG, hex, "RS");

    char* plaintext = recover_n_lsbs_str(digest, digest_len, m);
    
    free(digest);
    EC_POINT_free(R);
    BN_CTX_free(ctx);

    return plaintext;
}


