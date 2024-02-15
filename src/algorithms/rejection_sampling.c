#include "rejection_sampling.h"
#include <openssl/rand.h>
#include "../utils.h"
#include "../logger/logger.h"
#include <openssl/evp.h>
#include <string.h>


BIGNUM* rs_encrypt(int m, const char* msg, EC_POINT* Y, EC_GROUP* group) {
    BIGNUM* k = BN_new();
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

    if (Y == NULL || group == NULL || m <= 0 || m >= (1 << 16)) {
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

    k = BN_secure_new();
    if (k == NULL) {
        RS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "BIGNUM allocation failure for k", "RS");
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
        size_t len = EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        char encoded_R[len];

        ok = EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)encoded_R, len, ctx);
        if (ok <= 0) {
            RS_ENCRYPT_CLEANUP;
            logger(LOG_ERR, "Serialization of R failed", "RS");
            return NULL;
        }

        char* input[2] = {encoded_R, "00"};
        int digest_len;
        char* digest = hash(input, 2, &digest_len);

        if (digest == NULL) {
            RS_ENCRYPT_CLEANUP;
            logger(LOG_ERR, "Hashing R failed", "RS");
            return NULL;
        }

        char* hex = chrs2hex(msg, strlen(msg));
        logger(LOG_DBG, "Message:", "RS");
        logger(LOG_DBG, hex, "RS");

        hex = chrs2hex(digest, digest_len);
        logger(LOG_DBG, "Hash digest:", "RS");
        logger(LOG_DBG, hex, "RS");

        comparison = compare_n_lsb(msg, strlen(msg), digest, digest_len, m);
        free(digest);
        
        if (comparison) {
            // k = k + 1
            BIGNUM* k_plus_one = BN_new();

            ok = BN_dec2bn(&one, "1");
            if (ok <= 0) {
                RS_ENCRYPT_CLEANUP;
                BN_free(k_plus_one);
                logger(LOG_ERR, "Creating a BIGNUM 1 failed", "RS");
                return NULL;
            }

            ok = BN_add(k_plus_one, k, one);
            if (ok <= 0) {
                RS_ENCRYPT_CLEANUP;
                BN_free(k_plus_one);
                logger(LOG_ERR, "Calculating k = k + 1 failed", "RS");
                return NULL;
            }

            BN_free(k);
            k = k_plus_one;
            
            EC_POINT* R_plus_Y = EC_POINT_new(group);
            
            // R = R + Y
            ok = EC_POINT_add(group, R_plus_Y, R, Y, ctx);
            
            if (ok <= 0) {
                RS_ENCRYPT_CLEANUP;
                EC_POINT_free(R_plus_Y);
                logger(LOG_ERR, "Calculating R + Y failed", "RS");
                return NULL;
            }

            EC_POINT_free(R);

            R = R_plus_Y;
        }
        
    } while (comparison);

    logger(LOG_INFO, "Found k:", "RS");
    BN_print_fp(stdout, k);
    
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
    size_t len = EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    char encoded_R[len];

    ok = EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)encoded_R, len, ctx);
    if (ok <= 0) {
        RS_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Serialization of R failed", "RS");
        return NULL;
    }

    char* input[2] = {encoded_R, "00"};
    int digest_len;
    char* digest = hash(input, 2, &digest_len);

    char* hex = chrs2hex(digest, digest_len);
    logger(LOG_DBG, "Hash digest:", "RS");
    logger(LOG_DBG, hex, "RS");

    char* plaintext;
    int starting_index;

    if (m % 8 == 0) {
        plaintext = (char*)malloc((m/8 + 1) * sizeof(char));
        starting_index = digest_len - m/8;
        
        for (int i = starting_index; i < digest_len; ++i) {
            plaintext[i - starting_index] = digest[i];
        }
        // technically it doesnt have to be a string
        // but better safe than sorry.
        plaintext[digest_len - starting_index] = '\0';
    } else {
        // we need m%8 lsbits of another byte
        plaintext = (char*)malloc((m/8 + 2) * sizeof(char));
        starting_index = digest_len - m/8 - 1;

        for (int i = starting_index; i < digest_len; ++i) {
            plaintext[i - starting_index] = digest[i];
        }
        plaintext[digest_len - starting_index] = '\0';
        plaintext[0] = plaintext[0] & ((1 << m%8) - 1);
    }
    
    free(digest);
    EC_POINT_free(R);
    BN_CTX_free(ctx);

    return plaintext;
}

/*void parse_key(EVP_PKEY* pkey) {
    int pkey_len = 0;
    char* pkey_buffer;
    
    // get length of public key (it will be written to pkey_len)
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pkey_len);
    pkey_buffer = malloc(pkey_len * sizeof(char));

    // get raw public key into the buffer
    EVP_PKEY_get_raw_public_key(pkey, pkey_buffer, &pkey_len);

    // gey key params
    OSSL_PARAM* params;
    EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params);

    char* group_name = OSSL_PARAM_locate(params, "group")->data;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(group_name);
    BIGNUM* p = OSSL_PARAM_locate(params, "p")->data;

    EC_POINT* Y;
    EC_POINT_oct2point(group, Y, pkey_buffer, pkey_len, NULL);

    free(pkey_buffer);
    OSSL_PARAM_free(params);
    EC_GROUP_free(group);
    EC_POINT_free(Y);
}*/
