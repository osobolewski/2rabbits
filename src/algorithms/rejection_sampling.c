#include "rejection_sampling.h"
#include <openssl/rand.h>
#include "../logger/logger.h"
#include <openssl/evp.h>
#include <string.h>


// only for printing
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
