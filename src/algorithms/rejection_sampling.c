#include "rejection_sampling.h"
#include <openssl/rand.h>
#include "logger.h"
#include <openssl/evp.h>

BIGNUM* rs_encrypt(int m, int msg, EC_POINT* Y, EC_GROUP* group) {
    BIGNUM* k;
    BIGNUM* order;

    int ok;

    if (Y == NULL || group == NULL || m <= 0 || m >= (1 << 16)) {
        logger(LOG_ERR, "Encryption parameters invalid or unspecified", "RS");
        return NULL;
    }

    BN_CTX* ctx = BN_CTX_new();

    ok = EC_GROUP_get_order(group, order, ctx);
    if (!ok) {
        BN_CTX_free(ctx);
        logger(LOG_ERR, "Get order failed for provided group", "RS");
        return NULL;
    }

    k = BN_secure_new();
    if (k == NULL) {
        BN_CTX_free(ctx);
        BN_free(order);
        logger(LOG_ERR, "BIGNUM allocation failure for k", "RS");
        return NULL;
    }

    // generate a random k
    ok = BN_priv_rand_range(k, order);
    if (ok <= 0) {
        BN_CTX_free(ctx);
        BN_free(order);
        BN_free(k);
        logger(LOG_ERR, "Get random k failed ", "RS");
        return NULL;
    }

    int comparison;
    EC_POINT* R;
    // calculate R = k*Y
    ok = EC_POINT_mul(group, R, NULL, Y, k, ctx);
    if (ok <= 0) {
        BN_CTX_free(ctx);
        BN_free(order);
        BN_free(k);
        logger(LOG_ERR, "Calculating R = k*Y failed", "RS");
        return NULL;
    }

    do {
        // parse point as bytes
        size_t len = EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        unsigned char encoded_R[len];

        ok = EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, encoded_R, len, ctx);
        if (ok <= 0) {
            BN_CTX_free(ctx);
            BN_free(order);
            BN_free(k);
            EC_POINT_free(R);
            logger(LOG_ERR, "Serialization of R failed", "RS");
            return NULL;
        }

        logger(LOG_DBG, encoded_R, "RS");

        char* input[2] = {encoded_R, "00"};
        int digest_len;
        unsigned char* digest = hash(input, 2, &digest_len);
        if (digest == NULL) {
            BN_CTX_free(ctx);
            BN_free(order);
            BN_free(k);
            EC_POINT_free(R);
            logger(LOG_ERR, "Hashing R failed", "RS");
            return NULL;
        }

        comparison = compare_n_lsb(msg, strlen(msg), digest, digest_len, m);
        
        if (comparison) {
            ok = BN_add(k, k, 1);
            
            EC_POINT* RY;
            ok = ok | EC_POINT_add(group, RY, R, Y, ctx);
            if (ok <= 0) {
                BN_CTX_free(ctx);
                BN_free(order);
                BN_free(k);
                EC_POINT_free(R);
                logger(LOG_ERR, "Calculating R + Y failed", "RS");
                return NULL;
            }
            EC_POINT_free(R);
            R = RY;
        }
    } while (comparison);

    EC_POINT_free(R);
    BN_free(order);
    BN_CTX_free(ctx);

    return k;
}

/* \return 0 if n least significant bits of a and b are the same and 1 otherwise*/
int compare_n_lsb(unsigned char* a, int len_a, unsigned char* b, int len_b, int n) {
    int bytes_to_check = n/(sizeof(unsigned char)) + 1;

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

    return comparison;
}

unsigned char* hash(unsigned char** inputs, int inputs_len, int* digest_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

    if (mdctx == NULL) {
        logger(LOG_ERR, "Hashing context creation failed", "RS");
        return NULL;
    }

	int ok;
	EVP_MD* algo = EVP_sha3_256;

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
    unsigned char* digest = malloc(*digest_len * sizeof(unsigned char));

    ok = EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    if (ok <= 0) {
        free(digest);
        EVP_MD_CTX_destroy(mdctx);
        logger(LOG_ERR, "Hash computation failed", "RS");
        return NULL;
    }

    EVP_MD_CTX_destroy(mdctx);

    return digest;
}


int rs_decrypt(EC_POINT* r, BIGNUM* y) {

}

void parse_key(EVP_PKEY* pkey) {
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
}
