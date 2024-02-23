#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "ecdsa.h"
#include "advanced_sampling.h"
#include "../logger/logger.h"
#include "../utils.h"
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <time.h>


char* ecdsa_sign(EVP_PKEY* sign_priv_key, const char* sign_message) {
    const char* inputs[] = {sign_message};
    const int lens[] = {(int)strlen(sign_message)};
    int digest_len;
    
    char* digest = hash(inputs, 1, lens, &digest_len);

    // We have to use `deprecated` functions
    // here as the new high-level API
    // does not allow us to do anything with the signature
    // params. I really don't know as to __why__ they are
    // deprecated as the high level APIs use those functions 
    // anyway. Let people use low-level functions! They sometimes
    // know what they are doing!
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(sign_priv_key); 

    int buf_len = ECDSA_size(ec_key);
    char* sig = (char*)malloc(buf_len * sizeof(char));
    
    ECDSA_sign(0, (unsigned char*)digest, digest_len, (unsigned char*)sig, (unsigned int)buf_len, ec_key);

    free(digest);
    EC_KEY_free(ec_key);;
    return sig;
} 

char* ecdsa_as_sign(EVP_PKEY* sign_priv_key, const char* sign_msg, 
                    EVP_PKEY* enc_pub_key, const char* enc_msg, int enc_msg_len,
                    const char* dkey, int dkey_len, 
                    int m, int C, BIGNUM*** lut) {

    logger(LOG_DBG, "Parsing the private key...", "ECDSA");

    EC_GROUP* group = NULL;
    EC_POINT* X = NULL;
    BIGNUM* x = NULL;
    parse_evp_pkey(sign_priv_key, &group, &X, &x);

    EC_GROUP* group2 = NULL;
    EC_POINT* Y = NULL;
    parse_evp_pkey(enc_pub_key, &group2, &Y, NULL);

    if (EC_GROUP_get_curve_name(group) != EC_GROUP_get_curve_name(group2)) {
        logger(LOG_ERR, "Provided keys operate on different curves!", "ECDSA");
        return NULL;
    }

    time_t now;
    time(&now);
    BIGNUM* k = as_encrypt(lut, m, C, enc_msg, enc_msg_len, sign_msg, strlen(sign_msg), dkey, dkey_len, Y, group);

    BIGNUM* order;
    EC_GROUP_get_order(group, order, NULL);
    
    // precompute k_inv to use in the signature algo
    BN_mod_inverse(k, k, order, NULL);

    const char* inputs[] = {sign_msg};
    const int lens[] = {(int)strlen(sign_msg)};
    int digest_len;
    
    char* digest = hash(inputs, 1, lens, &digest_len);

    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(sign_priv_key); 

    int buf_len = ECDSA_size(ec_key);
    char* sig = (char*)malloc(buf_len * sizeof(char));

    ECDSA_sign_ex(0, digest, digest_len, sig, buf_len, k, NULL, ec_key);

    free(digest);
    BIGNUM_free(order);
    BIGNUM_free(k);
    BIGNUM_free(x);
    EC_POINT_free(X);
    EC_POINT_free(Y);

    return sig;
}

char* ecdsa_rs_sign(EVP_PKEY* sign_priv_key, const char* sign_msg, 
                    EVP_PKEY* enc_pub_key, const char* enc_msg, int enc_msg_len,
                    const char* dkey, int dkey_len) {
    return "";
}



int ecdsa_verify_openssl(EVP_PKEY* sign_pub_key, const char* sign_message, 
                 const char* signature, int signature_len) {
    const char* inputs[] = {sign_message};
    const int lens[] = {(int)strlen(sign_message)};
    int digest_len;
    
    char* digest = hash(inputs, 1, lens, &digest_len);

    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(sign_pub_key); 

    int verify = ECDSA_verify(0, digest, digest_len, signature, signature_len, ec_key);
    free(digest);

    return verify;
}

// this function is basically copied from openssl library
int ecdsa_verify_explicit(EVP_PKEY* sign_pub_key, const char* sign_message, 
                 const char* signature, int signature_len,
                 EC_POINT* return_r) {
    const char* inputs[] = {sign_message};
    const int lens[] = {(int)strlen(sign_message)};
    int dgst_len;
    
    char* dgst = hash(inputs, 1, lens, &dgst_len);

    EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(sign_pub_key); 
    ECDSA_SIG* sig; 
    d2i_ECDSA_SIG(&sig, signature, signature_len); 

    int ret = -1, i;
    BN_CTX *ctx;
    const BIGNUM *order;
    BIGNUM *u1, *u2, *m, *X;
    EC_POINT *point = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;

    /* check input values */
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
        (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL) {
        return -1;
    }

    if (!EC_KEY_can_sign(eckey)) {
        return -1;
    }

    ctx = BN_CTX_new_ex((*eckey)->libctx);
    if (ctx == NULL) {
        return -1;
    }
    BN_CTX_start(ctx);
    u1 = BN_CTX_get(ctx);
    u2 = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    if (X == NULL) {
        goto err;
    }

    order = EC_GROUP_get0_order(group);
    if (order == NULL) {
        goto err;
    }

    BIGNUM* r = ECDSA_SIG_get0_r(sig);
    BIGNUM* s = ECDSA_SIG_get0_s(sig);

    if (BN_is_zero(r) || BN_is_negative(r) ||
        BN_ucmp(r, order) >= 0 || BN_is_zero(s) ||
        BN_is_negative(s) || BN_ucmp(s, order) >= 0) {
        ret = 0;                /* signature is invalid */
        goto err;
    }
    /* calculate tmp1 = inv(S) mod order */
    if (!ossl_ec_group_do_inverse_ord(group, u2, s, ctx)) {
        goto err;
    }
    /* digest -> m */
    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BN_bin2bn(dgst, dgst_len, m)) {
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        goto err;
    }

    /* u1 = m * tmp mod order */
    if (!BN_mod_mul(u1, m, u2, order, ctx)) {
        goto err;
    }
    /* u2 = r * w mod q */
    if (!BN_mod_mul(u2, r, u2, order, ctx)) {
        goto err;
    }

    if ((point = EC_POINT_new(group)) == NULL) {
        goto err;
    }
    if (!EC_POINT_mul(group, point, u1, pub_key, u2, ctx)) {
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates(group, point, X, NULL, ctx)) {
        goto err;
    }

    if (!BN_nnmod(u1, X, order, ctx)) {
        goto err;
    }

    // copy and return the recalculated point
    if (return_r != NULL) {
        EC_POINT_copy(return_r, point);
    }

    /*  if the signature is correct u1 is equal to sig->r */
    ret = (BN_ucmp(u1, r) == 0);
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    ECDSA_SIG_free(sig);
    return ret;
}