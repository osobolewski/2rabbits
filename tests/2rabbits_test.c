#include "../src/algorithms/2rabbits.h"
#include "../src/logger/logger.h"
#include "../src/utils.h"
#include <assert.h>

int two_rabbits_test(int b) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* private_key = BN_new();
    BIGNUM* order = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* public_key = EC_POINT_new(group);
    EC_KEY* keypair = EC_KEY_new();

    // not checking openssl errors here...

    logger(LOG_DBG, "Getting group order...", "TEST");
    EC_GROUP_get_order(group, order, ctx);

    logger(LOG_DBG, "Getting random private key...", "TEST");
    // x <-R {0,...,order-1} 
    BN_rand_range(private_key, order);

    logger(LOG_DBG, "Calculating corresponding public key...", "TEST");
    // X = x * G
    EC_POINT_mul(group, public_key, private_key, NULL, NULL, ctx);

    logger(LOG_DBG, "Setting EC_KEY object params...", "TEST");
    EC_KEY_set_group(keypair, group);
    EC_KEY_set_private_key(keypair, private_key);
    EC_KEY_set_public_key(keypair, public_key);

    logger(LOG_DBG, "Trying encryption...", "TEST");
    BIGNUM* k = two_rabbits_encrypt(b, public_key, group);

    logger(LOG_DBG, "Calculating r = k*G...", "TEST");
    EC_POINT* r = EC_POINT_new(group);
    EC_POINT_mul(group, r, k, NULL, NULL, ctx);

    logger(LOG_DBG, "Trying decryption...", "TEST");
    int bit_recovered = two_rabbits_decrypt(r, private_key, group);

    assert(bit_recovered == b);

    BN_free(k);
    EC_POINT_free(r);
    EC_KEY_free(keypair);
    EC_POINT_free(public_key);
    EC_GROUP_free(group);
    BN_free(order);
    BN_free(private_key);
    BN_CTX_free(ctx);
}

int main(int argc, char* argv[]) {   
    set_verbose(LOG_INFO);

    logger(LOG_INFO, "Starting 2 rabbits tests...", "TEST");

    for (int i = 0; i < 10000; ++i) {
        for (int b = 0; b < 2; ++b) {
            char print_string[255];
            sprintf(print_string, "Testing for b = %d", b);
            logger(LOG_DBG, print_string, "TEST");
            two_rabbits_test(b);
        }
    }

    logger(LOG_INFO, "2 rabbits tests done", "TEST");
}