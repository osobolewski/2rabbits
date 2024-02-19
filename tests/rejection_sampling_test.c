#include "../src/algorithms/rejection_sampling.h"
#include "../src/logger/logger.h"
#include "../src/utils.h"
#include <assert.h>


int chrcmp(const char* s1, const char* s2, const int l) {
    int c = 0;
    for (int i = 0; i < l; ++i) {
        c |= s1[i] ^ s2[i];
    }
    return c != 0;
}

int rs_test(int m, const char* plaintext, int len) {
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
    BIGNUM* k = rs_encrypt(m, plaintext, public_key, group);

    logger(LOG_DBG, "Calculating r = k*G...", "TEST");
    EC_POINT* r = EC_POINT_new(group);
    EC_POINT_mul(group, r, k, NULL, NULL, ctx);

    logger(LOG_DBG, "Trying decryption...", "TEST");
    char* plaintext_recovered = rs_decrypt(m, r, private_key, group);

    logger(LOG_INFO, "Decryption result:", "TEST");
    int pt_len = m/8 + (m % 8 == 0 ? 0 : 1);

    //printf("%s\n", plaintext_recovered);
    logger(LOG_INFO, chr_2_hex(plaintext_recovered, pt_len), "TEST");

    assert(compare_n_lsb(plaintext, len, plaintext_recovered, pt_len, m) == 0);

    free(plaintext_recovered);
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

    logger(LOG_INFO, "Starting rejection sampling tests...", "TEST");

    const char bts_string[] = {(char) 4, (char) 1, (char) 2, (char) 3, (char) 4, (char) 0};

    const char* test_strings[] = {"abcd", "test", "a longish string", "ab", "zzzz", bts_string};
    
    for (int m = 1; m < 17; ++m) {
        for (int i = 0; i < 6; ++i) {
            char print_string[255];
            sprintf(print_string, "Testing for m = %d and str = %s", m, test_strings[i]);
            logger(LOG_INFO, print_string, "TEST");
            rs_test(m, test_strings[i], strlen(test_strings[i]));
        }
    }

    logger(LOG_INFO, "Rejection sampling tests done", "TEST");
}