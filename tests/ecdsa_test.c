#include "../src/algorithms/advanced_sampling.h"
#include "../src/logger/logger.h"
#include "../src/utils.h"
#include <assert.h>
#include <string.h>


int main(int argc, char* argv[]) {   
    set_verbose(LOG_DBG);

    logger(LOG_INFO, "Reading the public key...", "TEST");

    EVP_PKEY* pubkey = NULL;
    parse_pem_key("./tests/keys/ec-secp256k1-pub-key.pem", &pubkey, 0);

    logger(LOG_INFO, "Parsing the public key...", "TEST");

    EC_GROUP* group_1 = NULL;
    EC_POINT* Y = NULL;
    parse_evp_pkey(pubkey, &group_1, &Y, NULL);

    logger(LOG_INFO, "Reading the private key...", "TEST");

    EVP_PKEY* privkey = NULL;
    parse_pem_key("./tests/keys/ec-secp256k1-priv-key.pem", &privkey, 1);

    logger(LOG_INFO, "Parsing the private key...", "TEST");

    EC_GROUP* group_2 = NULL;
    EC_POINT* Y2 = NULL;
    BIGNUM* y = NULL;
    parse_evp_pkey(privkey, &group_2, &Y2, &y);

    EVP_PKEY_free(pubkey);
    EC_GROUP_free(group_1);
    EC_POINT_free(Y);

    EVP_PKEY_free(privkey);
    EC_GROUP_free(group_2);
    EC_POINT_free(Y2);
    BN_free(y);
}