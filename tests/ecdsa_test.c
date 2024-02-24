#include "../src/algorithms/advanced_sampling.h"
#include "../src/algorithms/rejection_sampling.h"
#include "../src/anamorphic_ecdsa/ecdsa.h"
#include "../src/logger/logger.h"
#include "../src/utils.h"
#include <assert.h>
#include <string.h>


int main(int argc, char* argv[]) {   
    set_verbose(LOG_INFO);

    logger(LOG_INFO, "Parsing the signing public key...", "TEST");

    EVP_PKEY* pubkey = NULL;
    parse_pem_key("../keys/ec-secp256k1-pub-key.pem", &pubkey, 0);

    EC_GROUP* group_1 = NULL;
    EC_POINT* Y = NULL;
    parse_evp_pkey(pubkey, &group_1, &Y, NULL);

    logger(LOG_INFO, "Reading the signing private key...", "TEST");

    EVP_PKEY* privkey = NULL;
    parse_pem_key("../keys/ec-secp256k1-priv-key.pem", &privkey, 1);

    logger(LOG_INFO, "Parsing the private key...", "TEST");

    EC_GROUP* group_2 = NULL;
    EC_POINT* Y2 = NULL;
    BIGNUM* y = NULL;
    parse_evp_pkey(privkey, &group_2, &Y2, &y);

    logger(LOG_INFO, "Reading the encryption private key...", "TEST");

    EVP_PKEY* privkey_enc = NULL;
    parse_pem_key("../keys/ec-secp256k1-priv-key_enc.pem", &privkey_enc, 1);

    logger(LOG_INFO, "Parsing the private key...", "TEST");

    EC_GROUP* group_3 = NULL;
    EC_POINT* X = NULL;
    BIGNUM* x = NULL;
    parse_evp_pkey(privkey_enc, &group_3, &X, &x);

    logger(LOG_INFO, "Reading the encryption public key...", "TEST");

    EVP_PKEY* pubkey_enc = NULL;
    parse_pem_key("../keys/ec-secp256k1-pub-key_enc.pem", &pubkey_enc, 0);


    // sanity tests
    char msg[] = "A message to sign 101";

    int sig1_len, sig2_len;
    char* sig1 = ecdsa_sign(privkey, msg, &sig1_len);

    char print_buf[200];

    sprintf(print_buf, "sig1: %s", chr_2_hex(sig1, sig1_len));
    logger(LOG_INFO, print_buf, "TEST");

    char* sig2 = ecdsa_sign_evp(privkey, msg, &sig2_len);

    sprintf(print_buf, "sig2: %s", chr_2_hex(sig2, sig2_len));
    logger(LOG_INFO, print_buf, "TEST");

    int verif1 = ecdsa_verify_evp(pubkey, msg, sig1, sig1_len);
    int verif2 = ecdsa_verify_openssl(pubkey, msg, sig1, sig1_len);
    int verif3 = ecdsa_verify_full(pubkey, msg, sig1, sig1_len, NULL);

    assert(verif1 == 1 && verif2 == 1 && verif3 == 1);

    verif1 = ecdsa_verify_evp(pubkey, msg, sig2, sig2_len);
    verif2 = ecdsa_verify_openssl(pubkey, msg, sig2, sig2_len);
    verif3 = ecdsa_verify_full(pubkey, msg, sig2, sig2_len, NULL);

    assert(verif1 == 1 && verif2 == 1 && verif3 == 1);

    free(sig1);
    free(sig2);

    //create a lookup table
    int m = 8;
    int C = 5;

    char dkey[] = "testing dual key";

    BIGNUM*** lut = lut_new(m, C);
    as_fill(lut, m, C, dkey, strlen(dkey), X, group_1);

    int sig3_len;
    char* sig3 = ecdsa_as_sign(privkey, msg, &sig3_len, pubkey_enc, "AA", 2, dkey, strlen(dkey), m, C, lut);

    EC_POINT* r;

    verif1 = ecdsa_verify_evp(pubkey, msg, sig3, sig3_len);
    verif2 = ecdsa_verify_openssl(pubkey, msg, sig3, sig3_len);
    verif3 = ecdsa_verify_full(pubkey, msg, sig3, sig3_len, &r);

    sprintf(print_buf, "sig3: %s", chr_2_hex(sig3, sig3_len));
    logger(LOG_INFO, print_buf, "TEST");

    assert(verif1 == 1 && verif2 == 1 && verif3 == 1);

    char* plaintext3 = as_decrypt(m, msg, strlen(msg), dkey, strlen(dkey), r, x, group_3);

    sprintf(print_buf, "Advanced sampling decrypted plaintext: %s", plaintext3);
    logger(LOG_INFO, print_buf, "TEST");

    assert(compare_n_lsb("AA", 2, plaintext3, 1, m) == 0);

    free(sig3);
    free(plaintext3);
    lut_free(lut, m, C);

    int sig4_len;
    char* sig4 = ecdsa_rs_sign(privkey, msg, &sig4_len, pubkey_enc, "BB", 2, m);

    EC_POINT_free(r);
    verif1 = ecdsa_verify_evp(pubkey, msg, sig4, sig4_len);
    verif2 = ecdsa_verify_openssl(pubkey, msg, sig4, sig4_len);
    verif3 = ecdsa_verify_full(pubkey, msg, sig4, sig4_len, &r);

    sprintf(print_buf, "sig4: %s", chr_2_hex(sig4, sig4_len));
    logger(LOG_INFO, print_buf, "TEST");

    assert(verif1 == 1 && verif2 == 1 && verif3 == 1);

    char* plaintext4 = rs_decrypt(m, r, x, group_3);

    sprintf(print_buf, "Rejection sampling decrypted plaintext: %s", plaintext4);
    logger(LOG_INFO, print_buf, "TEST");

    assert(compare_n_lsb("BB", 2, plaintext4, 1, m) == 0);

    free(sig4);
    free(plaintext4);

    logger(LOG_INFO, "ECDSA tests successful", "TEST");

    EC_POINT_free(r);
    EVP_PKEY_free(pubkey);
    EC_GROUP_free(group_1);
    EC_POINT_free(Y);

    EC_POINT_free(X);
    BN_free(x);
    EVP_PKEY_free(privkey_enc);
    EVP_PKEY_free(pubkey_enc);

    EVP_PKEY_free(privkey);
    EC_GROUP_free(group_2);
    EC_GROUP_free(group_3);
    EC_POINT_free(Y2);
    BN_free(y);
}