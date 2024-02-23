#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "ecdsa.h"
#include "../logger/logger.h"
#include "../utils.h"
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <time.h>


char* ecdsa_sign(const char* sign_prv_key_path, const char* sign_message) {
    const char* inputs[] = {sign_message};
    const int lens[] = {(int)strlen(sign_message)};
    int digest_len;
    
    char* digest = hash(inputs, 1, lens, &digest_len);

    logger(LOG_DBG, "Reading the private key...", "ECDSA");

    EVP_PKEY* privKey = NULL;
    parse_pem_key(sign_prv_key_path, &privKey, 1);

    // We have to use `deprecated` functions
    // here as the new high-level API
    // does not allow us to do anything with the signature
    // params. I really don't know as to __why__ they are
    // deprecated as the high level APIs use those functions 
    // anyway. Let people use low-level functions! They sometimes
    // know what they are doing!
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(privKey); 

    int buf_len = ECDSA_size(ec_key);
    char* sig = (char*)malloc(buf_len * sizeof(char));
    
    ECDSA_sign(0, (unsigned char*)digest, digest_len, (unsigned char*)sig, (unsigned int)buf_len, ec_key);

    free(digest);
    EC_KEY_free(ec_key);;
    return sig;
} 

char* ecdsa_as_sign(const char* sign_prv_key_path, const char* sign_msg, 
                    const char* enc_pub_key_path, const char* enc_msg, int enc_msg_len,
                    const char* dkey, int dkey_len) {

    logger(LOG_DBG, "Reading the private key...", "ECDSA");

    EVP_PKEY* privKey = NULL;
    parse_pem_key(sign_prv_key_path, &privKey, 1);

    logger(LOG_DBG, "Parsing the private key...", "ECDSA");

    EC_GROUP* group = NULL;
    EC_POINT* X = NULL;
    BIGNUM* x = NULL;
    parse_evp_pkey(privKey, &group, &X, &x);

    return "";
}

char* ecdsa_rs_sign(const char* sign_prv_key_path, const char* sign_msg, 
                    const char* enc_pub_key_path, const char* enc_msg, int enc_msg_len,
                    const char* dkey, int dkey_len) {
    return "";
}



int ecdsa_verify(const char* sign_pub_key_path, const char* sign_message, 
                 const char* signature, int signature_len,
                 EC_POINT* r) {
    return 0;
}

