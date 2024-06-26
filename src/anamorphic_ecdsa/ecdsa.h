#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

char* ecdsa_sign(EVP_PKEY* sign_priv_key, const char* sign_message, int sign_message_len, int* sig_len);

char* ecdsa_sign_evp(EVP_PKEY* sign_priv_key, const char* sign_message, int sign_message_len, int* sig_len);

char* ecdsa_as_sign(EVP_PKEY* sign_priv_key, const char* sign_msg, int sign_msg_len, 
                    int* sig_len, EVP_PKEY* enc_pub_key, const char* enc_msg, 
                    int enc_msg_len, const char* dkey, int dkey_len, 
                    const char* delta, int delta_len,
                    int m, int C, BIGNUM*** lut);

char* ecdsa_rs_sign(EVP_PKEY* sign_priv_key, 
                    const char* sign_msg, int sign_message_len,
                    int* sig_len, EVP_PKEY* enc_pub_key, 
                    const char* enc_msg, int enc_msg_len,
                    int m);

int ecdsa_verify_openssl(EVP_PKEY* sign_pub_key, 
                 const char* sign_message, int sign_message_len, 
                 const char* signature, int signature_len);

int ecdsa_verify_evp(EVP_PKEY* sign_pub_key, 
                 const char* sign_message, int sign_message_len,
                 const char* signature, int signature_len);

int ecdsa_verify_full(EVP_PKEY* sign_pub_key, 
                 const char* sign_message, int sign_message_len, 
                 const char* signature, int signature_len,
                 EC_POINT** return_r);

                 