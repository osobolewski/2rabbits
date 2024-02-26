#include "../../src/algorithms/advanced_sampling.h"
#include "../../src/algorithms/rejection_sampling.h"
#include "../../src/anamorphic_ecdsa/ecdsa.h"
#include "../../src/logger/logger.h"
#include "../../src/utils.h"
#include <assert.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>


char* get_random_bits(int n) {
    int bytes = bit_2_byte_len(n);
    char* buf = (char*)malloc(bytes*sizeof(char));
    RAND_bytes((unsigned char*)buf, bytes);

    return buf;
}

long long get_lut_size(BIGNUM*** lut, int m, int C) {
    int rows = (1 << m);
    int columns = 2 * C;

    long long size = 0;

    // pointer table size
    size += sizeof(lut);
    for (int i = 0; i < rows; i ++) {
        // also pointer table size
        size += sizeof(lut[i]);
        for (int j = 0; j < columns; j++) {
            // size of stored bignum
            if (lut[i][j] != NULL) {
                size += BN_num_bytes(lut[i][j]);
            }
        }
    }

    return size;
}

void as_benchmark(int m, int C, int repetitions, EC_POINT* Y, BIGNUM* y, EC_GROUP* group, EVP_PKEY* signing_key, EVP_PKEY* encryption_key) {
    char print_buf[200];
    const char dkey[] = "dual key";

    BIGNUM*** lut = lut_new(m, C);

    clock_t now = clock();
    as_fill(lut, m, C, dkey, strlen(dkey), Y, group);

    double t = (double)(clock() - now) / CLOCKS_PER_SEC;

    sprintf(print_buf, "as_fill time: %.3f ms", t*1000);
    logger(LOG_INFO, print_buf, "BNCH");

    long long size = get_lut_size(lut, m, C);
    sprintf(print_buf, "Filled LUT size: %u bytes", size);
    logger(LOG_INFO, print_buf, "BNCH");

    // create messages to sign;
    // and messages to encrypt
    char messages[repetitions][20];
    char* messages_enc[repetitions];
    for (int i = 0; i < repetitions; i++) {
        sprintf(messages[i], "Message: %d", i);
        messages_enc[i] = get_random_bits(m);
    }

    // store signatures for verifications
    char* signatures[repetitions];
    int signature_lens[repetitions];

    // benchmark loop
    now = clock();
    for (int i = 0; i < repetitions; i++) {
        // insert
        as_insert(lut, m, C, 0, dkey, strlen(dkey), Y, group);
        // then sign
        signatures[i] = ecdsa_as_sign(signing_key, messages[i], &signature_lens[i], encryption_key, messages_enc[i], bit_2_byte_len(m), dkey, strlen(dkey), m, C, lut);
    }

    t = (double)(clock() - now) / CLOCKS_PER_SEC;
    sprintf(print_buf, "Average as_sign time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    // verify signatures, recover plaintexts
    EC_POINT* rs[repetitions];
    char* plaintexts[repetitions];
    memset(rs, 0, repetitions*sizeof(EC_POINT*));

    now = clock();
    for (int i = 0; i < repetitions; i++) {
        assert(ecdsa_verify_full(signing_key, messages[i], signatures[i], signature_lens[i], &rs[i]) == 1);
        plaintexts[i] = as_decrypt(m, messages[i], strlen(messages[i]), dkey, strlen(dkey), rs[i], y, group);
    }
    t = (double)(clock() - now) / CLOCKS_PER_SEC;

    sprintf(print_buf, "Average as verification + plaintext recovery time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    // assert that the decryptions were successful
    for (int i = 0; i < repetitions; i++) {
        assert(compare_n_lsb(plaintexts[i], bit_2_byte_len(m), messages_enc[i], bit_2_byte_len(m), m) == 0);
    }

    for (int i = 0; i < repetitions; i++) {
        free(messages_enc[i]);
        free(signatures[i]);
        free(plaintexts[i]);
        EC_POINT_free(rs[i]);
    }

    lut_free(lut, m, C);
}

void rs_benchmark(int m, int repetitions, BIGNUM* y, EC_GROUP* group, EVP_PKEY* signing_key, EVP_PKEY* encryption_key) {
    char print_buf[200];
    const char dkey[] = "dual key";

    // create messages to sign;
    // and messages to encrypt
    char messages[repetitions][20];
    char* messages_enc[repetitions];
    for (int i = 0; i < repetitions; i++) {
        sprintf(messages[i], "Message: %d", i);
        messages_enc[i] = get_random_bits(m);
    }

    // store signatures for verifications
    char* signatures[repetitions];
    int signature_lens[repetitions];

    // benchmark loop
    time_t now = clock();
    for (int i = 0; i < repetitions; i++) {
        // just sign
        signatures[i] =  ecdsa_rs_sign(signing_key, messages[i], &signature_lens[i], encryption_key, messages_enc[i], bit_2_byte_len(m), m);
    }

    double t = (double)(clock() - now) / CLOCKS_PER_SEC;
    sprintf(print_buf, "Average rs_sign time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    // verify signatures, recover plaintexts
    EC_POINT* rs[repetitions];
    char* plaintexts[repetitions];
    memset(rs, 0, repetitions*sizeof(EC_POINT*));

    now = clock();
    for (int i = 0; i < repetitions; i++) {
        assert(ecdsa_verify_full(signing_key, messages[i], signatures[i], signature_lens[i], &rs[i]) == 1);
        plaintexts[i] = rs_decrypt(m, rs[i], y, group);
    }
    t = (double)(clock() - now) / CLOCKS_PER_SEC;

    sprintf(print_buf, "Average rs verification + plaintext recovery time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    // assert that the decryptions were successful
    for (int i = 0; i < repetitions; i++) {
        assert(compare_n_lsb(plaintexts[i], bit_2_byte_len(m), messages_enc[i], bit_2_byte_len(m), m) == 0);
    }

    for (int i = 0; i < repetitions; i++) {
        free(messages_enc[i]);
        free(signatures[i]);
        free(plaintexts[i]);
        EC_POINT_free(rs[i]);
    }
}

void ecdsa_benchmark(int repetitions, EVP_PKEY* signing_key) {
    char print_buf[200];
    const char dkey[] = "dual key";

    // create messages to sign;
    char messages[repetitions][20];
    for (int i = 0; i < repetitions; i++) {
        sprintf(messages[i], "Message: %d", i);
    }

    // store signatures for verifications
    char* signatures[repetitions];
    int signature_lens[repetitions];

    // benchmark loop
    time_t now = clock();
    for (int i = 0; i < repetitions; i++) {
        // just sign
        signatures[i] =  ecdsa_sign_evp(signing_key, messages[i], &signature_lens[i]);
    }

    double t = (double)(clock() - now) / CLOCKS_PER_SEC;
    sprintf(print_buf, "Average ecdsa_sign time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    // verify signatures
    now = clock();
    for (int i = 0; i < repetitions; i++) {
        assert(ecdsa_verify_evp(signing_key, messages[i], signatures[i], signature_lens[i]) == 1);
    }
    t = (double)(clock() - now) / CLOCKS_PER_SEC;

    sprintf(print_buf, "Average ecdsa verification time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    for (int i = 0; i < repetitions; i++) {
        free(signatures[i]);
    }
}

int main(int argc, char* argv[]) {  
    set_verbose(LOG_INFO);
    
    int arg_benchmark_as = 0;
    int arg_benchmark_rs = 0;
    int arg_benchmark_ecdsa = 0;
    int arg_m_as = 0;
    int arg_m_rs = 0;
    int arg_C = 0;
    char print_buf[200];
    

    // run all benchmarks
    if (argc < 2) {
        arg_benchmark_as = 1;
        arg_benchmark_rs = 1;
        arg_benchmark_ecdsa = 1;
    }
    else {
        for(int i = 1; i < argc; i++){
            if(argv[i][0] == '-') {
                int inp_err = 0;
                const char* arg = &argv[i][1];

                // -ac
                if (arg[0] == 'a') {
                    arg_benchmark_as = 1;
                    // m specified
                    if (i + 1 < argc && argv[i+1][0] != '-') {
                        arg_m_as = atoi(argv[i+1]);
                        if (arg_m_as > 16 || arg_m_as < 0) {
                            inp_err = 1;
                            printf("Error: use 0 < m < 17\n");
                        }
                    }
                    // C specified
                    if (i + 2 < argc && argv[i+2][0] != '-') {
                        arg_C = atoi(argv[i+2]);
                        if (arg_C < 0) {
                            inp_err = 1;
                            printf("Error: use C >= 0\n");
                        }
                    }
                }
                else if (arg[0] == 'r') {
                    arg_benchmark_rs = 1;
                    // m specified
                    if (i + 1 < argc && argv[i+1][0] != '-') {
                        arg_m_rs = atoi(argv[i+1]);
                        if (arg_m_rs > 16 || arg_m_rs < 0) {
                            inp_err = 1;
                            printf("Error: use 0 < m < 17\n");
                        }
                    }
                }
                else if (arg[0] == 'e') {
                    arg_benchmark_ecdsa = 1;
                }
                else if (arg[0] == 'v') {
                    set_verbose(LOG_DBG);
                }
                else if (arg[0] != 'h'){
                    inp_err = 1;
                    printf("Unknown argument.\n");
                }
                // -help or -h
                if (inp_err || arg[0] == 'h') {
                    printf("%s usage: [-as (m) (C)] [-rs] [-ecdsa] [-v]\n", argv[0]);
                    printf("\t-ac: run advanced sampling benchmark. If m or C are omitted or 0, run for m = [1-16] and C = [3-20].\n");
                    printf("\t-rs: run rejection sampling benchmark. If m is omitted or 0, run for m = [1-16] \n");
                    printf("\t-ecdsa: run pure ecdsa benchmark.\n");
                    printf("\t-v: verbose (debug) mode - warning: its VERY verbose\n");
                    printf("If all arguments (besides -v) are omitted then all tests with all param values are run.\n");
                    printf("ex. usage:\n");
                    printf("\t%s -as 0 10 -rs -ecdsa\n", argv[0]);
                    return 0;

                } 
            }
        }
    }

    // debug arguments
    printf("%d %d %d %d %d %d\n", arg_benchmark_as, arg_m_as, arg_C, arg_benchmark_rs, arg_m_rs, arg_benchmark_ecdsa);

    logger(LOG_INFO, "Generating signing keys...", "BNCH");

    EVP_PKEY* signing_key = EVP_PKEY_new();
    EC_POINT* X = NULL;
    BIGNUM* x = NULL;
    EC_GROUP* group_1 = NULL;

    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1);
    EVP_PKEY_keygen(ctx, &signing_key);

    EVP_PKEY_CTX_free(ctx);
    parse_evp_pkey(signing_key, &group_1, &X, &x);

    EVP_PKEY* encryption_key = EVP_PKEY_new();
    EC_POINT* Y = NULL;
    BIGNUM* y = NULL;
    EC_GROUP* group_2 = NULL;

    // encryption key
    if (arg_benchmark_as || arg_benchmark_rs) {
        logger(LOG_INFO, "Generating encryption keys...", "BNCH");
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1);
        EVP_PKEY_keygen(ctx, &encryption_key);

        EVP_PKEY_CTX_free(ctx);
        parse_evp_pkey(encryption_key, &group_2, &Y, &y);
    }

    logger(LOG_INFO, "Keys generated", "BNCH");

    int repetitions = 1000;

    if (arg_benchmark_as) {
        // try all params
        if (arg_m_as == 0){
            for(int i = 1; i < 17; i++) {
                // not recommended
                if (arg_C == 0) {
                    for(int j = 3; j < 21; j++) {
                        sprintf(print_buf, "Starting as_benchmark with: m=%d, C=%d, repetitions=%d", i, j, repetitions);
                        logger(LOG_INFO, print_buf, "BNCH");
                        as_benchmark(i, j, repetitions, Y, y, group_2, signing_key, encryption_key);
                    }
                }
                else {
                    sprintf(print_buf, "Starting as_benchmark with: m=%d, C=%d, repetitions=%d", i, arg_C, repetitions);
                    logger(LOG_INFO, print_buf, "BNCH");
                    as_benchmark(i, arg_C, repetitions, Y, y, group_2, signing_key, encryption_key); 
                }
                               
            }
        }
        else if (arg_C == 0) {
            for(int j = 3; j < 21; j++) {
                sprintf(print_buf, "Starting as_benchmark with: m=%d, C=%d, repetitions=%d", arg_m_as, j, repetitions);
                logger(LOG_INFO, print_buf, "BNCH");
                as_benchmark(arg_m_as, j, repetitions, Y, y, group_2, signing_key, encryption_key);
            }
        }
        else {
            sprintf(print_buf, "Starting as_benchmark with: m=%d, C=%d, repetitions=%d", arg_m_as, arg_C, repetitions);
            logger(LOG_INFO, print_buf, "BNCH");
            as_benchmark(arg_m_as, arg_C, repetitions, Y, y, group_2, signing_key, encryption_key);
        }

    }

    // rs_sign tends to be very slow for b >= 12
    // as its time complexity is O(2^b)
    repetitions = 100;

    if (arg_benchmark_rs) {
        if (arg_m_rs == 0){
            for(int i = 1; i < 17; i++) {
                sprintf(print_buf, "Starting rs_benchmark with: m=%d, repetitions=%d", i, repetitions);
                logger(LOG_INFO, print_buf, "BNCH");
                rs_benchmark(i, repetitions, y, group_2, signing_key, encryption_key);
            }
        }
        else {
            sprintf(print_buf, "Starting rs_benchmark with: m=%d, repetitions=%d", arg_m_rs, repetitions);
            logger(LOG_INFO, print_buf, "BNCH");
            rs_benchmark(arg_m_rs, repetitions, y, group_2, signing_key, encryption_key);
        }
    }

    repetitions = 1000;

    if (arg_benchmark_ecdsa) {
        ecdsa_benchmark(repetitions, signing_key);
    }

    EVP_PKEY_free(signing_key);
    EVP_PKEY_free(encryption_key);
    EC_POINT_free(X);
    BN_free(x);
    EC_GROUP_free(group_1);
    if (Y) EC_POINT_free(Y);
    if (y) BN_free(y);
    if (group_2) EC_GROUP_free(group_2);

    return 0;
}