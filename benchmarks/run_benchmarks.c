#include "../src/algorithms/advanced_sampling.h"
#include "../src/algorithms/rejection_sampling.h"
#include "../src/anamorphic_ecdsa/ecdsa.h"
#include "../src/logger/logger.h"
#include "../src/utils.h"
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

void print_array(char* buf, const float* arr, int len) {
    for (int i = 0; i < len - 1; i++) {
        // size of each printed float will be 5 bytes - "X.XXX"
        // + n-1 "," so n*5 + (n-1) * 1 = 6*n - 1
        sprintf(buf, "%.3f,", arr[i]);
    }
    sprintf(buf, "%.3f", arr[len - 1]);
}

void print_array_fp(FILE* fp, const long* arr, int len) {
    for (int i = 0; i < len - 1; i++) {
        fprintf(fp, "%ld,", arr[i]);
    }
    fprintf(fp, "%ld", arr[len - 1]);
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

void get_lut_entries(BIGNUM*** lut, int m, int C, long* entries) {
    int rows = (1 << m);
    int columns = 2 * C;

    // long* entries = (long*)malloc(rows*sizeof(long));
    for (int i = 0; i < rows; i++) {
        entries[i] = 0;
    }

    for (int i = 0; i < rows; i ++) {
        for (int j = 0; j < columns; j++) {
            entries[i] += lut[i][j] != NULL;
        }
    }
}

// benchmark insertion and retrieval of LUT entries
void lut_balance_benchmark(int m, int C, int repetitions,
                  EC_POINT* Y, BIGNUM* y, EC_GROUP* group, 
                  EVP_PKEY* signing_key, EVP_PKEY* encryption_key, 
                  long* entries) {
    char print_buf[200];
    const char dkey[] = "dual key";

    BIGNUM*** lut = lut_new(m, C);
    as_fill(lut, m, C, dkey, strlen(dkey), Y, group);
    
    logger(LOG_INFO, "LUT filled", "BNCH");

    char* sign_message = (char*)malloc(100*sizeof(char));
    char* enc_message;

    for (int i = 0; i < repetitions; i++) {
        // prepare messages
        // we can do it in a loop because we don't need to store them
        // and we are not measuring the time 
        sprintf(sign_message, "Message: %d", i);
        enc_message = get_random_bits(m);

        char* signature;
        int signature_len;

        // insert
        as_insert(lut, m, C, 0, dkey, strlen(dkey), Y, group);
        // then sign
        signature = ecdsa_as_sign(signing_key, 
                            sign_message, strlen(sign_message), 
                            &signature_len, encryption_key, 
                            enc_message, bit_2_byte_len(m), 
                            dkey, strlen(dkey), 
                            sign_message, strlen(sign_message), 
                            m, C, lut);

        EC_POINT* rs = EC_POINT_new(group);

        // verify signatures, recover plaintexts
        assert(ecdsa_verify_full(signing_key, sign_message, strlen(sign_message), signature, signature_len, &rs) == 1);
        char* plaintext = as_decrypt(m, sign_message, strlen(sign_message), dkey, strlen(dkey), rs, y, group);

        // assert that the decryptions were successful
        assert(compare_n_lsb(plaintext, bit_2_byte_len(m), enc_message, bit_2_byte_len(m), m) == 0);

        EC_POINT_free(rs);
        free(plaintext);
        free(signature);
        free(enc_message);
    }

    logger(LOG_INFO, "Signing done.", "BNCH");

    // get number of entries in each row
    get_lut_entries(lut, m, C, entries);

    free(sign_message);
}

void as_benchmark(int m, int C, int repetitions, 
                  EC_POINT* Y, BIGNUM* y, EC_GROUP* group, 
                  EVP_PKEY* signing_key, EVP_PKEY* encryption_key, 
                  float* fill_time, long long* lut_size, float* sign_time, float* verify_time) {
    char print_buf[200];
    const char dkey[] = "dual key";

    BIGNUM*** lut = lut_new(m, C);

    clock_t now = clock();
    as_fill(lut, m, C, dkey, strlen(dkey), Y, group);

    double t = (double)(clock() - now) / CLOCKS_PER_SEC;

    sprintf(print_buf, "as_fill time: %.3f ms", t*1000);
    logger(LOG_INFO, print_buf, "BNCH");

    *fill_time = t*1000;

    long long size = get_lut_size(lut, m, C);
    sprintf(print_buf, "Filled LUT size: %u bytes", size);
    logger(LOG_INFO, print_buf, "BNCH");

    *lut_size = size;

    // create messages to sign;
    // and messages to encrypt
    char messages[repetitions][20];
    char* messages_enc[repetitions];
    for (int i = 0; i < repetitions; i++) {
        sprintf(messages[i], "Message: %d", i);
        messages_enc[i] = get_random_bits(m);
    }

    // store signatures for verification
    char* signatures[repetitions];
    int signature_lens[repetitions];

    // benchmark loop
    now = clock();
    for (int i = 0; i < repetitions; i++) {
        // insert
        as_insert(lut, m, C, 0, dkey, strlen(dkey), Y, group);
        // then sign
        signatures[i] = ecdsa_as_sign(signing_key, 
                            messages[i], strlen(messages[i]), 
                            &signature_lens[i], encryption_key, 
                            messages_enc[i], bit_2_byte_len(m), 
                            dkey, strlen(dkey), 
                            messages[i], strlen(messages[i]), 
                            m, C, lut);
    }

    t = (double)(clock() - now) / CLOCKS_PER_SEC;
    sprintf(print_buf, "Average as_sign time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    *sign_time = t*1000/(double)repetitions;

    // verify signatures, recover plaintexts
    EC_POINT* rs[repetitions];
    char* plaintexts[repetitions];
    memset(rs, 0, repetitions*sizeof(EC_POINT*));

    now = clock();
    for (int i = 0; i < repetitions; i++) {
        assert(ecdsa_verify_full(signing_key, messages[i], strlen(messages[i]), signatures[i], signature_lens[i], &rs[i]) == 1);
        plaintexts[i] = as_decrypt(m, messages[i], strlen(messages[i]), dkey, strlen(dkey), rs[i], y, group);
    }
    t = (double)(clock() - now) / CLOCKS_PER_SEC;

    sprintf(print_buf, "Average as verification + plaintext recovery time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    *verify_time = t*1000/(double)repetitions;

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

void rs_benchmark(int m, int repetitions, 
                  BIGNUM* y, EC_GROUP* group, 
                  EVP_PKEY* signing_key, EVP_PKEY* encryption_key,
                  float* sign_time, float* verify_time) {
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
        signatures[i] =  ecdsa_rs_sign(signing_key, messages[i], strlen(messages[i]), &signature_lens[i], encryption_key, messages_enc[i], bit_2_byte_len(m), m);
    }

    double t = (double)(clock() - now) / CLOCKS_PER_SEC;
    sprintf(print_buf, "Average rs_sign time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    *sign_time = t*1000/(double)repetitions;

    // verify signatures, recover plaintexts
    EC_POINT* rs[repetitions];
    char* plaintexts[repetitions];
    memset(rs, 0, repetitions*sizeof(EC_POINT*));

    now = clock();
    for (int i = 0; i < repetitions; i++) {
        assert(ecdsa_verify_full(signing_key, messages[i], strlen(messages[i]), signatures[i], signature_lens[i], &rs[i]) == 1);
        plaintexts[i] = rs_decrypt(m, rs[i], y, group);
    }
    t = (double)(clock() - now) / CLOCKS_PER_SEC;

    sprintf(print_buf, "Average rs verification + plaintext recovery time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    *verify_time = t*1000/(double)repetitions;

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

void ecdsa_benchmark(int repetitions, EVP_PKEY* signing_key, float* sign_time, float* verify_time) {
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
        signatures[i] =  ecdsa_sign_evp(signing_key, messages[i], strlen(messages[i]), &signature_lens[i]);
    }

    double t = (double)(clock() - now) / CLOCKS_PER_SEC;
    sprintf(print_buf, "Average ecdsa_sign time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    *sign_time = t*1000/(double)repetitions;

    // verify signatures
    now = clock();
    for (int i = 0; i < repetitions; i++) {
        assert(ecdsa_verify_evp(signing_key, messages[i], strlen(messages[i]), signatures[i], signature_lens[i]) == 1);
    }
    t = (double)(clock() - now) / CLOCKS_PER_SEC;

    sprintf(print_buf, "Average ecdsa verification time: %.3f ms for %d repetitions", t*1000/(double)repetitions, repetitions);
    logger(LOG_INFO, print_buf, "BNCH");

    *verify_time = t*1000/(double)repetitions;

    for (int i = 0; i < repetitions; i++) {
        free(signatures[i]);
    }
}

int main(int argc, char* argv[]) {  
    set_verbose(LOG_INFO);
    
    int arg_benchmark_as = 0;
    int arg_benchmark_rs = 0;
    int arg_benchmark_ecdsa = 0;
    int arg_benchmark_lut = 0;

    int arg_m_as = 0;
    int arg_m_rs = 0;
    int arg_m_lut = 0;
    int arg_C = 0;
    int arg_C_lut = 0;
    char print_buf[200];

    // run all benchmarks
    if (argc < 2) {
        arg_benchmark_as = 1;
        arg_benchmark_rs = 1;
        arg_benchmark_ecdsa = 1;
        arg_benchmark_lut = 1;
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
                else if (arg[0] == 'l') {
                    arg_benchmark_lut = 1;
                    // m specified
                    if (i + 1 < argc && argv[i+1][0] != '-') {
                        arg_m_lut = atoi(argv[i+1]);
                        if (arg_m_lut > 16 || arg_m_lut < 0) {
                            inp_err = 1;
                            printf("Error: use 0 < m < 17\n");
                        }
                    }
                    // C specified
                    if (i + 2 < argc && argv[i+2][0] != '-') {
                        arg_C_lut = atoi(argv[i+2]);
                        if (arg_C_lut < 0) {
                            inp_err = 1;
                            printf("Error: use C >= 0\n");
                        }
                    }
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
                    printf("%s usage: [-as (m) (C)] [-rs] [-ecdsa] [-lut (m) (C)] [-v]\n", argv[0]);
                    printf("\t-ac: run advanced sampling benchmark. If m or C are omitted or 0, run for m = [1-16] and C = [3-20].\n");
                    printf("\t-rs: run rejection sampling benchmark. If m is omitted or 0, run for m = [1-16] \n");
                    printf("\t-ecdsa: run pure ecdsa benchmark.\n");
                    printf("\t-lut: run LUT balance benchmark. If m or C are omitted, run for m = [1-16] and C = 5.\n");
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
    if (arg_benchmark_as || arg_benchmark_rs || arg_benchmark_lut) {
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
        int start_m = 1;
        int end_m = 17;
        int variable_M = 1;

        // if m is specified from params, only run for that m
        if (arg_m_as){
            start_m = arg_m_as;
            end_m = arg_m_as + 1;
            variable_M = 0;
        }

        int start_C = 3;
        int end_C = 21;
        int variable_C = 1;

        // if C is specified from params, only run for that C
        if (arg_C) {
            start_C = arg_C;
            end_C = arg_C + 1;
            variable_C = 0;
        } 

        float sign_time_results[(end_m - start_m) * (end_C - start_C)];
        long long lut_size_results[(end_m - start_m) * (end_C - start_C)];
        float fill_time_results[(end_m - start_m) * (end_C - start_C)];
        float verify_time_results[(end_m - start_m) * (end_C - start_C)];

        char names[(end_m - start_m) * (end_C - start_C)][100];

        for(int m = start_m; m < end_m; m++) {
            for(int C = start_C; C < end_C; C++/* heh */) {
                int current_m = m - start_m;
                int current_C = C - start_C;
                int current_index = current_m*(end_C - start_C) + current_C;

                sprintf(print_buf, "Starting as_benchmark with: m=%d, C=%d, repetitions=%d", m, C, repetitions);
                sprintf(names[current_index], "%d,%d", m, C);
                logger(LOG_INFO, print_buf, "BNCH");
                as_benchmark(m, C, repetitions, Y, y, group_2, signing_key, encryption_key, 
                             &fill_time_results[current_index], 
                             &lut_size_results[current_index], 
                             &sign_time_results[current_index], 
                             &verify_time_results[current_index]);
            }       
        }

        for(int i = 0; i < (end_m - start_m) * (end_C - start_C); i++) {
            sprintf(print_buf, "Results for as m,c=%s: fill_time=%.3f, lut_size=%lld, sign_time=%.3f, verify_time=%.3f", 
                    names[i], fill_time_results[i], lut_size_results[i], sign_time_results[i], verify_time_results[i]);
            logger(LOG_INFO, print_buf, "BNCH");
        }

        FILE* fp;
        if (variable_C) {
            fp = fopen("as_var_C_benchmark_results.out", "w");
        } else if (variable_M) {
            fp = fopen("as_var_M_benchmark_results.out", "w");
        } else {
            fp = fopen("as_benchmark_results.out", "w");
        }
        
        if (fp == NULL) {
            logger(LOG_ERR, "Error opening file for writing", "BNCH");
            return 1;
        }

        fprintf(fp, "m,C,fill_time,lut_size,sign_time,verify_time\n");
        for(int i = 0; i < (end_m - start_m) * (end_C - start_C); i++) {
            fprintf(fp, "%s,%.3f,%lld,%.3f,%.3f\n", names[i], fill_time_results[i], lut_size_results[i], sign_time_results[i], verify_time_results[i]);
        }
        fclose(fp);
    }

    repetitions = 1000;

    if (arg_benchmark_rs) {
        int start_m = 1;
        int end_m = 17;

        // if m is specified from params, only run for that m
        if (arg_m_rs){
            start_m = arg_m_rs;
            end_m = arg_m_rs + 1;
        }

        float sign_time_results[end_m - start_m];
        float verify_time_results[end_m - start_m];

        for(int m = start_m; m < end_m; m++) {
            sprintf(print_buf, "Starting rs_benchmark with: m=%d, repetitions=%d", m, repetitions);
            logger(LOG_INFO, print_buf, "BNCH");
            rs_benchmark(m, repetitions, y, group_2, signing_key, encryption_key, 
                         &sign_time_results[m - start_m], 
                         &verify_time_results[m - start_m]);
        } 

        for (int i = 0; i < end_m - start_m; i++) {
            sprintf(print_buf, "Results for rs m=%d: sign_time=%.3f, verify_time=%.3f", 
                    i + start_m, sign_time_results[i], verify_time_results[i]);
            logger(LOG_INFO, print_buf, "BNCH");
        }

        FILE* fp = fopen("rs_benchmark_results.out", "w");
        if (fp == NULL) {
            logger(LOG_ERR, "Error opening file for writing", "BNCH");
            return 1;
        }
        
        fprintf(fp, "m,sign_time,verify_time\n");
        for (int i = 0; i < end_m - start_m; i++) {
            fprintf(fp, "%d,%.3f,%.3f\n", i + start_m, sign_time_results[i], verify_time_results[i]);
        }
        fclose(fp);
    }

    repetitions = 1000;

    if (arg_benchmark_ecdsa) {
        float sign_time;
        float verify_time;

        ecdsa_benchmark(repetitions, signing_key, &sign_time, &verify_time);

        sprintf(print_buf, "Results for ecdsa: sign_time=%.3f, verify_time=%.3f", sign_time, verify_time);
        logger(LOG_INFO, print_buf, "BNCH");

        FILE* fp = fopen("ecdsa_benchmark_results.out", "w");
        if (fp == NULL) {
            logger(LOG_ERR, "Error opening file for writing", "BNCH");
            return 1;
        }

        fprintf(fp, "sign_time,verify_time\n");
        fprintf(fp, "%.3f,%.3f\n", sign_time, verify_time);
        fclose(fp);
    }

    if (arg_benchmark_lut) {
        repetitions = 100000;

        int start_m = 1;
        int end_m = 17;

        if (arg_m_lut){
            start_m = arg_m_lut;
            end_m = arg_m_lut + 1;
        }


        int start_C = 5;
        int end_C = 6;

        if (arg_C_lut) {
            start_C = arg_C_lut;
            end_C = arg_C_lut + 1;
        } 
        
        long* entries_results[(end_m - start_m) * (end_C - start_C)];

        for (int m = start_m; m < end_m; m++) {
            for (int C = start_C; C < end_C; C++) {
                int current_m = m - start_m;
                int current_C = C - start_C;
                int current_index = current_m*(end_C - start_C) + current_C;

                sprintf(print_buf, "Starting lut_balance_benchmark with: m=%d, C=%d, repetitions=%d", m, C, repetitions);
                logger(LOG_INFO, print_buf, "BNCH");
                long* entries = (long*)malloc((1 << m)*sizeof(long));
                entries_results[current_index] = entries;

                lut_balance_benchmark(m, C, repetitions, Y, y, group_2, signing_key, encryption_key, entries);

                for (int i = 0; i < (1 << m); i++) {
                    if (entries[i] == 0) {
                        sprintf(print_buf, "empty LUT row for m=%d, C=%d, row=%d: %ld entries", m, C, i, entries[i]);
                        logger(LOG_INFO, print_buf, "BNCH");
                    }
                }
            }
        }

        FILE* fp = fopen("lut_balance_benchmark_results.out", "w");
        if (fp == NULL) {
            logger(LOG_ERR, "Error opening file for writing", "BNCH");
            return 1;
        }

        fprintf(fp, "m,C,[entries]\n");
        for (int m = start_m; m < end_m; m++) {
            for (int C = start_C; C < end_C; C++) {
                int current_m = m - start_m;
                int current_C = C - start_C;
                int current_index = current_m*(end_C - start_C) + current_C;

                sprintf(print_buf, "%d,%d,[", m, C);
                fprintf(fp, "%s", print_buf);
                print_array_fp(fp, entries_results[current_index], 1 << m);
                fprintf(fp, "]\n");

                free(entries_results[current_index]);
            }
        }

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