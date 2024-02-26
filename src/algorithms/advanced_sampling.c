#include "advanced_sampling.h"
#include "../logger/logger.h"
#include <openssl/rand.h>
#include "../utils.h"
#include "../../dependencies/Format-Preserving-Encryption/src/fpe.h"

#define MIN(a,b) (((a)<(b))?(a):(b))


BIGNUM* as_encrypt(BIGNUM*** lut, int m, int C, const char* msg, int msg_len, const char* delta, int delta_len, const char* dkey, int dkey_len, const EC_POINT* Y, EC_GROUP* group) {
    BIGNUM* minus_one = BN_new();
    BIGNUM* order = BN_new();
    BIGNUM* kappa;
    BN_CTX* ctx = BN_CTX_new();
    // w = amsg | m-1 
    char* K = NULL;
    char print_buf[100];
    int K_len;
    int ok;

    #define AS_ENCRYPT_CLEANUP \
        BN_free(minus_one);\
        BN_free(order);\
        if (K != NULL) free(K);\
        BN_CTX_free(ctx);

    if (Y == NULL || group == NULL || m <= 0 || m > 16 || C <= 0 || delta == NULL || msg == NULL) {
        AS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Encryption parameters invalid or unspecified", "AS");
        return NULL;
    }

    // w = msg | m-1
    size_t w = recover_n_lsbs_size_t(msg, msg_len, m-1);
    // msb of amsg
    int msb = recover_nth_lsbit(msg, msg_len, m-1);

    // ----2 choices part----

    // hash the inputs and calculate encryption key 
    const char* hash_input[] = {delta, dkey, "01"};
    const int hash_input_lens[] = {delta_len, dkey_len, 3};
    K = hash(hash_input, 3, hash_input_lens, &K_len);

    logger(LOG_DBG, "K:", "AS");
    logger(LOG_DBG, chr_2_hex(K, K_len), "AS");

    // Set the FPE key
    FPE_KEY K_ff3;
    ok = FPE_set_ff3_key((unsigned char*)K, K_len * 8, (const unsigned char*)"tweak", (1 << m), &K_ff3);
    if (ok < 0) {
        AS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "FPE set key failed", "AS");
        return NULL;
    }

    // FPE encrypt
    unsigned int fpe_input[1] = {0};
    unsigned int fpe_output[1];
    unsigned int i0;
    unsigned int i1;
    
    
    // i0 = ENC(w || 0)
    fpe_input[0] = (w << 1);
    FPE_ff3_encrypt(fpe_input, fpe_output, 1, &K_ff3, FPE_ENCRYPT);
    i0 = fpe_output[0];
    // i0 = ENC(w || 1)
    fpe_input[0] = (w << 1) | 1;
    FPE_ff3_encrypt(fpe_input, fpe_output, 1, &K_ff3, FPE_ENCRYPT);
    i1 = fpe_output[0];

    FPE_unset_ff1_key(&K_ff3);

    int free_slots_i0 = lut_free_slots_row(lut[i0], C);
    int free_slots_i1 = lut_free_slots_row(lut[i1], C);

    // if row i0 contains more entries than i1
    // or they contain the same number of entries and i0 < i1
    if (free_slots_i0 < free_slots_i1 || (free_slots_i0 == free_slots_i1 && i0 < i1)) {
        kappa = lut_pop(lut, C, i0);
        sprintf(print_buf, "Popping kappa from the row %d, free: %d (row %d: %d)", (int)i0, free_slots_i0, (int)i1, free_slots_i1);
        logger(LOG_DBG, print_buf, "AS");
    }
    // if row i1 contains more entries than i0
    // or they contain the same number of entries and i0 >= i1
    else {
        kappa = lut_pop(lut, C, i1);
        sprintf(print_buf, "Popping kappa from the row %d, free: %d (row %d: %d)", (int)i1, free_slots_i1, (int)i0, free_slots_i0);
        logger(LOG_DBG, print_buf, "AS");
    }

    if (!kappa) {
        AS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Could not pop kappa from the lookup table", "AS");
        return NULL;
    }

    logger(LOG_DBG, "kappa:", "AS");
    logger(LOG_DBG, BN_print_str(kappa), "AS");

    // ----2 rabbits part----
    EC_POINT* W = EC_POINT_new(group);
    EC_POINT* W_prim = EC_POINT_new(group);
    
    char* B0 = NULL;
    char* B1 = NULL;
    int digest_len;

    #define AS_2R_ENCRYPT_CLEANUP \
        EC_POINT_free(W);\
        EC_POINT_free(W_prim);\
        if (B0 != NULL) free(B0);\
        if (B1 != NULL) free(B1);
    
    int d;
    int b = msb;

    if (Y == NULL || group == NULL || m <= 0 || m > 16 || delta == NULL) {
        AS_2R_ENCRYPT_CLEANUP
        AS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Encryption parameters invalid or unspecified", "AS");
        return NULL;
    }

    ok = BN_dec2bn(&minus_one, "-1");
    if (ok <= 0) {
        AS_2R_ENCRYPT_CLEANUP
        AS_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Creating a BIGNUM -1 failed", "2R");
        return NULL;
    }

    ok = EC_GROUP_get_order(group, order, ctx);
    if (!ok) {
        AS_2R_ENCRYPT_CLEANUP;
        AS_ENCRYPT_CLEANUP
        logger(LOG_ERR, "Get order failed for provided group", "AS");
        return NULL;
    }

    // W = kappa * Y
    ok = EC_POINT_mul(group, W, NULL, Y, kappa, ctx);
    if (ok <= 0) {
        AS_2R_ENCRYPT_CLEANUP;
        AS_ENCRYPT_CLEANUP
        logger(LOG_ERR, "Calculating W = kappa*Y failed", "AS");
        return NULL;
    }    

    // W_prim = -1 * W
    EC_POINT_copy(W_prim, W);
    ok = EC_POINT_invert(group, W_prim, ctx);
    if (ok <= 0) {
        AS_2R_ENCRYPT_CLEANUP;
        AS_ENCRYPT_CLEANUP
        logger(LOG_ERR, "Calculating W_prim = -1 * W failed", "AS");
        return NULL;
    }

    EC_POINT* points[2] = {W, W_prim};
    char* hashes[2];
    // calculate hashes
    for (int i = 0; i < 2; i++) {
        size_t encoded_len;
        char* encoded = encode_point(points[i], &encoded_len, group, ctx);

        const char* hash_input_2r[] = {encoded, dkey, "10"};
        const int hash_input_2r_lens[] = {(int)encoded_len, dkey_len, 3};
        hashes[i] = hash(hash_input_2r, 3, hash_input_2r_lens, &digest_len);

        free(encoded);
    }
    
    B0 = hashes[0], B1 = hashes[1];

    // if B0 < B1 then d = 0 and 1 otherwise
    d = chr_cmp(B0, B1, digest_len) >= 0;

    AS_2R_ENCRYPT_CLEANUP;

    // ----finalize----

    // if b xor d == 0 then k = kappa
    // if b xor d == 1 then k = -kappa
    if ((b ^ d) != 0) { 
        ok = BN_mod_mul(kappa, kappa, minus_one, order, ctx);
        if (ok <= 0) {
            AS_ENCRYPT_CLEANUP;
            logger(LOG_ERR, "Get kappa' = -kappa failed ", "AS");
            return NULL;
        }
    }

    AS_ENCRYPT_CLEANUP;

    logger(LOG_DBG, "kappa:", "AS");
    logger(LOG_DBG, BN_print_str(kappa), "AS");

    return kappa;
}

char* as_decrypt(int m, const char* delta, int delta_len, const char* dkey, int dkey_len, EC_POINT*r, BIGNUM* y, EC_GROUP* group) {
    EC_POINT* W = EC_POINT_new(group);
    EC_POINT* W_prim = EC_POINT_new(group);
    char* K = NULL;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    char* B0 = NULL;
    char* B1 = NULL;
    int digest_len;
    size_t z;
    size_t w;
    char print_buf[100];

    int ok;

    #define AS_DECRYPT_CLEANUP \
        EC_POINT_free(W);\
        EC_POINT_free(W_prim);\
        BN_CTX_free(ctx);\
        BN_free(order);\
        if (B0) free(B0);\
        if (B1) free(B1);\
        if (K) free(K);
    
    int b;

    ok = EC_GROUP_get_order(group, order, ctx);
    if (!ok) {
        AS_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Get order failed for provided group", "AS");
        return NULL;
    }

    // W = kappa * Y = y*r
    ok = EC_POINT_mul(group, W, NULL, r, y, ctx);
    if (ok <= 0) {
        AS_2R_ENCRYPT_CLEANUP;
        logger(LOG_ERR, "Calculating W = y*r failed", "AS");
        return NULL;
    }    

    // W_prim = -1 * W
    EC_POINT_copy(W_prim, W);
    ok = EC_POINT_invert(group, W_prim, ctx);
    if (ok <= 0) {
        AS_DECRYPT_CLEANUP;
        logger(LOG_ERR, "Calculating W_prim = -1 * W failed", "AS");
        return NULL;
    }

    // parse points as bytes
    size_t bytes_lens_W[2];
    char* bytes_W[2] = {
        encode_point(W, &bytes_lens_W[0], group, ctx), 
        encode_point(W_prim, &bytes_lens_W[1], group, ctx)
    };

    // ----2 rabbits part----

    char* hashes[2];
    // calculate hashes
    for (int i = 0; i < 2; i++) {
        char* encoded = bytes_W[i];

        const char* hash_input[] = {encoded, dkey, "10"};
        const int hash_input_lens[] = {(int)bytes_lens_W[i], dkey_len, 3};
        hashes[i] = hash(hash_input, 3, hash_input_lens, &digest_len);
    }
    
    B0 = hashes[0], B1 = hashes[1];

    // if B0 < B1 then b = 0 and 1 otherwise
    b = chr_cmp(B0, B1, digest_len) >= 0;

    // ----2 choices part----

    // sort arrays
    size_t min_len = MIN(bytes_lens_W[0], bytes_lens_W[1]);
    chr_sort(bytes_W, 2, min_len, NULL);

    char* digest;

    // hash the inputs and calculate z
    const char* hash_input_z[] = {bytes_W[0], bytes_W[1], dkey, "00"};
    const int hash_input_z_lens[] = {(int)bytes_lens_W[0], (int)bytes_lens_W[1], dkey_len, 3};
    digest = hash(hash_input_z, 4, hash_input_z_lens, &digest_len);
    z = recover_n_lsbs_size_t(digest, digest_len, m);

    free(digest);
    for (int i = 0; i < 2; i++) free(bytes_W[i]);

    sprintf(print_buf, "Recovered z: %d", (int)z);
    logger(LOG_DBG, print_buf, "AS");

    // hash the inputs and calculate encryption key 
    int K_len;
    const char* hash_input[] = {delta, dkey, "01"};
    const int hash_input_lens[] = {delta_len, dkey_len, 3};
    K = hash(hash_input, 3, hash_input_lens, &K_len);

    logger(LOG_DBG, "K:", "AS");
    logger(LOG_DBG, chr_2_hex(K, K_len), "AS");

    // Set the FPE key
    FPE_KEY K_ff3;
    ok = FPE_set_ff3_key((unsigned char*)K, K_len * 8, "tweak", (1 << m), &K_ff3);
    if (ok < 0) {
        AS_DECRYPT_CLEANUP;
        logger(LOG_ERR, "FPE set key failed", "AS");
        return NULL;
    }

    unsigned int fpe_input[1] = {(unsigned int)z};
    unsigned int fpe_output[1];

    // FPE decrypt
    FPE_ff3_encrypt(fpe_input, fpe_output, 1, &K_ff3, FPE_DECRYPT);
    w = fpe_output[0];

    FPE_unset_ff1_key(&K_ff3);

    w = (w >> 1) | (b << (m - 1));

    sprintf(print_buf,  "Recovered msg: %lu", w);
    logger(LOG_DBG, print_buf, "AS");

    int size = sizeof(size_t);
    char* plaintext = (char*)malloc(size * sizeof(char));
    memcpy(plaintext, &w, size);
    swap_endian(plaintext, bit_2_byte_len(m));
    
    AS_DECRYPT_CLEANUP;

    return plaintext;
}

long long as_insert(BIGNUM*** lut, int m, int C, int C_hard_bound, const char* dkey, int dkey_len, EC_POINT* Y, EC_GROUP* group) {
    BIGNUM* kappa_zero = BN_secure_new();
    BIGNUM* kappa_one = BN_secure_new();
    BIGNUM* order = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* U = EC_POINT_new(group);
    EC_POINT* U_prim = EC_POINT_new(group);
    EC_POINT* V = EC_POINT_new(group);
    EC_POINT* V_prim = EC_POINT_new(group);
    int ok;
    size_t z_zero;
    size_t z_one;
    char print_buf[100];

    #define AS_INSERT_CLEANUP_NO_KAPPA \
        EC_POINT_free(U);\
        EC_POINT_free(U_prim);\
        EC_POINT_free(V);\
        EC_POINT_free(V_prim);\
        BN_CTX_free(ctx);\
        BN_free(order);

    #define AS_INSERT_CLEANUP \
        EC_POINT_free(U);\
        EC_POINT_free(U_prim);\
        EC_POINT_free(V);\
        EC_POINT_free(V_prim);\
        BN_CTX_free(ctx);\
        BN_free(order);\
        BN_free(kappa_zero);\
        BN_free(kappa_one);

    if (Y == NULL || group == NULL || dkey == NULL || lut == NULL || (unsigned long)m > sizeof(size_t)*8) {
        AS_INSERT_CLEANUP;
        logger(LOG_ERR, "Insert parameters invalid or unspecified", "AS");
        return -1;
    }    

    ok = EC_GROUP_get_order(group, order, ctx);
    if (!ok) {
        AS_INSERT_CLEANUP;
        logger(LOG_ERR, "Get order failed for provided group", "AS");
        return -1;
    }

    // kappa_zero <-R {0, order}
    ok = BN_priv_rand_range(kappa_zero, order);
    if (ok <= 0) {
        AS_INSERT_CLEANUP;
        logger(LOG_ERR, "Get random kappa failed", "AS");
        return -1;
    }

    // kappa_one := 2*kappa_zero mod q
    // Openssl documentation says to use lshift, so we do
    ok = BN_mod_lshift1(kappa_one, kappa_zero, order, ctx);
    if (ok <= 0) {
        AS_INSERT_CLEANUP;
        logger(LOG_ERR, "Calculating kappa_one failed", "AS");
        return -1;
    }

    // U = kappa_zero * Y
    ok = EC_POINT_mul(group, U, NULL, Y, kappa_zero, ctx);
    if (ok <= 0) {
        AS_INSERT_CLEANUP;
        logger(LOG_ERR, "Calculating U = kappa_zero*Y failed", "AS");
        return -1;
    }
    // U_prim = -1 * U
    EC_POINT_copy(U_prim, U);
    ok = EC_POINT_invert(group, U_prim, ctx);
    if (ok <= 0) {
        AS_INSERT_CLEANUP;
        logger(LOG_ERR, "Calculating U_prim = -1 * U failed", "AS");
        return -1;
    }

    // V = 2 * U
    ok = EC_POINT_dbl(group, V, U, ctx);
    if (ok <= 0) {
        AS_INSERT_CLEANUP;
        logger(LOG_ERR, "Calculating V = 2*U failed", "AS");
        return -1;
    }
    // V_prim = -1 * V
    EC_POINT_copy(V_prim, V);
    ok = EC_POINT_invert(group, V_prim, ctx);
    if (ok <= 0) {
        AS_INSERT_CLEANUP;
        logger(LOG_ERR, "Calculating V_prim = -1 * V failed", "AS");
        return -1;
    }

    // parse points as bytes
    size_t bytes_lens_U[2];
    size_t bytes_lens_V[2];
    char* bytes_U[2] = {
        encode_point(U, &bytes_lens_U[0], group, ctx), 
        encode_point(U_prim, &bytes_lens_U[1], group, ctx)
    };
    char* bytes_V[2] = {
        encode_point(V, &bytes_lens_V[0], group, ctx), 
        encode_point(V_prim, &bytes_lens_V[1], group, ctx)
    };

    // sort arrays
    size_t min_len = MIN(bytes_lens_U[0], bytes_lens_U[1]);
    chr_sort(bytes_U, 2, min_len, NULL);
    min_len = MIN(bytes_lens_V[0], bytes_lens_V[1]);
    chr_sort(bytes_V, 2, min_len, NULL);

    int digest_len;
    char* digest;

    // hash the inputs and calculate z_zero 
    const char* hash_input_z_zero[] = {bytes_U[0], bytes_U[1], dkey, "00"};
    const int hash_input_z_zero_lens[] = {(int)bytes_lens_U[0], (int)bytes_lens_U[1], dkey_len, 3};
    digest = hash(hash_input_z_zero, 4, hash_input_z_zero_lens, &digest_len);
    z_zero = recover_n_lsbs_size_t(digest, digest_len, m);

    free(digest);

    // hash the inputs and calculate z_one
    const char* hash_input_z_one[] = {bytes_V[0], bytes_V[1], dkey, "00"};
    const int hash_input_z_one_lens[] = {(int)bytes_lens_V[0], (int)bytes_lens_V[1], dkey_len, 3};
    digest = hash(hash_input_z_one, 4, hash_input_z_one_lens, &digest_len);
    z_one = recover_n_lsbs_size_t(digest, digest_len, m);

    for (int i = 0; i <2; i++) {
        free(bytes_U[i]);
        free(bytes_V[i]);
    }
    free(digest);

    // decide which row to use
    int z_zero_free_slots = lut_free_slots_row(lut[z_zero], C); 
    int z_one_free_slots = lut_free_slots_row(lut[z_one], C);

    sprintf(print_buf, "Free slots for (z0) %d: %d", (int)z_zero, (int)z_zero_free_slots);
    logger(LOG_DBG, print_buf, "AS");
    sprintf(print_buf, "Free slots for (z1) %d: %d", (int)z_one, (int)z_one_free_slots);
    logger(LOG_DBG, print_buf, "AS");

    size_t inserted_row;

    // if row z_zero contains fewer number of entries than z_one
    // or they contain the same number of entries and z_zero < z_one
    if (z_zero_free_slots > z_one_free_slots || (z_one_free_slots == z_zero_free_slots && z_zero < z_one)) {
        // if we have hard boundary on C and row has already
        // at least C elements, dont insert
        if (C_hard_bound && z_zero_free_slots <= C) {
            AS_INSERT_CLEANUP;
            sprintf(print_buf, "Skipping insert as row %d has only %d slots", (int)z_zero, z_zero_free_slots);
            logger(LOG_DBG, print_buf, "AS");
            return -1;
        }
        ok = lut_push(lut, C, z_zero, kappa_zero);
        sprintf(print_buf, "Inserting kappa_zero into the row %d", (int)z_zero);
        logger(LOG_DBG, print_buf, "AS");
        inserted_row = z_zero;
        BN_free(kappa_one);
        if (ok <= 0) {
            AS_INSERT_CLEANUP_NO_KAPPA;
            BN_free(kappa_zero);
            logger(LOG_ERR, "Failed to insert kappa into lookup table", "AS");
            return ok;
        }
    }
    // if row z_one contains fewer number of entries than z_zero
    // or they contain the same number of entries and z_zero >= z_one
    // (chances of z_zero == z_one should be negligible)
    else {
        if (C_hard_bound && z_one_free_slots <= C) {
            AS_INSERT_CLEANUP;
            sprintf(print_buf, "Skipping insert as row %d has only %d slots", (int)z_one, z_one_free_slots);
            logger(LOG_DBG, print_buf, "AS");
            return -1;
        }
        ok = lut_push(lut, C, z_one, kappa_one);
        sprintf(print_buf, "Inserting kappa_one into the row %d", (int)z_one);
        logger(LOG_DBG, print_buf, "AS");
        inserted_row = z_one;
        BN_free(kappa_zero);
        if (ok <= 0) {
            AS_INSERT_CLEANUP_NO_KAPPA;
            BN_free(kappa_one);
            logger(LOG_ERR, "Failed to insert kappa into lookup table", "AS");
            return ok;
        }
    }

    AS_INSERT_CLEANUP_NO_KAPPA;

    return inserted_row;
}

void as_fill(BIGNUM*** lut, int m, int C, const char* dkey, int dkey_len, EC_POINT* Y, EC_GROUP* group) {
    // assume that the table is empty
    size_t rows = (1 << m);

    // small optimization - we can track the number of empty slots
    // globally with a counter instead of checking the array
    // should not overflow as the upper boundary of m is 16 bits
    long long slots_to_fill = rows * C;

    while (slots_to_fill > 0) {
        // hard boundary on insert function to not insert anything into
        // rows containing C elements already
        long long inserted_row = as_insert(lut, m, C, 1, dkey, dkey_len, Y, group);
        
        if (inserted_row < 0) {
            // nothing was inserted
            logger(LOG_DBG, "Inserted nothing into the lookup table", "AS");
        }
        else {
            // decrement counter
            slots_to_fill--;
        }
    }
}

int lut_free_slots_row(BIGNUM** row, int C) {
    int res = 0;
    for (int i = 0; i < 2*C; i++) {
        res += (row[i] == NULL);
    }
    return res;
}

int lut_push(BIGNUM*** lut, int C, size_t row, BIGNUM* num) {
    // find first free column
    for(size_t j = 0; j < 2*(size_t)C; j++) {
        if (lut[row][j] == NULL) {
            lut[row][j] = num;
            return 1;
        }
    }

    return -1;
}

BIGNUM*** lut_new(int m, int C) {
    // 2^m
    size_t n_rows = ((size_t)1 << m);
    size_t n_row_elements = (size_t)C * 2;

    BIGNUM*** lut = (BIGNUM***)malloc(n_rows * sizeof(BIGNUM**));

    for(size_t i = 0; i < n_rows; i++) {
        lut[i] = (BIGNUM**)malloc(n_row_elements * sizeof(BIGNUM*));
        for (size_t j = 0; j < n_row_elements; j++) {
            lut[i][j] = NULL;
        }
    }

    return lut;
}

void lut_free(BIGNUM*** lut, int m, int C) {
    // 2^m
    size_t n_rows = ((size_t)1 << m);
    size_t n_row_elements = (size_t)C * 2;

    for(size_t i = 0; i < n_rows; i++) {
        for (size_t j = 0; j < n_row_elements; j++) {
            if (lut[i][j] != NULL) {
                BN_free(lut[i][j]);
            }
        }
        free(lut[i]);
    }
    free(lut);
}

BIGNUM* lut_pop(BIGNUM*** lut, int C, size_t row) {
    BIGNUM* res;

    for(long long j = 2*(size_t)C - 1; j >= 0; j--) {
        if (lut[row][j] != NULL) {
            res = lut[row][j];
            lut[row][j] = NULL;
            return res;
        }
    }

    return NULL;
}