#include "utils.h"
#include "logger/logger.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>


char* chr_2_hex(const char* bytes, size_t len) {
    const char hex[] = "0123456789ABCDEF";

    static char result[255];
    result[0] = '\0';

    // very lazy
    for (int i = 0; i < (int)len && 1 < 255; ++i) {
        char byte[3];
        byte[0] = hex[(unsigned char)bytes[i] >> 4]; // upper nibble
        byte[1] = hex[(unsigned char)bytes[i] & (0b1111)]; // lower nibble
        byte[2] = '\0';
        strcat(result, byte);
    }
    result[2*len] = '\0';

    return result;
}

/* \return 0 if n least significant bits of a and b are the same and 1 otherwise*/
int compare_n_lsb(const char* a, size_t len_a, const char* b, size_t len_b, int n) {
    int bytes_to_check = n/8 + 1;

    // for first byte check only remainder bits
    int remainder = n % 8;

    unsigned char first_byte_a = a[len_a - bytes_to_check];
    unsigned char first_byte_b = b[len_b - bytes_to_check];

    int mask = (1 << remainder) - 1;

    int comparison = (first_byte_a & mask) ^ (first_byte_b & mask);

    for (int i = 1; i < bytes_to_check; ++i) {
        int index_a = len_a - bytes_to_check + i;
        int index_b = len_b - bytes_to_check + i;

        int c = a[index_a] ^ b[index_b];
        comparison = comparison | c;
    }

    return comparison != 0;
}

char* hash(const char** inputs, int inputs_arr_len, const int* inputs_lens, int* digest_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

    if (mdctx == NULL) {
        logger(LOG_ERR, "Hashing context creation failed", "RS");
        return NULL;
    }

	int ok;
	const EVP_MD* algo = EVP_sha3_256();

    ok = EVP_DigestInit_ex(mdctx, algo, NULL);
    if (ok <= 0) {
        EVP_MD_CTX_destroy(mdctx);
        logger(LOG_ERR, "Digest initialization failed", "RS");
        return NULL;
    }

    for (int i = 0; i < inputs_arr_len; ++i) {
        int l = inputs_lens[i];
        ok = EVP_DigestUpdate(mdctx, inputs[i], l);
        if (ok <= 0) {
            EVP_MD_CTX_destroy(mdctx);
            logger(LOG_ERR, "Digest update failed", "RS");
            return NULL;
        }
    }

    *digest_len = EVP_MD_size(algo);
    char* digest = (char*)malloc(*digest_len * sizeof(char));

    ok = EVP_DigestFinal_ex(mdctx, (unsigned char*)digest, (unsigned int*)digest_len);
    if (ok <= 0) {
        free(digest);
        EVP_MD_CTX_destroy(mdctx);
        logger(LOG_ERR, "Hash computation failed", "RS");
        return NULL;
    }
    EVP_MD_CTX_destroy(mdctx);

    return digest;
}

int parse_pem_key(const char* path, EVP_PKEY** pkey, int priv) {
    FILE* fp = NULL; 
    fp = fopen(path, "r");
    
    if (!fp) {
        logger(LOG_ERR, "Failed to open the PEM key file", "PK");
        return -1;
    }

    if (priv) {
        PEM_read_PrivateKey(fp, pkey, NULL, NULL);
    } 
    else {
        PEM_read_PUBKEY(fp, pkey, NULL, NULL);
    }

    fclose(fp);

    if (!pkey) {
        logger(LOG_ERR, "Failed read and parse PEM file", "PK");
        return -1;
    }

    return 1;
}

// I'm truly astonished by the fact that 
// there is a name2nid function in openssl
// but there is no nid2name
int name2nid(const char* name) {
    for(int i = 0; i < 2000; i++) {
        const char* cname = OSSL_EC_curve_nid2name(i);
        if (cname && strcmp(cname, name) == 0) {
            return i;
        }
    }
    return -1;
}

int parse_evp_pkey(const EVP_PKEY* pkey, EC_GROUP** group, EC_POINT** public_key, BIGNUM** private_key) {
    size_t len = 0;
    size_t p_len = 0;
    int ok;
    char* buffer = NULL;
    char print_buf[200];
    BN_CTX* ctx = BN_CTX_new();

    // get length of public key (it will be written to pkey_len)
    ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 100, &len);
    if (ok <= 0) {
        BN_CTX_free(ctx);
        logger(LOG_ERR, "Failed to get public key length", "PK");
        return -1;
    }
    buffer = (char*)malloc(len * sizeof(char));
   
    #define PK_CLEANUP\
        BN_CTX_free(ctx);\
        free(buffer);
    
    // get raw public key into the buffer
    ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, (unsigned char*)buffer, 1000, &p_len);
    if (ok <= 0) {
        PK_CLEANUP;
        logger(LOG_ERR, "Failed to get raw public key", "PK");
        return -1;
    }
    
    char group_name[50];
    ok = EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 50, NULL);
    if (ok <= 0) {
        PK_CLEANUP;
        logger(LOG_ERR, "Failed to get group name", "PK");
        return -1;
    }

    int group_nid = name2nid(group_name);

    sprintf(print_buf, "Curve name: %s, NID: %d", group_name, group_nid);
    logger(LOG_DBG, print_buf, "PK");
    
    *group = EC_GROUP_new_by_curve_name(group_nid);
    if (!*group) {
        PK_CLEANUP;
        logger(LOG_ERR, "Failed to get cerate a group from the group name", "PK");
        return -1;
    }

    // parse public key as point
    //EC_POINT_2
    //ok = EC_POINT_hex2point(*group, buffer, *public_key, ctx);
    *public_key = EC_POINT_new(*group);
    ok = EC_POINT_oct2point(*group, *public_key, (unsigned char*)buffer, p_len, ctx);
    if (ok <= 0) {
        PK_CLEANUP;
        logger(LOG_ERR, "Failed to parse public key as point", "PK");
        return -1;
    }

    sprintf(print_buf, "Public key: %s", chr_2_hex(buffer, len));
    logger(LOG_DBG, print_buf, "PK");

    // parse private key as bignum
    if (private_key) {
        if (!EVP_PKEY_can_sign(pkey)) {
            PK_CLEANUP;
            logger(LOG_ERR, "The key does not contain private key!", "PK");
            return -1;
        }

        ok = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, private_key);
        if (ok <= 0) {
            PK_CLEANUP;
            logger(LOG_ERR, "Failed to get private key", "PK");
            return -1;
        }

        sprintf(print_buf, "Private key: %s", BN_print_str(*private_key));
        logger(LOG_DBG, print_buf, "PK");
    }

    PK_CLEANUP;

    return 1;
}

char* BN_print_str(BIGNUM* a) {
    char* buffer;
    static char result[100]; 
    size_t buffer_size;

    FILE* file_stream = open_memstream(&buffer, &buffer_size);
    BN_print_fp(file_stream, a);
    fclose(file_stream); 

    strcpy(result, buffer);

    free(buffer);

    // return a static string
    return result;
}

int chr_cmp(const char* c1, const char* c2, int len) {
    while(len && (*c1 == *c2)) {
        c1++;
        c2++;
        len--;
    }
    return *(const unsigned char*)c1 - *(const unsigned char*)c2;
}

void swap(int* arr, int i, int j) {
    int tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
}

void chr_swap(char** arr, int i, int j) {
    char* tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
}

void chr_sort(char** arr,  int arr_len, int cmp_len, int* indices) {
    // if pointer indices is provided, returns an array of 
    // original indices in the sorted array
    // indices is expected to be allocated
    if (indices) {
        for (int i = 0; i < arr_len; ++i) {
            indices[i] = i;
        }
    }

    // bubble sort, the arrays are expected 
    // to be length 2 anyway
    for(int i = 0; i < arr_len - 1; i++){
        for(int j = 0; j < arr_len - i - 1; j++){
            if(chr_cmp(arr[i], arr[j+1], cmp_len) > 0){
                if (indices) {
                    swap(indices, i, j+1);
                }
                chr_swap(arr, i, j+1);
            }
        }
    }
}

int bit_2_byte_len(int bit_len) {
    return bit_len/8 + (bit_len % 8 != 0);
}

char* encode_point(EC_POINT* point, size_t* enc_len, EC_GROUP* group, BN_CTX* ctx) {
    char* buffer;
    size_t len = encoded_point_len(point, group, ctx);
    
    if (enc_len) {
        *enc_len = len;
    }

    buffer = (char*)malloc(len * sizeof(char));
    
    int ok = point_2_buffer(buffer, len, point, group, ctx);
    if (ok <= 0) {
        return NULL;
    }     

    return buffer;
} 

int recover_nth_lsbit(const char* arr, int len, int n) {
    int starting_index = len - 1 - n/8;
    int res = (arr[starting_index] >> (n%8)) & 1;
    return res;
}

void recover_n_lsbs(char* buffer, const char* arr, int len, int n) {
    int starting_index = len - n/8 - ((n % 8 != 0));
    
    for (int i = starting_index; i < len; ++i) {
        buffer[i - starting_index] = arr[i];
    }
    
    // recover the last n%8 bits if necessary
    // if 8|n then the bit mask is 1111 1111 
    buffer[0] = buffer[0] & ((1 << (n % 8 + 8 * (n % 8 == 0))) - 1);
}

char* recover_n_lsbs_str(const char* arr, int len, int n) {
    char* buffer;
    
    // If n is not divisible by 8, then we need 
    // to allocate one additional byte
    // and recover n%8 bits from it
    
    // It can be done with an if...
    // I like this trick more though
    // +1 len for \0
    int buffer_len = bit_2_byte_len(n) + 1;
    buffer = (char*)malloc((buffer_len) * sizeof(char));
    recover_n_lsbs(buffer, arr, len, n);

    buffer[buffer_len - 1] = '\0';

    return buffer;
}

void swap_endian(char* arr, int len) {
   for (size_t i = 0; i < len/2; i++) {
        char tmp = arr[i];
        arr[i] = arr[len - i - 1];
        arr[len - i - 1] = tmp;
    }
}

size_t recover_n_lsbs_size_t(const char* arr, int len, int n) {
    unsigned long actual_byte_len = bit_2_byte_len(n);
    unsigned long size = sizeof(size_t);

    if (actual_byte_len > size) {
        return (size_t)0;
    }


    char static_buffer[size];

    // fill buffer with 0s
    // could use memcpy here too I guess
    for (size_t i = 0; i < size; i++) {
        static_buffer[i] = 0;
    }

    // recover n bits and swap endianesses
    recover_n_lsbs(static_buffer, arr, len, n);
    swap_endian(static_buffer, actual_byte_len);

    size_t result = 0;

    // copy char array as size_t
    memcpy(&result, static_buffer, size);
    
    return result;
}

size_t encoded_point_len(EC_POINT* point, EC_GROUP* group, BN_CTX* ctx) {
    return EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
}

int point_2_buffer(char* buffer, size_t len, EC_POINT* point, EC_GROUP* group, BN_CTX* ctx) {
    int ok;

    ok = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)buffer, len, ctx);
 
    return ok;   
}

int save_to_file(const char* in, int in_len, const char* path) {
    FILE* f = fopen(path,"wb");

    if (!f) {
        return -1;
    }

    int ret = fwrite(in, sizeof(char), in_len, f);
    fclose(f);
    
    return ret;
}

char* read_from_file(const char* path, int* out_len) {
    FILE* f = fopen(path,"rb");

    if (!f) {
        return -1;
    }

    fseek(f, 0L, SEEK_END);
    int len = ftell(f);
    rewind(f);

    char* buf = (char*)malloc(len*sizeof(char));

    int ret = fread(buf, sizeof(char), len, f);
    fclose(f);
    
    if (ret < 0) {
        free(buf);
        return NULL;
    }

    *out_len = ret;
    return buf;
}