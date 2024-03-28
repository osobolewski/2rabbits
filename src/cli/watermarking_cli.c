#include "../algorithms/advanced_sampling.h"
#include "../algorithms/rejection_sampling.h"
#include "../anamorphic_ecdsa/ecdsa.h"
#include "../logger/logger.h"
#include "../utils.h"
#include <assert.h>
#include <string.h>

#include <openssl/pem.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define HELP_ALL 0b111


void print_help(const char* prog_name, int print_mask) {
    printf("CLI tool for anamorphic watermarking/encryption for ECDSA signatures.\n");
    printf("\nUSAGE:");
    
    if (print_mask & 0b1) {
        printf("\n");
        printf("[1] Generate a lookup table for anamorphic encryption:\n\n");
        printf("%s [-v] g[enerate_lut] '/lut.out' '/path/to/enc_key.pub' (m) [C] 'dual_key'\n", prog_name);
        printf("\n\tPARAMS:\n");
        printf("\t[-v]: [OPTIONAL] verbose mode. [-vv] is debug mode\n");
        printf("\t'/lut.out': Save location of the generated lookup table.\n");
        printf("\t'/path/to/enc_key.pub': Path to PEM-encoded ECDSA public key used to encrypt the anamorphic message\n");
        printf("\t(m): Number of bits to be encrypted (width of the anamorphic channel). 0 < m < 32. Be careful as the size of the table is O(2^m)!\n");
        printf("\t[C]: [OPTIONAL] Number of records in a row of the lookup table. Default is 5\n");
        printf("\t'dual_key': String used as a dual key to encrypt the anamorphic message.\n");
        printf("Ex: %s g lut.out ./keys/ec-secp256k1-pub-key_enc.pem 8 5 'Secret dual key'\n", prog_name);
    }

    if (print_mask & 0b10) {
        printf("\n");
        printf("[2] Sign a message and encrypt an anamorphic watermark:\n\n%s [-v] s[ign] '/sign.bin' '/path/to/lut' '/path/to/sign_key.priv' '/path/to/enc_key.pub' '/path/to/sign_msg.txt' 'watermark' 'dual_key' ['delta']\n", prog_name);
        printf("\n\tPARAMS:\n");
        printf("\t[-v]: [OPTIONAL] verbose mode. [-vv] is debug mode\n");
        printf("\t'/sign.bin': Save location of the generated signature\n");
        printf("\t'/path/to/lut': Path to lookup table generated by the command 'g[enerate_table]'\n");
        printf("\t'/path/to/sign_key.priv': Path to PEM-encoded ECDSA signing key used to sign a message\n");
        printf("\t'/path/to/enc_key.pub': Path to PEM-encoded ECDSA public key used to encrypt 'watermark'\n");
        printf("\t'/path/to/sign_msg.txt': Path to file containing message to be signed with private key (can be binary)\n");
        printf("\t'watermark': Message to be encrypted inside of the signature\n");
        printf("\t'dual_key': String used as a dual key to encrypt the 'watermark'\n");
        printf("\t['delta']: [OPTIONAL] Public string to be used for encryption. Default is the timestamp of the signature\n");
        printf("Ex: %s s sign.bin lut.out ./keys/ec-secp256k1-priv-key.pem ./keys/ec-secp256k1-pub-key_enc.pem msg.test bb 'Secret dual key' 'Some unique public string 1'\n", prog_name);
    }

    if (print_mask & 0b100) {
        printf("\n");
        printf("[3] Decrypt an anamorphic message from the signature:\n\n%s [-v] d[ecrypt] '/path/to/sign_key.pub' '/path/to/enc_key.priv' '/path/to/sig.bin' '/path/to/sign_msg.txt' (m) 'dual_key' 'delta'\n", prog_name);
        printf("\n\tPARAMS:\n");
        printf("\t[-v]: [OPTIONAL] verbose mode. [-vv] is debug mode\n");
        printf("\t'/path/to/sign_key.pub': Path to PEM-encoded ECDSA signing key used to verify the 'message_to_verify'\n");
        printf("\t'/path/to/enc_key.priv': Path to PEM-encoded ECDSA private key used to decrypt the anamorphic message\n");
        printf("\t'/path/to/sig.bin': Path to file containing the signature to verify and decrypt from\n");
        printf("\t'/path/to/sign_msg.txt': Path to file containing message to be verified with the public key\n");
        printf("\t(m): Number of bits to be decrypted (width of the anamorphic channel). 0 < m < 32\n");
        printf("\t'dual_key': String used as a dual key to decrypt the anamorphic message\n");
        printf("\t'delta': Public string to be used for decryption. By default its the timestamp of the signature\n");
        printf("Ex: %s d ./keys/ec-secp256k1-pub-key.pem ./keys/ec-secp256k1-priv-key_enc.pem sign.bin msg.test 8 'Secret dual key' 'Some unique public string 1'\n", prog_name);
    }
}

int main(int argc, char *argv[]) {   
    set_verbose(LOG_WARN);
    if (argc < 2) {
        logger(LOG_ERR, "Incorrect number of arguments", "CLI");
        print_help(argv[0], HELP_ALL);
        return -1;
    }

    char buf[255];

    int start_index = 1;
    if (argv[1][0] == '-') {
        if (argc < 3) {
            logger(LOG_ERR, "Incorrect number of arguments", "CLI");
            print_help(argv[0], HELP_ALL);
            return -1;
        }
        int verbosity = MAX(LOG_WARN - ((int)strlen(argv[1]) - 1), 0);
        set_verbose(verbosity);
        sprintf(buf, "Verbosity set to %d", verbosity);
        logger(LOG_DBG, buf, "CLI");
        start_index++;
    }

    switch (argv[start_index][0])
    {
    case 'g':
        char* save_path;
        char* enc_key_path;
        int m;
        char* dual_key;
        int C = 0;

        switch (argc - start_index - 1)
        {
        case 4: // no C 
            C = 5;
        case 5:
            save_path = argv[start_index + 1];
            enc_key_path = argv[start_index + 2];
            m = strtol(argv[start_index+3], NULL, 10);
            if (!C) C = strtol(argv[start_index+4], NULL, 10);
            else start_index--;
            dual_key = argv[start_index + 5];

            break;
        default:
            logger(LOG_ERR, "Incorrect number of arguments", "CLI");
            print_help(argv[0], 0b1);
            return -1;
        }

        if (m <= 0 || m >= 32 || C <= 0) {
            logger(LOG_ERR, "Invalid m or C values", "CLI");
            return -1;
        }
        sprintf(buf, "m = %d, C = %d, dkey = %s", m, C, dual_key);
        logger(LOG_DBG, buf, "CLI");

        EVP_PKEY* enc_key = EVP_PKEY_new();
        FILE* fp = fopen(enc_key_path, "rb");

        if (!fp) {
            sprintf(buf, "Opening the file %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        logger(LOG_INFO, "Decoding the key from PEM...", "CLI");
        if (!PEM_read_PUBKEY(fp, &enc_key, NULL, NULL)){
            sprintf(buf, "Loading the public key %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        fclose(fp);

        EC_GROUP* group = NULL;
        EC_POINT* public_key = NULL;

        logger(LOG_INFO, "Parsing the EVP key...", "CLI");
        if (parse_evp_pkey(enc_key, &group, &public_key, NULL) <= 0) {
            sprintf(buf, "Parsing the evp key %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;   
        }

        logger(LOG_INFO, "Creating and filling the lookup table...", "CLI");
        BIGNUM*** lut = lut_new(m, C);
        as_fill(lut, m, C, dual_key, strlen(dual_key), public_key, group);

        logger(LOG_INFO, "Serializing the lookup table...", "CLI");
        char* lut_serialized = NULL;
        unsigned int len;
        if (lut_serialize(lut, m, C, NULL, &len) < 0) {
            logger(LOG_ERR, "Getting length of serialized buffer failed", "CLI");
            return -1;   
        }

        lut_serialized = (char*)malloc(len * sizeof(char));

        if (lut_serialize(lut, m, C, lut_serialized, &len) <= 0) {
            logger(LOG_ERR, "Serialization of lookup table failed", "CLI");
            return -1;   
        }

        logger(LOG_INFO, "Saving the lookup table to file...", "CLI");
        if (save_to_file(lut_serialized, len, save_path) <= 0) {
            sprintf(buf, "Saving the file %s failed", save_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;    
        }

        printf("Lookup table written to '%s'.\n", save_path);

        free(lut_serialized);
        lut_free(lut, m, C);
        EC_GROUP_free(group);
        EC_POINT_free(public_key);

        break;
    case 's':
        char* lut_path;
        char* sign_key_path;
        char* msg_path;
        char* msg;
        unsigned int msg_len;
        char* enc_msg;
        char static_delta[25];
        char* delta = "\0";
        char* custom_delta = "\0";
        int delta_len = 0;
        char* sig_path;

        switch (argc - start_index - 1)
        {
        case 7: // no delta
            custom_delta = NULL;
        case 8:
            sig_path = argv[start_index + 1];
            lut_path = argv[start_index + 2];
            sign_key_path = argv[start_index + 3];
            enc_key_path = argv[start_index + 4];
            msg_path = argv[start_index + 5];
            enc_msg = argv[start_index + 6];
            dual_key = argv[start_index + 7];
            if (custom_delta) custom_delta = argv[start_index+8];

            break;
        default:
            logger(LOG_ERR, "Incorrect number of arguments", "CLI");
            print_help(argv[0], 0b10);
            return -1;
        }

        logger(LOG_DBG, "Opening the msg file", "CLI");
        msg = read_from_file(msg_path, &msg_len);

        if (!msg) {
            sprintf(buf, "Opening the file %s failed", msg_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        } 

        sprintf(buf, "msg_path = %s, enc_msg = %s, dkey = %s", msg_path, enc_msg, dual_key);
        logger(LOG_DBG, buf, "CLI");
        if (custom_delta) logger(LOG_DBG, strcat(strcpy(buf, "delta = "), custom_delta), "CLI");

        enc_key = EVP_PKEY_new();
        EVP_PKEY* sign_key = EVP_PKEY_new();
        fp = fopen(enc_key_path, "rb");

        if (!fp) {
            sprintf(buf, "Opening the file %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        logger(LOG_INFO, "Decoding the enc key from PEM...", "CLI");
        if (!PEM_read_PUBKEY(fp, &enc_key, NULL, NULL)){
            sprintf(buf, "Loading the public key %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        fclose(fp);

        fp = fopen(sign_key_path, "rb");

        if (!fp) {
            sprintf(buf, "Opening the file %s failed", sign_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        logger(LOG_INFO, "Decoding the sign key from PEM...", "CLI");
        if (!PEM_read_PrivateKey(fp, &sign_key, NULL, NULL)){
            sprintf(buf, "Loading the private key %s failed", sign_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }
        fclose(fp);

        public_key = NULL;
        group = NULL;

        logger(LOG_INFO, "Parsing the EVP key...", "CLI");
        if (parse_evp_pkey(enc_key, &group, &public_key, NULL) <= 0) {
            sprintf(buf, "Parsing the evp key %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;   
        }

        logger(LOG_INFO, "Opening the lookup table...", "CLI");
        unsigned int lut_serialized_len;
        lut_serialized = read_from_file(lut_path, &lut_serialized_len);

        logger(LOG_INFO, "Deserializing the lookup table...", "CLI");
        if (lut_deserialize(NULL, &m, &C, lut_serialized, lut_serialized_len) < 0) {
            logger(LOG_ERR, "Recovering m and C failed", "CLI");
            return -1;   
        }
        if (m <= 0 || m >= 32 || C <= 0) {
            logger(LOG_ERR, "Invalid m or C values", "CLI");
            return -1;
        }
        lut = lut_new(m, C);

        if (lut_deserialize(lut, &m, &C, lut_serialized, lut_serialized_len) <= 0) {
            logger(LOG_ERR, "Deserializing the lookup table failed", "CLI");
            return -1;   
        }
        free(lut_serialized);

        logger(LOG_INFO, "Inserting into the lookup table...", "CLI");
        as_insert(lut, m, C, 0, 
                dual_key, strlen(dual_key),
                public_key, group);

        logger(LOG_INFO, "Calculating the signature...", "CLI");
        unsigned int sig_len;

        if (!custom_delta) {
            time_t t;
            time(&t);
            sprintf(static_delta, "%lu", t);
            custom_delta = static_delta;
        };

        logger(LOG_INFO, "Prepending message to delta", "CLI");
        delta_len = strlen(custom_delta) + msg_len;
        char *buffer = (char *)malloc(delta_len * sizeof(char));
        memcpy((void *)buffer, (void *)msg, msg_len);
        memcpy((void *)&buffer[msg_len], (void *)custom_delta, strlen(custom_delta));
        delta = buffer;

        char* sig = ecdsa_as_sign(sign_key, msg, (int)msg_len,
                                (int*)&sig_len, enc_key, 
                                enc_msg, (int)strlen(enc_msg), 
                                dual_key, (int)strlen(dual_key),
                                delta, delta_len,
                                m, C, lut);

        logger(LOG_INFO, "Serializing the lookup table...", "CLI");
        if (lut_serialize(lut, m, C, NULL, &len) < 0) {
            logger(LOG_ERR, "Getting length of serialized buffer failed", "CLI");
            return -1;   
        }

        lut_serialized = (char*)malloc(len * sizeof(char));

        if (lut_serialize(lut, m, C, lut_serialized, &len) <= 0) {
            logger(LOG_ERR, "Serialization of lookup table failed", "CLI");
            return -1;   
        }

        logger(LOG_INFO, "Saving the modified lookup table to file...", "CLI");
        if (save_to_file(lut_serialized, len, lut_path) <= 0) {
            sprintf(buf, "Saving the file %s failed", lut_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;    
        }

        free(lut_serialized);

        printf("m = %d, C = %d\n", m, C);
        char* out = recover_n_lsbs_str(enc_msg, strlen(enc_msg), m);
        printf("\tEncrypted: %s\n", chr_2_hex(out, bit_2_byte_len(m)));
        printf("\tDelta: \n%s\n", custom_delta);
        printf("\tSignature: \n%s\n", chr_2_hex(sig, sig_len));

        logger(LOG_INFO, "Saving the signature to file...", "CLI");
        if (save_to_file(sig, sig_len, sig_path) <= 0) {
            sprintf(buf, "Saving the file %s failed", sig_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;       
        }

        printf("Signature written to '%s'. Remember to save the delta!\n", sig_path);

        free(out);
        free(msg);
        free(delta);
        lut_free(lut, m, C);
        free(sig);
        EVP_PKEY_free(enc_key);
        EVP_PKEY_free(sign_key);
        EC_POINT_free(public_key);
        EC_GROUP_free(group);

        break;
    case 'd':
        switch (argc - start_index - 1)
        {
        case 7:
            sign_key_path = argv[start_index + 1];
            enc_key_path = argv[start_index + 2];
            sig_path = argv[start_index + 3];
            msg_path = argv[start_index + 4];
            m = strtol(argv[start_index+5], NULL, 10);
            dual_key = argv[start_index + 6];
            custom_delta = argv[start_index+7];

            break;
        default:
            logger(LOG_ERR, "Incorrect number of arguments", "CLI");
            print_help(argv[0], 0b100);
            return -1;
        }

        msg = read_from_file(msg_path, &msg_len);
        if (!msg) {
            sprintf(buf, "Opening the file %s failed", msg_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        sig = read_from_file(sig_path, &sig_len);
        if (!sig) {
            sprintf(buf, "Opening the file %s failed", sig_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        if (m <= 0 || m >= 32) {
            logger(LOG_ERR, "Invalid m value", "CLI");
            return -1;
        }

        sprintf(buf, "msg_path = %s, dual_key = %s, delta = %s, m = %d", msg_path, dual_key, custom_delta, m);
        logger(LOG_DBG, buf, "CLI");
        sprintf(buf, "sig = %s", chr_2_hex(sig, sig_len));
        logger(LOG_DBG, buf, "CLI");

        logger(LOG_INFO, "Prepending message to delta", "CLI");
        delta_len = strlen(custom_delta) + msg_len;
        buffer = (char *)malloc(delta_len * sizeof(char));
        memcpy((void *)buffer, (void *)msg, msg_len);
        memcpy((void *)&buffer[msg_len], (void *)custom_delta, strlen(custom_delta));
        delta = buffer;

        enc_key = EVP_PKEY_new();
        sign_key = EVP_PKEY_new();
        fp = fopen(enc_key_path, "rb");

        if (!fp) {
            sprintf(buf, "Opening the file %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        logger(LOG_INFO, "Decoding the enc key from PEM...", "CLI");
        if (!PEM_read_PrivateKey(fp, &enc_key, NULL, NULL)){
            sprintf(buf, "Loading the private key %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        fclose(fp);

        fp = fopen(sign_key_path, "rb");

        if (!fp) {
            sprintf(buf, "Opening the file %s failed", sign_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }

        logger(LOG_INFO, "Decoding the sign key from PEM...", "CLI");
        if (!PEM_read_PUBKEY(fp, &sign_key, NULL, NULL)){
            sprintf(buf, "Loading the public key %s failed", sign_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;
        }
        fclose(fp);

        BIGNUM* priv_key = BN_new();
        public_key = NULL;
        group = NULL;

        logger(LOG_INFO, "Parsing the EVP key...", "CLI");
        if (parse_evp_pkey(enc_key, &group, &public_key, &priv_key) <= 0) {
            sprintf(buf, "Parsing the evp key %s failed", enc_key_path);
            logger(LOG_ERR, buf, "CLI");
            return -1;   
        }

        logger(LOG_INFO, "Verifying the signature...", "CLI");
        EC_POINT* r = EC_POINT_new(group);
        int verif = ecdsa_verify_full(sign_key, msg, msg_len, sig, sig_len, &r);

        if (!verif) {
            logger(LOG_WARN, "Signature verification failed!", "CLI");
        }
        else {
            logger(LOG_INFO, "Signature verified", "CLI");
        }

        logger(LOG_INFO, "Decrypting the encrypted message...", "CLI");
        char* plaintext = as_decrypt(m, delta, delta_len,
                                    dual_key, strlen(dual_key), 
                                    r, priv_key, group);

        printf("m = %d\n", m);
        printf("\tDecrypted: \n%s\n", plaintext);
        printf("\tDecrypted (hex): \n%s\n", chr_2_hex(plaintext, bit_2_byte_len(m)));
        
        EC_POINT_free(r);
        EVP_PKEY_free(enc_key);
        EVP_PKEY_free(sign_key);
        free(plaintext);
        free(delta);
        free(sig);
        free(msg);

        break;
    case 'h':
    case 'H':
        print_help(argv[0], HELP_ALL);
        break;
    default:
        logger(LOG_ERR, "Unknown argument", "CLI");
        print_help(argv[0], HELP_ALL);
        break;
    }
}