#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void tea_cbc_encrypt(FILE *in, FILE *out, uint32_t iv[2], const uint32_t key[4]);
void tea_cbc_decrypt(FILE *in, FILE *out, uint32_t iv[2], const uint32_t key[4]);
void chacha_process(FILE *in, FILE *out, uint32_t key[8], uint32_t nonce[3]);
void rsa_encrypt(FILE *in, FILE *out, const char *e_hex, const char *n_hex);
void rsa_decrypt(FILE *in, FILE *out, const char *d_hex, const char *n_hex);
void rsa_key_generation(int bits);


// function for reading the words for both symmetric algs
void parse(const char* hex, uint32_t *k, int words) {
    for (int i = 0; i < words; i++) {
        sscanf(hex + (i * 8), "%8x", &k[i]);
    }
}

void read_key(const char *filename, char *buffer, size_t len){
    FILE *f = fopen(filename, "r");
    if (!f){
        perror("Error opening key.txt file");
        exit(1);
    }
    if (fgets(buffer, len, f) == NULL) {
        fprintf(stderr, "Key file is empty or cannot be read");
        fclose(f);
        exit(1);
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    fclose(f);
}

int main(int argc, char *argv[]) {
    char *in_path = NULL, *out_path = NULL, *key_path = NULL, *alg = NULL;
    char hex_buffer[128];
    int mode = -1;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-g") == 0) {
            rsa_key_generation(1024);
            return 0;
        }
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0) {
            mode = 0;
            in_path = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0) {
            mode = 1;
            in_path = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0) {
            alg = argv[++i];
        }
    }

    if (mode == -1 || !in_path || !out_path || !key_path || !alg){
        printf("Usage: crypto -e <input_file> -a <tea/chacha/rsa> -k <key.txt> -o <output_file>\n");
        return 1;
    }

    FILE *in = fopen(in_path, "rb");
    FILE *out = fopen(out_path, "wb");

    if (!in || !out){
        perror("Error finding file");
        return 1;
    }

    read_key(key_path, hex_buffer, sizeof(hex_buffer));

    if (strcmp(alg, "tea") == 0) {
        uint32_t key[4], iv[2]  = {0xDEADBEEF, 0xCAFEBABE};
        parse(hex_buffer, key, 4);
        if (mode == 0){
            printf("Starting encryption using TEA...");
            tea_cbc_encrypt(in, out, iv, key);
        } else {
            printf("Starting decryption using TEA...");
            tea_cbc_decrypt(in, out, iv, key);
        }
    }

    else if (strcmp(alg, "chacha") == 0) {
        uint32_t key[8], nonce[3]  = {0x12345678, 0x9ABCDEF0, 0xDEADBEEF};
        parse(hex_buffer, key, 8);
        printf("Starting %s using ChaCha20...", (mode == 0 ? "encryption" : "decryption"));
        chacha_process(in, out, key, nonce);
    }

    else if (strcmp(alg, "rsa") == 0) {
        char key_buffer[1024];
        char n_buffer[1024];

        FILE *key_file = fopen(key_path, "r");
        if (!key_file) {
            perror("Error opening RSA key file");
            return 1;
        }

        // read 1st line
        if (fgets(key_buffer, sizeof(key_buffer), key_file)) {
            key_buffer[strcspn(key_buffer, "\r\n")] = 0;
        }
        // and the 2nd one
        if (fgets(n_buffer, sizeof(n_buffer), key_file)) {
            n_buffer[strcspn(n_buffer, "\r\n")] = 0;
        }
        fclose(key_file);

        if (strlen(key_buffer) == 0 || strlen(n_buffer) == 0) {
            fprintf(stderr, "Error: RSA key or modulus is empty\n");
            return 3;
        }

        if (mode == 0){
            printf("Starting encryption using RSA...");
            rsa_encrypt(in, out, key_buffer, n_buffer);
        } else {
            printf("Starting decryption using RSA...");
            rsa_decrypt(in, out, key_buffer, n_buffer);
        }
    }

    printf("\nFinished %s!", (mode == 0 ? "encrypting" : "decrypting"));
    fclose(in);
    fclose(out);
    return 0;
}