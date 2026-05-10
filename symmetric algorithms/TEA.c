#include <stdio.h>
#include <stdint.h>
#include <string.h>

// implementation found on Wikipedia
void encrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0;  /* set up */
    uint32_t delta = 0x9E3779B9;  /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (int i = 0; i < 32; i++) {  /* basic cycle starts */
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t  v0=v[0], v1=v[1], sum = 0xC6EF3720;
    uint32_t delta = 0x9E3779B9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (int i = 0; i < 32; i++) {  /* start cycle */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) +k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }
    v[0] = v0; v[1] = v1;
}



// since TEA is a block cipher, I opted for the CBC mode
void tea_cbc_encrypt(FILE *in, FILE *out, uint32_t iv[2], const uint32_t key[4]) {
    uint32_t v[2], prev[2] = {iv[0], iv[1]};
    size_t bytes_read;
    // bigger size buffer to make reading chunks more efficient
    uint8_t buffer[1024*1024];

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        for (size_t i = 0; i < bytes_read; i += 8) {

            // TEA works on 64 bits = 8 bytes
            if (bytes_read - i < 8) {
                // pad last block with 0s if there are any remaining bytes
                uint8_t last_block[8] = {0};
                memcpy(last_block, buffer + i, bytes_read - i);
                memcpy(v, last_block, 8);
            } else {
                memcpy(v, buffer + i, 8);
            }


            v[0] ^= prev[0];
            v[1] ^= prev[1];

            encrypt(v, key);

            prev[0] = v[0];
            prev[1] = v[1];
            fwrite(v, 1, 8, out);
        }
    }
}

void tea_cbc_decrypt(FILE *in, FILE *out, uint32_t iv[2], const uint32_t key[4]) {
    // adding variable current ciphertext to be able to assign it
    // to prev after decryption
    uint32_t v[2], prev[2] = {iv[0], iv[1]}, curr_ciphertext[2];
    size_t bytes_read;
    uint8_t buffer[1024 * 1024];

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        for (size_t i = 0; i < bytes_read; i += 8) {
            if (bytes_read - i < 8) break;
            memcpy(v, buffer + i, 8);

            curr_ciphertext[0] = v[0];
            curr_ciphertext[1] = v[1];

            decrypt(v, key);

            v[0] ^= prev[0];
            v[1] ^= prev[1];
            fwrite(v, 1, 8, out);

            prev[0] = curr_ciphertext[0];
            prev[1] = curr_ciphertext[1];
        }
    }
}
