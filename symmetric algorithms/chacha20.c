#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (             \
	a += b, d ^= a, d = ROTL(d, 16), \
	c += d, b ^= c, b = ROTL(b, 12), \
	a += b, d ^= a, d = ROTL(d,  8), \
	c += d, b ^= c, b = ROTL(b,  7))
#define ROUNDS 20

// implementation found on Wikipedia
void chacha_block(uint32_t out[16], uint32_t const in[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = in[i];
    for (int i = 0; i < ROUNDS; i += 2) {
        // Odd round
        QR(x[0], x[4], x[ 8], x[12]); // column 1
        QR(x[1], x[5], x[ 9], x[13]); // column 2
        QR(x[2], x[6], x[10], x[14]); // column 3
        QR(x[3], x[7], x[11], x[15]); // column 4
        // Even round
        QR(x[0], x[5], x[10], x[15]); // diagonal 1 (main diagonal)
        QR(x[1], x[6], x[11], x[12]); // diagonal 2
        QR(x[2], x[7], x[ 8], x[13]); // diagonal 3
        QR(x[3], x[4], x[ 9], x[14]); // diagonal 4
    }
    for (int i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}


// ChaCha20 is a stream cipher that uses CTR by default
// so, I'll make use of it
void chacha_process(FILE *in, FILE *out, uint32_t key[8], uint32_t nonce[3]) {
    uint32_t matrix[16], keystream[16];
    uint8_t buffer[1024 * 1024];
    size_t bytes_read;

    // 0 to 3 is constants
    matrix[0] = 0x61707865; matrix[1] = 0x3320646e;
    matrix[2] = 0x79622d32; matrix[3] = 0x6b206574;
    // 4 to 11 is the 256-bit key
    memcpy(&matrix[4], key, 32);
    // 12 is the 32-bit counter
    matrix[12] = 0;
    // 13 to 15 is the 96-bit nonce
    matrix[13] = nonce[0]; matrix[14] = nonce[1]; matrix[15] = nonce[2];

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        for (size_t i = 0; i < bytes_read ; i += 64) {
            chacha_block(keystream, matrix);
            size_t chunk = (bytes_read - i < 64) ? (bytes_read - i) : 64;
            uint8_t *keystr = (uint8_t *) keystream;
            for (size_t j = 0; j < chunk; j++) {
                buffer[i + j] ^= keystr[j];
            }

            matrix[12]++;
            if (matrix[12] == 0){
                matrix[13]++;
            }
        }
        fwrite(buffer,1, bytes_read, out);
    }
}
