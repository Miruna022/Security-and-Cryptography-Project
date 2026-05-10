#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

void rsa_encrypt(FILE *in, FILE *out, const char *e_hex, const char *n_hex) {
    mpz_t x, y, e, n;
    mpz_inits(x, y, e, n, NULL);
    uint8_t  in_buffer[64];
    size_t bytes_read;

    mpz_set_str(e, e_hex, 16);
    mpz_set_str(n, n_hex, 16);

    // keeping it small at only 63 bytes to avoid overflow
    // byte 1 used for length
    while ((bytes_read = fread(in_buffer + 1, 1, 63, in)) > 0) {
        in_buffer[0] = (uint8_t)bytes_read;
        if (bytes_read < 63) {
            memset(in_buffer + 1 + bytes_read, 0, 63 - bytes_read);
        }

        mpz_import(x, 64, 1, 1, 1, 0, in_buffer);
        mpz_powm(y, x, e, n);   // Encryption: y = x^e mod n
        uint8_t out_buffer[128] = {0};
        size_t ct;
        mpz_export(out_buffer, &ct, 1, 1, 1, 0, y);
        // shift right and pad to make sure that each block is 128 bytes long
        if (ct < 128){
            memmove(out_buffer + (128 - ct), out_buffer, ct);
            memset(out_buffer, 0, 128 - ct);
        }
        fwrite(out_buffer, 1, 128, out);
    }
    mpz_clears(x, y, e, n, NULL);
}



void rsa_decrypt(FILE *in, FILE *out, const char *d_hex, const char *n_hex) {
    mpz_t x, y, d, n;
    mpz_inits(x, y, d, n, NULL);
    uint8_t  in_buffer[128];

    mpz_set_str(d, d_hex, 16);
    mpz_set_str(n, n_hex, 16);

    // read the ciphertext block of 128 bytes
    while (fread(in_buffer, 1, 128, in) == 128) {
        mpz_import(y, 128, 1, 1, 1, 0, in_buffer);
        mpz_powm(x, y, d, n);   // Decryption: x = y^d mod n
        uint8_t out_buffer[64] = {0};
        size_t ct;
        mpz_export(out_buffer, &ct, 1, 1, 1, 0, x);

        // shift right
        if (ct < 64) {
            memmove(out_buffer + (64 - ct), out_buffer, ct);
            memset(out_buffer, 0, 64 - ct);
        }

        uint8_t actual_length = out_buffer[0];

        if (actual_length > 63) {
            actual_length = 63;
        }
        fwrite(out_buffer + 1, 1, actual_length, out);
    }

    mpz_clears(x, y, d, n, NULL);
}



void rsa_key_generation(int bits){
    mpz_t p, q, n, phi, e, d, gcd, p1, q1;
    gmp_randstate_t state;

    mpz_inits(p, q, n, phi, e, d, gcd, p1, q1, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    // Choose two large primes p, q
    mpz_urandomb(p, state, bits / 2);
    mpz_nextprime(p, p);
    mpz_urandomb(q, state, bits/2);
    mpz_nextprime(q, q);
    // Compute n = p * q
    mpz_mul(n, p, q);
    // Compute Φ(n) = (p-1) * (q-1)
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);
    // Select the public exponent e such that gcd(e, Φ(n) ) = 1
    mpz_set_ui(e, 65537);
    // Compute the private key d such that d * e ≡ 1 mod Φ(n)
    if (mpz_invert(d, e, phi) == 0) {
        printf("No modular inverse, try again.");
        return;
    }

    FILE *public = fopen("keys/public_key.txt", "w");
    gmp_fprintf(public, "%ZX\n%ZX\n", e, n);
    fclose(public);

    FILE *private = fopen("keys/private_key.txt", "w");
    gmp_fprintf(private, "%ZX\n%ZX\n", d, n);
    fclose(private);

    printf("Keys generated successfully!\n");

    mpz_clears(p, q, n, phi, e, d, p1, q1, gcd, NULL);
    gmp_randclear(state);
}


