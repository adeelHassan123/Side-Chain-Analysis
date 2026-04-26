#include <stdint.h>

// Function to calculate Hamming Weight of a byte
int hamming_weight(uint8_t value) {
    int count = 0;
    while (value > 0) {
        if (value & 1) count++;
        value >>= 1;
    }
    return count;
}

// 128-bit XOR encryption: ciphertext = plaintext ^ key
void xor_encrypt_128(uint8_t *plaintext, uint8_t *key, uint8_t *ciphertext) {
    for (int i = 0; i < 16; i++) {
        ciphertext[i] = plaintext[i] ^ key[i];
    }
}

// Entry point for emulation
void main() {
    uint8_t plaintext[16] = {0}; 
    uint8_t key[16] = {0xDE, 0xAD, 0xBE, 0xEF}; // Example key
    uint8_t ciphertext[16];

    xor_encrypt_128(plaintext, key, ciphertext);
}
