/**
 * ascon128_reference.c - Minimal but complete ASCON-128 encryption (AEAD)
 * For ARM Cortex-M3 side-channel experiments.
 */

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t x[5];
} ascon_state_t;

static const uint8_t sbox[32] = {
    0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2,
    0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1e,
    0x10, 0xc, 0x1c, 0x13, 0x7, 0x17, 0x1, 0xd,
    0x19, 0x18, 0xe, 0x16, 0xf, 0x0, 0xa, 0x11
};

static void sbox_layer(uint64_t state[5]) {
    for (int w = 0; w < 5; w++) {
        uint64_t input = state[w];
        uint64_t output = 0;
        for (int i = 0; i < 64; i += 5) {
            uint8_t chunk = (input >> i) & 0x1F;
            uint8_t transformed = sbox[chunk];
            output |= ((uint64_t)transformed) << i;
        }
        state[w] = output;
    }
}

static inline uint64_t rotr(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static void diffusion_layer(uint64_t state[5]) {
    state[0] ^= rotr(state[0], 19) ^ rotr(state[0], 28);
    state[1] ^= rotr(state[1], 61) ^ rotr(state[1], 39);
    state[2] ^= rotr(state[2], 1) ^ rotr(state[2], 6);
    state[3] ^= rotr(state[3], 10) ^ rotr(state[3], 17);
    state[4] ^= rotr(state[4], 7) ^ rotr(state[4], 41);
}

static void add_round_constant(uint64_t state[5], uint64_t rc) {
    state[2] ^= rc;
}

static const uint64_t RC[12] = {
    0x0000000f0000000fULL, 0x0000001e0000001eULL,
    0x0000003c0000003cULL, 0x0000007800000078ULL,
    0x000000f0000000f0ULL, 0x000001e0000001e0ULL,
    0x000003c0000003c0ULL, 0x0000078000000780ULL,
    0x00000f0000000f00ULL, 0x00001e0000001e00ULL,
    0x00003c0000003c00ULL, 0x0000780000007800ULL
};

static void ascon_permutation(uint64_t state[5], int rounds) {
    for (int r = 0; r < rounds; r++) {
        add_round_constant(state, RC[r]);
        sbox_layer(state);
        diffusion_layer(state);
    }
}

static uint64_t bytes_to_u64be(const uint8_t bytes[8]) {
    return ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8) | ((uint64_t)bytes[7]);
}

static void u64_to_bytes_be(uint64_t val, uint8_t bytes[8]) {
    bytes[0] = (val >> 56) & 0xFF;
    bytes[1] = (val >> 48) & 0xFF;
    bytes[2] = (val >> 40) & 0xFF;
    bytes[3] = (val >> 32) & 0xFF;
    bytes[4] = (val >> 24) & 0xFF;
    bytes[5] = (val >> 16) & 0xFF;
    bytes[6] = (val >> 8) & 0xFF;
    bytes[7] = val & 0xFF;
}

static void ascon_init(uint64_t state[5], const uint8_t key[16], const uint8_t nonce[16]) {
    state[0] = 0x0000000000000040ULL;
    state[1] = bytes_to_u64be(key);
    state[2] = bytes_to_u64be(key + 8);
    state[3] = bytes_to_u64be(nonce);
    state[4] = bytes_to_u64be(nonce + 8);
    ascon_permutation(state, 12);
}

static void ascon_encrypt_block(uint64_t state[5], uint8_t *ciphertext, const uint8_t *plaintext) {
    uint64_t p = bytes_to_u64be(plaintext);
    uint64_t c = state[0] ^ p;
    u64_to_bytes_be(c, ciphertext);
    state[0] = c;
    ascon_permutation(state, 6);
}

static void ascon_finalize(uint64_t state[5], uint8_t tag[16]) {
    ascon_permutation(state, 12);
    u64_to_bytes_be(state[0], tag);
    u64_to_bytes_be(state[1], tag + 8);
}

void ascon_encrypt(const uint8_t key[16], const uint8_t nonce[16],
                   const uint8_t *plaintext, size_t len,
                   uint8_t *ciphertext, uint8_t tag[16]) {
    uint64_t state[5];
    ascon_init(state, key, nonce);

    size_t full_blocks = len / 8;
    for (size_t i = 0; i < full_blocks; i++) {
        ascon_encrypt_block(state, ciphertext + i * 8, plaintext + i * 8);
    }

    size_t rem = len % 8;
    if (rem > 0) {
        uint8_t last_plain[8] = {0};
        uint8_t last_cipher[8];
        for (size_t i = 0; i < rem; i++) {
            last_plain[i] = plaintext[full_blocks * 8 + i];
        }
        ascon_encrypt_block(state, last_cipher, last_plain);
        for (size_t i = 0; i < rem; i++) {
            ciphertext[full_blocks * 8 + i] = last_cipher[i];
        }
    }

    ascon_finalize(state, tag);
}
