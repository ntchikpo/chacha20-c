#include "chacha20.h"
#include <string.h>

/* Rotation a gauche sur 32 bits. */
static inline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

/* Lit 4 octets en little-endian et les assemble en un mot de 32 bits. */
static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* Ecrit un mot de 32 bits en little-endian. */
static inline void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

/*
 * Le "quarter round" de ChaCha20 : l'operation de base qui melange
 * quatre mots de l'etat. C'est le coeur de la diffusion de l'algorithme.
 */
#define QR(a, b, c, d)                 \
    do {                               \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d, 8);  \
        c += d; b ^= c; b = rotl32(b, 7);  \
    } while (0)

/*
 * Construit l'etat initial de 16 mots :
 *   - 4 mots de constante ("expand 32-byte k")
 *   - 8 mots de cle
 *   - 1 mot de compteur
 *   - 3 mots de nonce
 */
static void chacha20_init_state(uint32_t state[16],
                                const uint8_t key[CHACHA20_KEY_SIZE],
                                const uint8_t nonce[CHACHA20_NONCE_SIZE],
                                uint32_t counter)
{
    /* Constantes ASCII "expand 32-byte k" en little-endian. */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32_le(key + 4 * i);
    }

    state[12] = counter;

    for (int i = 0; i < 3; i++) {
        state[13 + i] = load32_le(nonce + 4 * i);
    }
}

void chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE],
                    const uint8_t nonce[CHACHA20_NONCE_SIZE],
                    uint32_t counter,
                    uint8_t out[CHACHA20_BLOCK_SIZE])
{
    uint32_t state[16];
    uint32_t working[16];

    chacha20_init_state(state, key, nonce, counter);
    memcpy(working, state, sizeof(state));

    /* 20 tours = 10 doubles-tours (colonnes puis diagonales). */
    for (int i = 0; i < 10; i++) {
        /* Tours de colonnes. */
        QR(working[0], working[4], working[8],  working[12]);
        QR(working[1], working[5], working[9],  working[13]);
        QR(working[2], working[6], working[10], working[14]);
        QR(working[3], working[7], working[11], working[15]);
        /* Tours de diagonales. */
        QR(working[0], working[5], working[10], working[15]);
        QR(working[1], working[6], working[11], working[12]);
        QR(working[2], working[7], working[8],  working[13]);
        QR(working[3], working[4], working[9],  working[14]);
    }

    /* On ajoute l'etat initial a l'etat travaille, puis on serialise. */
    for (int i = 0; i < 16; i++) {
        uint32_t v = working[i] + state[i];
        store32_le(out + 4 * i, v);
    }
}

void chacha20_xor(const uint8_t key[CHACHA20_KEY_SIZE],
                  const uint8_t nonce[CHACHA20_NONCE_SIZE],
                  uint32_t counter,
                  const uint8_t *in,
                  uint8_t *out,
                  size_t len)
{
    uint8_t block[CHACHA20_BLOCK_SIZE];
    size_t offset = 0;

    while (offset < len) {
        chacha20_block(key, nonce, counter, block);
        counter++;

        size_t chunk = len - offset;
        if (chunk > CHACHA20_BLOCK_SIZE) {
            chunk = CHACHA20_BLOCK_SIZE;
        }

        for (size_t i = 0; i < chunk; i++) {
            out[offset + i] = in[offset + i] ^ block[i];
        }
        offset += chunk;
    }
}
