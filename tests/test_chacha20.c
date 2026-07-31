#include <stdio.h>
#include <string.h>
#include "../src/chacha20.h"

/*
 * Tests de validation contre les vecteurs officiels de la RFC 8439.
 * Si notre implementation retrouve exactement ces valeurs de reference,
 * c'est qu'elle est correcte.
 */

static int g_checks = 0;
static int g_fails = 0;

static void check(int cond, const char *msg)
{
    g_checks++;
    if (cond) {
        printf("  [PASS] %s\n", msg);
    } else {
        printf("  [FAIL] %s\n", msg);
        g_fails++;
    }
}

/* Compare deux buffers et renvoie 1 s'ils sont identiques. */
static int equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

/*
 * Vecteur de test du bloc ChaCha20, RFC 8439 section 2.3.2.
 * Cle 00..1f, nonce 00 00 00 09 00 00 00 4a 00 00 00 00, compteur = 1.
 */
static void test_rfc_block(void)
{
    printf("test_rfc_block (RFC 8439 §2.3.2)\n");

    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
    }

    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    /* Sortie de reference attendue (keystream du bloc, compteur = 1). */
    uint8_t expected[64] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    };

    uint8_t out[64];
    chacha20_block(key, nonce, 1, out);

    check(equal(out, expected, 64), "bloc keystream conforme a la RFC");
}

/*
 * Vecteur de chiffrement complet, RFC 8439 section 2.4.2.
 * On chiffre le texte "Ladies and Gentlemen..." et on compare au
 * chiffre de reference.
 */
static void test_rfc_encrypt(void)
{
    printf("test_rfc_encrypt (RFC 8439 §2.4.2)\n");

    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
    }

    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    const char *plaintext =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";

    size_t len = strlen(plaintext);

    /* Premiers octets du chiffre de reference (RFC). */
    uint8_t expected_start[16] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81
    };

    uint8_t cipher[256];
    chacha20_xor(key, nonce, 1, (const uint8_t *)plaintext, cipher, len);

    check(equal(cipher, expected_start, 16),
          "chiffre conforme a la RFC (16 premiers octets)");

    /* Le dechiffrement doit redonner le texte clair d'origine. */
    uint8_t decrypted[256];
    chacha20_xor(key, nonce, 1, cipher, decrypted, len);
    decrypted[len] = '\0';

    check(strcmp((const char *)decrypted, plaintext) == 0,
          "dechiffrement = texte clair d'origine");
}

/*
 * Propriete fondamentale : chiffrer puis dechiffrer avec la meme cle
 * et le meme nonce redonne le message initial, quelle que soit sa taille.
 */
static void test_roundtrip_various_sizes(void)
{
    printf("test_roundtrip_various_sizes\n");

    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0x10 + i);

    /* On teste plusieurs tailles, dont des tailles non multiples de 64. */
    size_t sizes[] = {1, 63, 64, 65, 127, 200};
    int all_ok = 1;

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        uint8_t msg[256], cipher[256], back[256];

        for (size_t i = 0; i < n; i++) {
            msg[i] = (uint8_t)(i * 7 + 3);
        }

        chacha20_xor(key, nonce, 0, msg, cipher, n);
        chacha20_xor(key, nonce, 0, cipher, back, n);

        if (memcmp(msg, back, n) != 0) {
            all_ok = 0;
        }
    }

    check(all_ok, "chiffrer puis dechiffrer redonne le message (toutes tailles)");
}

/*
 * Un keystream ne doit pas laisser le message en clair : le chiffre
 * doit differer du clair (sauf cas degenere improbable).
 */
static void test_cipher_differs(void)
{
    printf("test_cipher_differs\n");

    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    const char *msg = "message secret de test";
    size_t n = strlen(msg);

    uint8_t cipher[64];
    chacha20_xor(key, nonce, 0, (const uint8_t *)msg, cipher, n);

    check(memcmp(msg, cipher, n) != 0, "le chiffre differe du clair");
}

int main(void)
{
    printf("=== Tests ChaCha20 (validation RFC 8439) ===\n\n");

    test_rfc_block();
    test_rfc_encrypt();
    test_roundtrip_various_sizes();
    test_cipher_differs();

    printf("\n=== Resultat : %d/%d checks reussis ===\n",
           g_checks - g_fails, g_checks);

    return (g_fails == 0) ? 0 : 1;
}
