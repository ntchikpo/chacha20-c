#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

/*
 * Implementation de ChaCha20 (RFC 8439).
 *
 * ChaCha20 est un chiffrement de flux : il genere un keystream
 * pseudo-aleatoire a partir d'une cle, d'un nonce et d'un compteur,
 * puis fait un XOR entre ce keystream et le message.
 *
 * Comme l'operation est un XOR, la meme fonction chiffre et dechiffre :
 *   chiffre  = clair   XOR keystream
 *   clair    = chiffre XOR keystream
 *
 * AVERTISSEMENT : ce code est un projet d'apprentissage destine a
 * comprendre le fonctionnement interne de l'algorithme. En production,
 * il faut utiliser une bibliotheque auditee comme libsodium.
 */

#define CHACHA20_KEY_SIZE   32u  /* cle de 256 bits */
#define CHACHA20_NONCE_SIZE 12u  /* nonce de 96 bits (RFC 8439) */
#define CHACHA20_BLOCK_SIZE 64u  /* un bloc de keystream fait 64 octets */

/*
 * Chiffre (ou dechiffre) len octets.
 *
 * key    : cle de 32 octets
 * nonce  : nonce de 12 octets (ne doit jamais etre reutilise avec la meme cle)
 * counter: valeur initiale du compteur de bloc (souvent 0 ou 1)
 * in     : donnees d'entree
 * out    : donnees de sortie (peut pointer sur in pour un traitement en place)
 * len    : nombre d'octets a traiter
 */
void chacha20_xor(const uint8_t key[CHACHA20_KEY_SIZE],
                  const uint8_t nonce[CHACHA20_NONCE_SIZE],
                  uint32_t counter,
                  const uint8_t *in,
                  uint8_t *out,
                  size_t len);

/*
 * Genere un seul bloc de keystream de 64 octets.
 * Expose surtout pour permettre les tests contre les vecteurs de la RFC.
 */
void chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE],
                    const uint8_t nonce[CHACHA20_NONCE_SIZE],
                    uint32_t counter,
                    uint8_t out[CHACHA20_BLOCK_SIZE]);

#endif /* CHACHA20_H */
