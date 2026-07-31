#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "chacha20.h"

/*
 * Outil en ligne de commande : chiffre ou dechiffre un fichier avec ChaCha20.
 *
 * Comme ChaCha20 est symetrique et fonctionne par XOR, la meme commande
 * sert a chiffrer et a dechiffrer.
 *
 * Usage :
 *   chacha20 <cle_hex_64> <nonce_hex_24> <fichier_entree> <fichier_sortie>
 *
 *   cle_hex_64   : 64 caracteres hex = 32 octets
 *   nonce_hex_24 : 24 caracteres hex = 12 octets
 *
 * AVERTISSEMENT : projet d'apprentissage. Pour un usage reel, utiliser
 * une bibliotheque auditee comme libsodium, et ne jamais reutiliser
 * un couple (cle, nonce).
 */

/* Convertit une chaine hex en octets. Renvoie 0 en cas d'erreur. */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t expected_len)
{
    if (strlen(hex) != expected_len * 2) {
        return 0;
    }
    for (size_t i = 0; i < expected_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return 0;
        }
        out[i] = (uint8_t)byte;
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr,
            "Usage : %s <cle_hex_64> <nonce_hex_24> <entree> <sortie>\n",
            argv[0]);
        return 1;
    }

    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];

    if (!hex_to_bytes(argv[1], key, CHACHA20_KEY_SIZE)) {
        fprintf(stderr, "Erreur : la cle doit faire 64 caracteres hex.\n");
        return 1;
    }
    if (!hex_to_bytes(argv[2], nonce, CHACHA20_NONCE_SIZE)) {
        fprintf(stderr, "Erreur : le nonce doit faire 24 caracteres hex.\n");
        return 1;
    }

    FILE *fin = fopen(argv[3], "rb");
    if (!fin) {
        fprintf(stderr, "Erreur : impossible d'ouvrir %s\n", argv[3]);
        return 1;
    }
    FILE *fout = fopen(argv[4], "wb");
    if (!fout) {
        fprintf(stderr, "Erreur : impossible d'ecrire %s\n", argv[4]);
        fclose(fin);
        return 1;
    }

    /*
     * On traite le fichier par blocs de 64 octets (taille d'un bloc
     * ChaCha20). Le compteur avance d'un cran par bloc, ce qui garantit
     * un keystream different pour chaque portion du fichier.
     */
    uint8_t buf_in[CHACHA20_BLOCK_SIZE];
    uint8_t buf_out[CHACHA20_BLOCK_SIZE];
    uint32_t counter = 0;
    size_t nread;

    while ((nread = fread(buf_in, 1, CHACHA20_BLOCK_SIZE, fin)) > 0) {
        chacha20_xor(key, nonce, counter, buf_in, buf_out, nread);
        fwrite(buf_out, 1, nread, fout);
        counter++;
    }

    fclose(fin);
    fclose(fout);

    printf("Termine : %s -> %s\n", argv[3], argv[4]);
    return 0;
}
