# ChaCha20 en C

Implémentation du chiffrement de flux **ChaCha20** (RFC 8439) en C, from scratch, avec un outil en ligne de commande pour chiffrer et déchiffrer des fichiers.

L'implémentation est validée contre les **vecteurs de test officiels de la RFC 8439** : si le code retrouve exactement les valeurs de référence publiées, c'est qu'il est correct.

## Avertissement

Ce projet est un **exercice d'apprentissage** destiné à comprendre le fonctionnement interne d'un chiffrement moderne. En production, on n'implémente jamais sa propre cryptographie : on utilise une bibliothèque auditée comme [libsodium](https://libsodium.org). Réutiliser un même couple (clé, nonce) casse par ailleurs la sécurité de ChaCha20.

## Comment ça marche

ChaCha20 est un **chiffrement de flux**. À partir d'une clé, d'un nonce et d'un compteur, il génère un keystream pseudo-aléatoire, puis fait un XOR entre ce keystream et le message :

```
chiffré = clair   XOR keystream
clair   = chiffré XOR keystream
```

Comme l'opération est un simple XOR, **la même fonction chiffre et déchiffre**.

L'algorithme repose sur :

- un **état de 16 mots de 32 bits** : 4 constantes, 8 mots de clé, 1 compteur, 3 mots de nonce ;
- une opération de mélange, le **quarter round**, appliquée en colonnes puis en diagonales ;
- **20 tours** (10 doubles-tours) qui assurent la diffusion.

| Paramètre | Taille          |
|-----------|-----------------|
| Clé       | 256 bits (32 o) |
| Nonce     | 96 bits (12 o)  |
| Bloc      | 512 bits (64 o) |

## Compilation et tests

```sh
make test
```

Sortie attendue :

```
=== Résultat : 5/5 checks réussis ===
```

Les tests couvrent :

- le keystream d'un bloc (vecteur RFC 8439 §2.3.2) ;
- un chiffrement complet (vecteur RFC 8439 §2.4.2) ;
- la propriété d'aller-retour (chiffrer puis déchiffrer) sur plusieurs tailles, y compris non multiples de 64 ;
- le fait que le chiffré diffère bien du clair.

Le projet compile avec `-Wall -Wextra -Werror` : aucun avertissement toléré.

## Utilisation de l'outil

```sh
make

# Clé de 64 caractères hex (32 octets), nonce de 24 caractères hex (12 octets)
KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
NONCE=000000000000004a00000000

# Chiffrement
./build/chacha20 $KEY $NONCE message.txt message.enc

# Déchiffrement (même commande, même clé, même nonce)
./build/chacha20 $KEY $NONCE message.enc message.dec
```

`message.dec` est alors identique à `message.txt`.

## Structure

```
chacha20-c/
├── src/
│   ├── chacha20.c    # coeur de l'algorithme
│   ├── chacha20.h
│   └── main.c        # outil CLI chiffrer/déchiffrer
├── tests/
│   └── test_chacha20.c   # validation contre les vecteurs RFC
├── Makefile
└── README.md
```

## Pistes d'amélioration

- Ajouter Poly1305 pour passer d'un simple chiffrement à un chiffrement **authentifié** (AEAD), comme ChaCha20-Poly1305 réellement utilisé dans TLS et WireGuard.
- Générer clé et nonce aléatoirement plutôt que de les passer en argument.
- Effacer les buffers sensibles de la mémoire après usage.
