#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "common.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        return printf("Usage: %s -[e | d | a]\n", argv[0]), 1;
    }

    if (!strcmp(argv[1], "-e")) {
        u8 subkeys[11][3];

        u8 key[10] = {
            0xD1, 0xBD, 0x2D, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00
        };

        generate_round_keys(key, subkeys);

        u8 clear_text[3] = { 0xF9, 0x55, 0xB9 };
        printf("Clear:  %x%x%x\n\n", clear_text[0], clear_text[1], clear_text[2]);

        u8 *cipher_text = PRESENT24_encrypt(clear_text, subkeys);
        printf("\nCipher: %x%x%x\n", cipher_text[0], cipher_text[1], cipher_text[2]);
    }
    else if (!strcmp(argv[1], "-d")) {
        u8 subkeys[11][3];

        u8 key[10] = {
            0xD1, 0xBD, 0x2D, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00
        };

        generate_round_keys(key, subkeys);

        u8 cipher_text[3] = { 0x47, 0xA9, 0x29 };
        printf("Cipher: %x%x%x\n\n", cipher_text[0], cipher_text[1], cipher_text[2]);

        u8 *clear_text = PRESENT24_decrypt(cipher_text, subkeys);
        printf("\nClear: %x%x%x\n", clear_text[0], clear_text[1], clear_text[2]);
    }
    else if (!strcmp(argv[1], "-a")) {
        if (argc == 6) {
            i32 a2 = strtol(argv[2], NULL, 16);
            i32 a3 = strtol(argv[3], NULL, 16);
            i32 a4 = strtol(argv[4], NULL, 16);
            i32 a5 = strtol(argv[5], NULL, 16);

            u8 m1[3] = {
                (a2 & 0x00ff0000) >> 16,
                (a2 & 0x0000ff00) >> 8,
                (a2 & 0x000000ff)
            };

            u8 c1[3] = {
                (a3 & 0x00ff0000) >> 16,
                (a3 & 0x0000ff00) >> 8,
                (a3 & 0x000000ff)
            };

            u8 m2[3] = {
                (a4 & 0x00ff0000) >> 16,
                (a4 & 0x0000ff00) >> 8,
                (a4 & 0x000000ff)
            };

            u8 c2[3] = {
                (a5 & 0x00ff0000) >> 16,
                (a5 & 0x0000ff00) >> 8,
                (a5 & 0x000000ff)
            };

            PRESENT24_attack(m1, c1, m2, c2);
        }
        else {
            return printf("Usage: %s -a m1 c1 m2 c2\n", argv[0]), 1;
        }
    }
    else {
        return printf("Usage: %s -[e | d | a]\n", argv[0]), 1;
    }

    return 0;
}

