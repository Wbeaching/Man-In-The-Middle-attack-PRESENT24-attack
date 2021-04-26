#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "encrypt.h"
#include "decrypt.h"

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

    } else if (!strcmp(argv[1], "-d")) {
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

    } else if (!strcmp(argv[1], "-a")) {
        printf("Unimplemented!\n");
    } else {
        return printf("Usage: %s -[e | d | a]\n", argv[0]), 1;
    }

    return 0;
}

