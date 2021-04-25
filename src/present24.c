#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "encrypt.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        return printf("Usage: %s -[e | d]\n", argv[0]), 1;
    }

    if (!strcmp(argv[1], "-e")) {
        u8 subkeys[11][3];

        u8 key[10] = {
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00
        };

        generate_round_keys(key, subkeys);

        u8 clear_text[3] = { 0x00, 0x00, 0x00 };
        printf("Clear:  %X%X%X\n\n", clear_text[0], clear_text[1], clear_text[2]);

        u8 *cipher_text = PRESENT24_encrypt(clear_text, subkeys);
        printf("\nCipher: %X%X%X\n", cipher_text[0], cipher_text[1], cipher_text[2]);

    } else if (!strcmp(argv[1], "-d")) {
        printf("Unimplemented!\n");
    } else {
        return printf("Usage: %s -[e | d]\n", argv[0]), 1;
    }

    return 0;
}

