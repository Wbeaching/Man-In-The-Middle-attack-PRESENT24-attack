#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "encrypt.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        return printf("Usage: %s -[e | d] TEST_VECTOR\n", argv[0]), 1;
    }

    static const u64 master_key[3] = {
        0x000000,
        0xffffff,
        0xd1bd2d
    };

    static const u32 clear_text[3] = {
        0x000000,
        0x000000,
        0xf955b9
    };

    u32 vector = atoi(argv[2]);
    if (vector > 2) {
        printf("Test vector must be between 0 and 2\n");
        return printf("Usage: %s -[e | d] KEY TEST_VECTOR\n", argv[0]), 1;
    }

    if (!strcmp(argv[1], "-e")) {
        u32 key[11];

        generate_round_keys(master_key[vector], key);

        u32 cipher = PRESENT24_encrypt(clear_text[vector], key);

        printf("Cipher: %x", cipher);
    } else if (!strcmp(argv[1], "-d")) {
        printf("Unimplemented!\n");
    } else {
        return printf("Usage: %s -[e | d] KEY\n", argv[0]), 1;
    }

    return 0;
}

