#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "encrypt.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        return printf("Usage: %s -[e | d] TEST_VECTOR\n", argv[0]), 1;
    }

    static const u8 master_key[3][10] = {
        { 0x00, 0x00, 0x00 },
        { 0xff, 0xff, 0xff },
        { 0xd1, 0xbd, 0x2d }
    };

    static const u8 clear_text[3][3] = {
        { 0x00, 0x00, 0x00 },
        { 0x00, 0x00, 0x00 },
        { 0xf9, 0x55, 0xb9 }
    };

    u32 vector = atoi(argv[2]);
    if (vector > 2) {
        printf("Test vector must be between 0 and 2\n");
        return printf("Usage: %s -[e | d] KEY TEST_VECTOR\n", argv[0]), 1;

        u8 subkeys[11][3];
        memcpy(subkeys[0], master_key[vector], 8);

        PRESENT24_encrypt(clear_text[vector], subkeys);
    }

    if (!strcmp(argv[1], "-e")) {
    } else if (!strcmp(argv[1], "-d")) {
        printf("Unimplemented!\n");
    } else {
        return printf("Usage: %s -[e | d] KEY\n", argv[0]), 1;
    }

    return 0;
}

