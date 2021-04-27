#include <stdio.h>
#include <string.h>

#include "decrypt.h"

u8 sbox_layer_decrypt(u8 byte) {
    static const u8 sbox[16] = {
        0x05, 0x0E, 0x0F, 0x08,
        0x0C, 0x01, 0x02, 0x0D,
        0x0B, 0x04, 0x06, 0x03,
        0x00, 0x07, 0x09, 0x0A
    };

    return (sbox[((byte & 0xF0) >> 4)] << 4) | (sbox[byte & 0x0F]);
}

u8 *pbox_layer_decrypt(u8 message[3]) {
    static const u8 pbox[24] = {
        0,  4,  8,  12,
        16, 20, 1,  5,
        9,  13, 17, 21,
        2,  6,  10, 14,
        18, 22, 3,  7,
        11, 15, 19, 23
    };

    u8 tmp_message[24];
    // Translate 3 bytes array to 24 bytes array containing 1 bit each
    for (u8 i = 0, j = 0; i < 24; i++) {
        j += (((i & 7) == 0) && (i > 0));
        tmp_message[pbox[i]] = (message[j] << (i & 7)) & 0x80;
    }

    // Recompress the 24 bytes back into a 3 bytes array
    u8 compressed[3] = { 0x00, 0x00, 0x00 };
    for (u8 i = 0, j = 0; i < 24; i++) {
        j += (((i & 7) == 0) && (i > 0));
        compressed[j] |= tmp_message[i] >> (i & 7);
    }

    for (u8 i = 0; i < 3; i++) {
        message[i] = compressed[i];
    }

    return message;
}

u8 *PRESENT24_decrypt(u8 message[3], u8 round_key[11][3]) {
    // XOR with key11
    for (u8 i = 0; i < 3; i++) {
        message[i] ^= round_key[10][i];
    }

    // 11 rounds of the clear
    for (u8 i = 10; i > 0; i--) {
        // PBox layer
        message = pbox_layer_decrypt(message);

        // SBox layer
        for (u8 j = 0; j < 3; j++) {
            message[j] = sbox_layer_decrypt(message[j]);
        }

        // XOR key with message
        for (u8 j = 0; j < 3; j++) {
            message[j] ^= round_key[i - 1][j];
        }

        // printf("State:  %x%x%x\n", message[0], message[1], message[2]);
    }

    // return clear text
    return message;
}
