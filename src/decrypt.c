#include <stdio.h>
#include <string.h>

#include "decrypt.h"

inline u8 sbox_layer_decrypt(u8 byte) {
    static const u8 sbox[16] = {
        0x05, 0x0E, 0x0F, 0x08,
        0x0C, 0x01, 0x02, 0x0D,
        0x0B, 0x04, 0x06, 0x03,
        0x00, 0x07, 0x09, 0x0A
    };

    return (sbox[((byte & 0xF0) >> 4)] << 4) | (sbox[byte & 0x0F]);
}

static inline u8 *pbox_layer_decrypt(u8 m[3]) {
    u8 p[3];

    p[0] = (m[0] & 0x80)      | (m[0] & 0x02) << 5 | (m[1] & 0x08) << 2 | (m[2] & 0x20) >> 1 |
           (m[0] & 0x40) >> 3 | (m[0] & 0x01) << 2 | (m[1] & 0x04) >> 1 | (m[2] & 0x10) >> 4;

    p[1] = (m[0] & 0x20) << 2 | (m[1] & 0x80) >> 1 | (m[1] & 0x02) << 4 | (m[2] & 0x08) << 1 |
           (m[0] & 0x10) >> 1 | (m[1] & 0x40) >> 4 | (m[1] & 0x01) << 1 | (m[2] & 0x04) >> 2;

    p[2] = (m[0] & 0x08) << 4 | (m[1] & 0x20) << 1 | (m[2] & 0x80) >> 2 | (m[2] & 0x02) << 3 |
           (m[0] & 0x04) << 1 | (m[1] & 0x10) >> 2 | (m[2] & 0x40) >> 5 | (m[2] & 0x01);

    for (u8 i = 0; i < 3; i++) {
        m[i] = p[i];
    }

    return m;
}

/*
static inline u8 *pbox_layer_decrypt(u8 message[3]) {
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
    for (u8 i = 0, j = 0; i < 24; i += 8, j++) {
        tmp_message[pbox[i]] = (message[j] << (i & 7)) & 0x80;
        tmp_message[pbox[i + 1]] = (message[j] << ((i + 1) & 7)) & 0x80;
        tmp_message[pbox[i + 2]] = (message[j] << ((i + 2) & 7)) & 0x80;
        tmp_message[pbox[i + 3]] = (message[j] << ((i + 3) & 7)) & 0x80;
        tmp_message[pbox[i + 4]] = (message[j] << ((i + 4) & 7)) & 0x80;
        tmp_message[pbox[i + 5]] = (message[j] << ((i + 5) & 7)) & 0x80;
        tmp_message[pbox[i + 6]] = (message[j] << ((i + 6) & 7)) & 0x80;
        tmp_message[pbox[i + 7]] = (message[j] << ((i + 7) & 7)) & 0x80;
    }

    // Recompress the 24 bytes back into a 3 bytes array
    u8 compressed[3] = { 0x00, 0x00, 0x00 };
    for (u8 i = 0, j = 0; i < 24; i++) {
        j += (((i & 7) == 0) && (i > 0));
        compressed[j] |= tmp_message[i] >> (i & 7);
        message[j] = compressed[j];
    }

    return message;
}*/

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
