#include <stdio.h>
#include <string.h>

#include "encrypt.h"

inline u8 sbox_layer_encrypt(u8 byte) {
    static const u8 sbox[16] = {
        0x0C, 0x05, 0x06, 0x0B,
        0x09, 0x00, 0x0A, 0x0D,
        0x03, 0x0E, 0x0F, 0x08,
        0x04, 0x07, 0x01, 0x02
    };

    return (sbox[((byte & 0xF0) >> 4)] << 4) | (sbox[byte & 0x0F]);
}

static inline u8 *pbox_layer_encrypt(u8 m[3]) {
    u8 p[3];

    p[0] = (m[0] & 0x80)      | (m[0] & 0x08) << 3 | (m[1] & 0x80) >> 2 | (m[1] & 0x08) << 1 |
           (m[2] & 0x80) >> 4 | (m[2] & 0x08) >> 1 | (m[0] & 0x40) >> 5 | (m[0] & 0x04) >> 2;

    p[1] = (m[1] & 0x40) << 1 | (m[1] & 0x04) << 4 | (m[2] & 0x40) >> 1 | (m[2] & 0x04) << 2 |
           (m[0] & 0x20) >> 2 | (m[0] & 0x02) << 1 | (m[1] & 0x20) >> 4 | (m[1] & 0x02) >> 1;

    p[2] = (m[2] & 0x20) << 2 | (m[2] & 0x02) << 5 | (m[0] & 0x10) << 1 | (m[0] & 0x01) << 4 |
           (m[1] & 0x10) >> 1 | (m[1] & 0x01) << 2 | (m[2] & 0x10) >> 3 | (m[2] & 0x01);

    for (u8 i = 0; i < 3; i++) {
        m[i] = p[i];
    }

    return m;
}

u8 *PRESENT24_encrypt(u8 message[3], u8 round_key[11][3]) {
    // 11 rounds of the cipher
    for (u8 i = 0; i < 10; i++) {
        // XOR key with message
        for (u8 j = 0; j < 3; j++) {
            message[j] ^= round_key[i][j];
        }

        // SBox layer
        for (u8 j = 0; j < 3; j++) {
            message[j] = sbox_layer_encrypt(message[j]);
        }

        // PBox layer
        //message = pbox_layer_encrypt(message);
        message = pbox_layer_encrypt(message);
    }

    // XOR with key11
    for (u8 i = 0; i < 3; i++) {
        message[i] ^= round_key[10][i];
    }

    // return cipher
    return message;
}
