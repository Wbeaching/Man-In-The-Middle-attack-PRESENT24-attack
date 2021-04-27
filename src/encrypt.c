#include <stdio.h>
#include <string.h>

#include "encrypt.h"

u8 sbox_layer_encrypt(u8 byte) {
    static const u8 sbox[16] = {
        0x0C, 0x05, 0x06, 0x0B,
        0x09, 0x00, 0x0A, 0x0D,
        0x03, 0x0E, 0x0F, 0x08,
        0x04, 0x07, 0x01, 0x02
    };

    return (sbox[((byte & 0xF0) >> 4)] << 4) | (sbox[byte & 0x0F]);
}

/*
u8 pbox_layer(u8 message) {
    u32 r = 0x0C0600;

    for (u8 j = 0; j < 24; j++) {
        message |= ((message >> j) & 0x01) << (r & 0xFF);
        r = ROTATE(r + 1, 6);
    }

    return message;
}
*/

u8 *pbox_layer_encrypt(u8 message[3]) {
    static const u8 pbox[24] = {
        0, 6,  12, 18,
        1, 7,  13, 19,
        2, 8,  14, 20,
        3, 9,  15, 21,
        4, 10, 16, 22,
        5, 11, 17, 23
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
        message = pbox_layer_encrypt(message);

        //printf("State:  %x%x%x\n", message[0], message[1], message[2]);
    }

    // XOR with key11
    for (u8 i = 0; i < 3; i++) {
        message[i] ^= round_key[10][i];
    }

    // return cipher
    return message;
}
