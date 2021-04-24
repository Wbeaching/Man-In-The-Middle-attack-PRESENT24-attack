#include "types.h"
#include "encrypt.h"
#include <string.h>

#define ROTATE(value, n) (((value) >> (n)) | ((value) << (24 - n)))

void generate_round_keys(u8 master_key[10], u8 keys[11][3]) {
    for (u8 i = 0; i < 11; i++) {
    }
}

u8 sbox_layer(u8 byte) {
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
    u32 r = 0x120C0600;

    for (u8 j = 0; j < 24; j++) {
        message |= ((message >> j) & 0x01) << (r & 0xFF);
        r = ROTATE(r + 1, 6);
    }

    return message;
}
*/

u8 compress_to_byte(u8 *message, u8 pos) {
    u8 compressed = 0;

    for (u8 i = pos; i < pos + 8; i++) {
        compressed |= message[i];
    }

    return compressed;
}

u8 *pbox_layer(u8 message[3]) {
    static const u8 pbox[24] = {
        0, 6,  12, 18,
        1, 7,  13, 19,
        2, 8,  14, 20,
        3, 9,  15, 21,
        4, 10, 16, 22,
        5, 11, 17, 23
    };

    u8 tmp_message[24];
    for (u8 i = 0, j = 0; i < 24; i++) {
        tmp_message[i] = (message[j] >> i % 8) & 0x01;
        j += (i % 8 && i > 7) ? 1 : 0;
    }

    for (u8 i = 0; i < 24; i++) {
        tmp_message[i] = tmp_message[i] << pbox[i];
    }

    for (u8 i = 0; i < 3; i++) {
        message[i] = compress_to_byte(tmp_message, i);
    }

    return message;
}

u8 *PRESENT24_encrypt(u8 message[3], u8 subkeys[11][3]) {
    // 11 rounds of the cipher
    for (u8 i = 0; i < 10; i++) {
        // XOR key with message
        for (u8 j = 0; j < 3; j++) {
            message[j] ^= subkeys[i][j];
        }

        // SBox layer
        for (u8 j = 0; j < 3; j++) {
            message[j] = sbox_layer(message[j]);
        }

        // PBox layer
        message = pbox_layer(message);
    }

    // XOR with key11
    for (u8 i = 0; i < 3; i++) {
        message[i] ^= subkeys[10][i];
    }

    // return cipher
    return message;
}
