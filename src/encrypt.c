#include "types.h"
#include "encrypt.h"

#define ROTATE(value, n) (((value) >> (n)) | ((value) << (24 - n)))

void generate_round_keys(u64 master_key, u32 keys[11]) {

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

u32 pbox_layer(u32 message) {
    u32 r = 0x1B120600;

    for (u8 j = 0; j < 24; j++) {
        message |= ((message >> j) & 0x01) << (r & 0xFF);
        r = ROTATE(r + 1, 6);
    }

    return message;
}

u32 PRESENT24_encrypt(u32 message, u32 key[11]) {
    // 10 rounds of the cipher
    for (u8 i = 0; i < 10; i++) {
        // XOR key with message
        message = message ^ key[i];

        // SBox layer
        for (u8 j = 0; j < 3; j++) {
            ((u8 *)&message)[j] = sbox_layer(((u8 *)&message)[j]);
        }

        // PBox layer
        message = pbox_layer(message);
    }

    // XOR with key11
    message ^= key[10];

    // return cipher
    return message;
}
