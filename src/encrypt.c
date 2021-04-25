#include "types.h"
#include "encrypt.h"
#include <string.h>

#define ROTATE(value, n) (((value) >> (n)) | ((value) << (24 - n)))

u8 sbox_layer(u8 byte) {
    static const u8 sbox[16] = {
        0x0C, 0x05, 0x06, 0x0B,
        0x09, 0x00, 0x0A, 0x0D,
        0x03, 0x0E, 0x0F, 0x08,
        0x04, 0x07, 0x01, 0x02
    };

    return (sbox[((byte & 0xF0) >> 4)] << 4) | (sbox[byte & 0x0F]);
}

void print_bin(unsigned char c) {
	for( int i = 7; i >= 0; i-- ) {
    	printf( "%d", ( c >> i ) & 1 ? 1 : 0 );
	}

	printf("\n");
}

void generate_round_keys(u8 master_key[10], u8 keys[11][3]) {
    u8 tab_shift_61[10];

    for (u8 i = 0; i < 11; i++) {
        keys[i][0] = master_key[5];
        keys[i][1] = master_key[6];
        keys[i][2] = master_key[7];

        tab_shift_61[0] = master_key[7] << 5 | master_key[8] >> 3;
        tab_shift_61[1] = master_key[8] << 5 | master_key[9] >> 3;
        tab_shift_61[2] = master_key[9] << 5 | master_key[0] >> 3;
        tab_shift_61[3] = master_key[0] << 5 | master_key[1] >> 3;
        tab_shift_61[4] = master_key[1] << 5 | master_key[2] >> 3;
        tab_shift_61[5] = master_key[2] << 5 | master_key[3] >> 3;
        tab_shift_61[6] = master_key[3] << 5 | master_key[4] >> 3;
        tab_shift_61[7] = master_key[4] << 5 | master_key[5] >> 3;
        tab_shift_61[8] = master_key[5] << 5 | master_key[6] >> 3;
        tab_shift_61[9] = master_key[6] << 5 | master_key[7] >> 3;  

        tab_shift_61[0] = (sbox_layer(tab_shift_61[0]) & 0xf0) | (tab_shift_61[0] & 0x0f);

        tab_shift_61[7] ^= (i+1) >> 1;
        tab_shift_61[8] ^= (i+1) << 7;

        for (int j = 0; j < 10; j++) {
            master_key[j] = tab_shift_61[j];
        }
    }
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

u8 *compress_to_byte(u8 *message) {
    u8 compressed[3];

    for (u8 i = 0, j = 0; i < 24; i++) {
        compressed[j] |= message[i] << (i%8);
        j += ((i % 8) && (i > 7)) ? 1 : 0;
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
        tmp_message[i] = (message[j] >> (i % 8)) & 0x01;
        j += ((i % 8) && (i > 7)) ? 1 : 0;
    }

    u8 tmp_message2[24];
    for (u8 i = 0; i < 24; i++) {
        tmp_message2[i] = tmp_message[pbox[i]];
    }

    // for (u8 i = 0; i < 3; i++) {
    //     message[i] = compress_to_byte(tmp_message2, i);
    // }

    message = compress_to_byte(tmp_message2);

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
        *message = pbox_layer(message);
        
        printf("etat %X%X%X\n", message[0], message[1], message[2]);
    }


    // XOR with key11
    for (u8 i = 0; i < 3; i++) {
        message[i] ^= subkeys[10][i];
    }


    // return cipher
    return message;
}
