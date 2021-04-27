#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pthread.h>

#include "common.h"
#include "encrypt.h"
#include "decrypt.h"

u8 *PRESENT24_attack(u8 clear_text[3], u8 cipher_text[3]) {
    //u64 *clears = malloc(sizeof(u64) * (pow(2, 24) - 1));
    //u64 *ciphers = malloc(sizeof(u64) * (pow(2, 24) - 1));

    u64 ciphers = 0;
    u64 clears = 0;
    u8 round_key[11][3];
    u8 key_reg[10] = {
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    };
   // for (u32 i = 0; i < (pow(2, 24) - 1); i++) {
        key_reg[0] = (0xd1bd2d & 0xff0000) >> 16;
        key_reg[1] = (0xd1bd2d & 0x00ff00) >> 8;
        key_reg[2] = 0xd1bd2d & 0x0000ff;
        ciphers |= key_reg[2] | (key_reg[1] << 8) | (key_reg[0] << 16);
        printf("%llx\n", ciphers);
        printf("T: %x%x%x\n", clear_text[0], clear_text[1], clear_text[2]);
        printf("K: %x%x%x\n", key_reg[0], key_reg[1], key_reg[2]);
        generate_round_keys(key_reg, round_key);

        u8 *result1 = PRESENT24_encrypt(clear_text, round_key);
        u8 *result2 = PRESENT24_decrypt(cipher_text, round_key);

        ciphers <<= 24;
        ciphers |= result1[2] | result1[1] << 8 | result1[0] << 16;
        printf("%llx\n", ciphers);
        clears |= result2[2] | result2[1] << 8 | result2[0] << 16;
        printf("%llx\n", clears);

        //u8 *c = PRESENT24_encrypt(clear_text, round_key);
        //printf("%x%x%x\n", c[0], c[1], c[2]);
    //}

    return clear_text;
}
