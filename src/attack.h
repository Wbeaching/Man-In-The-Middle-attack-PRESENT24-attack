#pragma once

#include "types.h"

typedef struct {
    u64 *ciphers;
    u64 *clears;
    u8 clear_text[3];
    u8 cipher_text[3];
    u32 start;
    u32 end;
} message_t;

u8 *PRESENT24_attack(u8 clear_text[3], u8 cipher_text[3], u8 clear_text2[3], u8 cipher_text2[3]);
