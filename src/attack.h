#pragma once

#include "types.h"

typedef struct {
    u64 *ciphers;
    u64 *clears;
    u32 start;
    u32 end;
    u8 m[3];
    u8 c[3];
} generate_t;

typedef struct {
    u64 *sorted;
    u64 *unsorted;
    i64 start;
    i64 end;
    u8 m[3];
    u8 c[3];
} research_t;

void PRESENT24_attack(u8 clear_text[3], u8 cipher_text[3], u8 clear_text2[3], u8 cipher_text2[3]);
