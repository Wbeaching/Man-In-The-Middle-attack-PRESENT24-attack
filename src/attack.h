#pragma once

#include "types.h"

typedef struct {
    u64 *encrypted;
    u64 *decrypted;
    u32 start;
    u32 end;
    u8 m[3];
    u8 c[3];
} dictionary_t;

typedef struct {
    u64 *sorted;
    u64 *unsorted;
    i64 start;
    i64 end;
    u8 m[3];
    u8 c[3];
} attack_t;

void PRESENT24_attack(u8 m1[3], u8 c1[3], u8 m2[3], u8 c2[3], size_t NB_THREADS);
