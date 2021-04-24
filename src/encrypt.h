#pragma once

#include "types.h"

void generate_round_keys(u64 master_key, u32 keys[11]);
u32 PRESENT24_encrypt(u32 message, u32 key[11]);
