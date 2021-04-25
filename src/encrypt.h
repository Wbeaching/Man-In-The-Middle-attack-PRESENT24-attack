#pragma once

#include "types.h"

u8 *PRESENT24_encrypt(u8 message[3], u8 subkeys[11][3]);
void generate_round_keys(u8 master_key[10], u8 keys[11][3]);
