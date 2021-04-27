#pragma once

#include "types.h"

#define ROTATE(value, n) (((value) >> (n)) | ((value) << (24 - n)))

void generate_round_keys(u8 key_reg[10], u8 round_key[11][3]);
void print_bin(u8 c);
