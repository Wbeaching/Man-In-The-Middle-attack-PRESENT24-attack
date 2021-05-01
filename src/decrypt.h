#pragma once

#include "types.h"

u8 *PRESENT24_decrypt(u8 message[3], u8 round_key[11][3]);
void main_decrypt(i8 *cipher, i8 *key);