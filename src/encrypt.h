#pragma once

#include "types.h"

u8 sbox_layer_encrypt(u8 byte);
u8 *PRESENT24_encrypt(u8 message[3], u8 subkeys[11][3]);
void main_encrypt(i8 *message, i8 *key);