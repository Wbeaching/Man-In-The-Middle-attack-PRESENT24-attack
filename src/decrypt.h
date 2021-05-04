#pragma once

#include "types.h"

/**
 * Decrypts a given message with the given round keys.
 *
 * Applies the PRESENT24 decryption algorithm on the given message
 * using the given round keys.
 *
 * @param m The message to decrypt.
 * @param rk The round keys to use for the decryption.
 */
void PRESENT24_decrypt(u8 m[3], u8 rk[11][3]);

/**
 * Sets up the needed parameters if the program was started
 * in decryption mode. Avoids having all the code in the main function.
 *
 * @param cipher The message to decrypt.
 * @param key The master key to use for the decryption.
 */
void main_decrypt(i8 *cipher, i8 *key);
