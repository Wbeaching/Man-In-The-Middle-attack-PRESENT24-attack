#pragma once

#include "types.h"

/**
 * Substitution box for the encryption part.
 *
 * The value returned is the concatenation of the high nibble and low nibble
 * of the given byte, passed through the SBox.
 *
 * @param byte The byte to substitute.
 * @return The substitued byte.
 */
u8 sbox_layer_encrypt(u8 byte);

/**
 * Encrypts a given message with the given round keys.
 *
 * Applies the PRESENT24 encryption algorithm on the given message
 * using the given round keys.
 *
 * @param m The message to encrypt.
 * @param rk The round keys to use for the encryption.
 */
void PRESENT24_encrypt(u8 m[3], u8 rk[11][3]);

/**
 * Sets up the needed parameters if the program was started
 * in encryption mode. Avoids having all the code in the main function.
 *
 * @param message The message to encrypt.
 * @param key The master key to use for the encryption.
 */
void main_encrypt(i8 *message, i8 *key);
