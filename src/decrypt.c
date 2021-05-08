#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decrypt.h"
#include "common.h"

// The substitution box for the decryption
static const u8 sbox[16] = {
    0x05, 0x0E, 0x0F, 0x08,
    0x0C, 0x01, 0x02, 0x0D,
    0x0B, 0x04, 0x06, 0x03,
    0x00, 0x07, 0x09, 0x0A
};

static inline
u8 sbox_layer_decrypt(u8 byte)
{
    // Mask the high nibble and shift it by 4 to the right so that
    // it doesn't overflow the size of the sbox and can be substituted,
    // then shift it back by 4 to the left
    // Mask the low nibble and substitute it with in sbox
    // Concatenate both and return the result to the caller
    return (sbox[((byte & 0xF0) >> 4)] << 4) | (sbox[byte & 0x0F]);
}

static inline
void pbox_layer_decrypt(u8 m[3])
{
    // Declare a variable that will hold the permutated value
    u8 p[3];

    // Directly compute all the bits that compose the permutated message using
    // masks and shifts, and concatenate them together using logical OR
    p[0] = (m[0] & 0x80)      | (m[0] & 0x02) << 5 |
           (m[1] & 0x08) << 2 | (m[2] & 0x20) >> 1 |
           (m[0] & 0x40) >> 3 | (m[0] & 0x01) << 2 |
           (m[1] & 0x04) >> 1 | (m[2] & 0x10) >> 4;

    p[1] = (m[0] & 0x20) << 2 | (m[1] & 0x80) >> 1 |
           (m[1] & 0x02) << 4 | (m[2] & 0x08) << 1 |
           (m[0] & 0x10) >> 1 | (m[1] & 0x40) >> 4 |
           (m[1] & 0x01) << 1 | (m[2] & 0x04) >> 2;

    p[2] = (m[0] & 0x08) << 4 | (m[1] & 0x20) << 1 |
           (m[2] & 0x80) >> 2 | (m[2] & 0x02) << 3 |
           (m[0] & 0x04) << 1 | (m[1] & 0x10) >> 2 |
           (m[2] & 0x40) >> 5 | (m[2] & 0x01);

    // Put the permutated message back into the given variable
    // before returning it
    for (u8 i = 0; i < 3; i++)
    {
        m[i] = p[i];
    }
}

void PRESENT24_decrypt(u8 cipher[3], u8 rk[11][3])
{
    // XOR with 11th round key for the first round of decryption
    for (u8 i = 0; i < 3; i++)
    {
        cipher[i] ^= rk[10][i];
    }

    // 10 rounds of the decryption
    for (u8 i = 10; i > 0; i--)
    {
        // Perform the Permuation layer on the cipher
        pbox_layer_decrypt(cipher);

        // Perform the S-Box layer for every byte of the cipher
        for (u8 j = 0; j < 3; j++)
        {
            cipher[j] = sbox_layer_decrypt(cipher[j]);
        }

        // XOR round key with the cipher
        for (u8 j = 0; j < 3; j++)
        {
            cipher[j] ^= rk[i - 1][j];
        }
    }
}

void main_decrypt(i8 *cipher, i8 *key)
{
    // Cast arguments as i32 values
    i32 a2 = strtol(cipher, NULL, 16);
    i32 a3 = strtol(key, NULL, 16);

    // Declare the round key array
    u8 rk[11][3];

    // Initialize the message based on the corresponding argument
    u8 c[3] = {
        (a2 & 0x00ff0000) >> 16,
        (a2 & 0x0000ff00) >> 8,
        (a2 & 0x000000ff)
    };

    // Initialize the key register based on the master key passed as argument
    u8 k_reg[10] = {
        (a3 & 0x00ff0000) >> 16,
        (a3 & 0x0000ff00) >> 8,
        (a3 & 0x000000ff), 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };

    printf("PRESENT24 decryption with:\n");
    printf("    Cipher:  %02x%02x%02x\n", c[0], c[1], c[2]);
    printf("    Key:     %02x%02x%02x\n", k_reg[0], k_reg[1], k_reg[2]);

    // Generate the round keys
    generate_round_keys(k_reg, rk);
    // Perform the decryption
    PRESENT24_decrypt(c, rk);

    printf("    Message: %02x%02x%02x\n", c[0], c[1], c[2]);
}
