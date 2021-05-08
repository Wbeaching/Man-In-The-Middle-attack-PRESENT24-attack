#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encrypt.h"
#include "common.h"

// The substitution box for the encryption
static const u8 sbox[16] = {
    0x0C, 0x05, 0x06, 0x0B,
    0x09, 0x00, 0x0A, 0x0D,
    0x03, 0x0E, 0x0F, 0x08,
    0x04, 0x07, 0x01, 0x02
};

inline
u8 sbox_layer_encrypt(u8 byte)
{
    // Mask the high nibble and shift it by 4 to the right so that
    // it doesn't overflow the size of the sbox and can be substituted,
    // then shift it back by 4 to the left
    // Mask the low nibble and substitute it with in sbox
    // Concatenate both and return the result to the caller
    return (sbox[((byte & 0xF0) >> 4)] << 4) | (sbox[byte & 0x0F]);
}

static inline
void pbox_layer_encrypt(u8 m[3])
{
    // Declare a variable that will hold the permutated value
    u8 p[3];

    // Directly compute all the bits that compose the permutated message using
    // masks and shifts, and concatenate them together using logical OR
    p[0] = (m[0] & 0x80)      | (m[0] & 0x08) << 3 |
           (m[1] & 0x80) >> 2 | (m[1] & 0x08) << 1 |
           (m[2] & 0x80) >> 4 | (m[2] & 0x08) >> 1 |
           (m[0] & 0x40) >> 5 | (m[0] & 0x04) >> 2;

    p[1] = (m[1] & 0x40) << 1 | (m[1] & 0x04) << 4 |
           (m[2] & 0x40) >> 1 | (m[2] & 0x04) << 2 |
           (m[0] & 0x20) >> 2 | (m[0] & 0x02) << 1 |
           (m[1] & 0x20) >> 4 | (m[1] & 0x02) >> 1;

    p[2] = (m[2] & 0x20) << 2 | (m[2] & 0x02) << 5 |
           (m[0] & 0x10) << 1 | (m[0] & 0x01) << 4 |
           (m[1] & 0x10) >> 1 | (m[1] & 0x01) << 2 |
           (m[2] & 0x10) >> 3 | (m[2] & 0x01);

    // Put the permutated message back into the given variable
    // before returning it
    for (u8 i = 0; i < 3; i++)
    {
        m[i] = p[i];
    }
}

void PRESENT24_encrypt(u8 m[3], u8 rk[11][3])
{
    // 10 rounds of the encryption
    for (u8 i = 0; i < 10; i++)
    {
        // XOR round key with message
        for (u8 j = 0; j < 3; j++)
        {
            m[j] ^= rk[i][j];
        }

        // Perform the S-Box layer for every byte of the message
        for (u8 j = 0; j < 3; j++)
        {
            m[j] = sbox_layer_encrypt(m[j]);
        }

        // Perform the Permuation layer on the message
        pbox_layer_encrypt(m);
    }

    // XOR the message with the 11th round key for the final round of encryption
    for (u8 i = 0; i < 3; i++)
    {
        m[i] ^= rk[10][i];
    }
}

extern
void main_encrypt(i8 *message, i8 *key)
{
    // Cast arguments as i32 values
    i32 a2 = strtol(message, NULL, 16);
    i32 a3 = strtol(key, NULL, 16);

    // Declare the round key array
    u8 rk[11][3];

    // Initialize the message based on the corresponding argument
    u8 m[3] = {
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

    printf("PRESENT24 encryption with:\n");
    printf("    Message: %02x%02x%02x\n", m[0], m[1], m[2]);
    printf("    Key:     %02x%02x%02x\n", k_reg[0], k_reg[1], k_reg[2]);

    // Generate the round keys
    generate_round_keys(k_reg, rk);
    // Perform the encryption
    PRESENT24_encrypt(m, rk);

    printf("    Cipher:  %02x%02x%02x\n", m[0], m[1], m[2]);
}
