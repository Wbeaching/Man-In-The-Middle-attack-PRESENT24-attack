#include <stdio.h>
#include <string.h>

#include "common.h"
#include "err.h"
#include "encrypt.h"

inline
f64 measure_time(struct timespec *before, struct timespec *after) {
    return (after->tv_sec - before->tv_sec) +
        (after->tv_nsec - before->tv_nsec) / 1E9;
}

inline
u8 check_args(i8 *arg)
{
    // Check that the length of the argument is correct
    if (strlen(arg) > 6)
    {
        err(5);
        printf("Invalid size for argument `%s`\n", arg);
        return 5;
    }

    // Iterate over the characters of the argument
    for (size_t i = 0; i < strlen(arg); i++)
    {
        // Check that the argument is a valid hexadecimal value
        if (arg[i] < 47 || (arg[i] > 57 && arg[i] < 64) ||
            (arg[i] > 70 && arg[i] < 96) || arg[i] > 102)
        {
            err(6);
            printf("Invalid character `%c` in argument `%s`\n", arg[i], arg);
            return 6;
        }
    }

    return 0;
}

inline
void generate_round_keys(u8 k_reg[10], u8 rk[11][3])
{
    u8 shifted_reg[10];
    // Initialize the rest of the key register
    for (u8 i = 3; i < 10; i++)
    {
        k_reg[i] = 0;
    }

    // Perform the 11 rounds of key generation
    for (u8 i = 0; i < 11; i++)
    {
        // Update the round key
        rk[i][0] = k_reg[5];
        rk[i][1] = k_reg[6];
        rk[i][2] = k_reg[7];

        // Shift the key register by 61 to the left
        shifted_reg[0] = k_reg[7] << 5 | k_reg[8] >> 3;
        shifted_reg[1] = k_reg[8] << 5 | k_reg[9] >> 3;
        shifted_reg[2] = k_reg[9] << 5 | k_reg[0] >> 3;
        shifted_reg[3] = k_reg[0] << 5 | k_reg[1] >> 3;
        shifted_reg[4] = k_reg[1] << 5 | k_reg[2] >> 3;
        shifted_reg[5] = k_reg[2] << 5 | k_reg[3] >> 3;
        shifted_reg[6] = k_reg[3] << 5 | k_reg[4] >> 3;
        shifted_reg[7] = k_reg[4] << 5 | k_reg[5] >> 3;
        shifted_reg[8] = k_reg[5] << 5 | k_reg[6] >> 3;
        shifted_reg[9] = k_reg[6] << 5 | k_reg[7] >> 3;

        // First 4 high-order bits of the key register through the S-Box
        shifted_reg[0] = (sbox_layer_encrypt(shifted_reg[0]) & 0xF0) | (shifted_reg[0] & 0x0F);

        // XOR bits 19 to 15 with round counter
        shifted_reg[7] ^= (i + 1) >> 1;
        shifted_reg[8] ^= (i + 1) << 7;

        // Copy the temporarily shifted key register to the original
        for (int j = 0; j < 10; j++)
        {
            k_reg[j] = shifted_reg[j];
        }
    }
}
