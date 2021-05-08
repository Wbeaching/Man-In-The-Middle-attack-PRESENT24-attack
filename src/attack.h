#pragma once

#include "types.h"

/**
 * A structure that holds the data that a thread needs to perform
 * the dictionary generation.
 */
typedef struct {
    // The array of texts that will be encrypted
    u64 *encrypted;

    // The array of texts that will be decrypted
    u64 *decrypted;

    // The array's starting index on which the thread will work
    u32 start;

    // The array's ending index on which the thread will work
    u32 end;

    // The plain text that need to be encrypted
    u8 m[3];

    // The cipher text that need to be decrypted
    u8 c[3];
} dictionary_t;

/**
 * A structure that holds the data that a thread needs to perform
 * the attack on the dictionaries.
 */
typedef struct {
    // The array of encrypted texts
    u64 *encrypted;

    // The array of decrypted texts
    u64 *decrypted;

    // The array's starting index on which the thread will work
    u32 start;

    // The array's ending index on which the thread will work
    u32 end;

    // The plain text that need to be encrypted
    u8 m[3];

    // The cipher text that need to be decrypted
    u8 c[3];
} attack_t;

/**
 * Sets up the needed parameters if the program was started
 * in attack mode. Avoids having all the code in the main function.
 *
 * @param nb_args The number of arguments passed.
 * @param args The array of passed arguments.
 */
void main_attack(i32 nb_args, i8 **args);
