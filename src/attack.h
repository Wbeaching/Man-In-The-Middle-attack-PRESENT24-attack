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
 * Perfoms a Man In The Middle Attack on the 2PRESENT24 block cipher.
 *
 * For every possible key, puts the results of the encryption of m1 and
 * the decryption of c1 in arrays (dictionaries).
 * Sorts both of these using radix sort.
 * Iterates over one of the arrays and looks for a matching result in the other
 * using a recursive binary search. If a collision is found (i.e the binary
 * search returns a valid index), a check is performed for pair of keys
 * k1 and k2 (used to encrypt/decrypt the matching texts) with m2 and c2.
 * The check by encrypting m2. The result is then re-encrypted, if it matches
 * with c2, then the pair of keys k1 and k2 is valid.
 *
 * @param m1 The message to use to generate the encrypt dictionary.
 * @param c1 The cipher to use to generate the decrypt dictionary.
 * @param m2 The message used to check that a pair of keys k1 and k2 is valid.
 * @param c2 The cipher used to check that a pair of keys k1 and k2 is valid.
 * @param rk NB_THREADS The number of threads to use to parallelize the attack.
 */
void PRESENT24_attack(u8 m1[3], u8 c1[3], u8 m2[3], u8 c2[3], size_t NB_THREADS);

/**
 * Sets up the needed parameters if the program was started
 * in attack mode. Avoids having all the code in the main function.
 *
 * @param nb_args The number of arguments passed.
 * @param args The array of passed arguments.
 */
void main_attack(i32 nb_args, i8 **args);
