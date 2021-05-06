#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "err.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

typedef void *(*fn_ptr)(void *arg);

static inline
void radix_sort_pass(u64 *restrict src, u64 *restrict dst, size_t n, size_t shift)
{
    size_t index[256] = { 0 }, next_index = 0, count;

    // Count every occurence of the masked digit using the index array
    for (size_t i = 0; i < n; i++)
    {
        index[(src[i] >> shift) & 0xff]++;
    }

    // Accumulate the value of indices into a counter
    for (size_t i = 0; i < 256; i++)
    {
        count = index[i];
        index[i] = next_index;
        next_index += count;
    }

    // Place the values back into the destination array using the index array
    for (size_t i = 0; i < n; i++)
    {
        dst[index[(src[i] >> shift) & 0xff]++] = src[i];
    }
}

static inline
void radix_sort(u64 *restrict arr, u64 *restrict tmp, size_t n)
{
    // Perform 3 pass on the array (8 bits evaluated and counted per pass)
    radix_sort_pass(arr, tmp, n, 0 * 8);
    radix_sort_pass(tmp, arr, n, 1 * 8);
    radix_sort_pass(arr, tmp, n, 2 * 8);

    // Put the values of the last pass back into the original array
    for (size_t i = 0; i < n; i++)
    {
        arr[i] = tmp[i];
    }
}

static
void verify_keys(u64 encrypted, u64 decrypted, u8 m2[3], u8 c2[3])
{
    u8  k1[10], k2[10], rk1[11][3], rk2[11][3], tmp_m2[3];

    // Initialize the key registers with the master keys and copy m2 into tmp_m2
    for (u8 i = 0; i < 3; i++)
    {
        k1[i] = (encrypted & MASK_K64) >> (40 - (i * 8));
        k2[i] = (decrypted & MASK_K64) >> (40 - (i * 8));
        tmp_m2[i] = m2[i];
    }

    // Generate the round keys for the first and second encryption
    generate_round_keys(k1, rk1);
    generate_round_keys(k2, rk2);

    // Encrypt the copy of m2 with the first round keys
    PRESENT24_encrypt(tmp_m2, rk1);
    // Encrypt the result of the first encryption with the second round keys
    PRESENT24_encrypt(tmp_m2, rk2);

    // Check if the result of the second encryption matches with c2
    if ((tmp_m2[0] == c2[0]) && (tmp_m2[1] == c2[1]) && (tmp_m2[2] == c2[2]))
    {
        info();
        printf("\x1b[32mFound a valid pair (k1, k2)!\x1b[0m\n    k1: %02x%02x%02x | k2: %02x%02x%02x\n\n",
            (u8)(0xff & (encrypted >> 40)), (u8)(0xff & (encrypted >> 32)),
            (u8)(0xff & (encrypted >> 24)), (u8)(0xff & (decrypted >> 40)),
            (u8)(0xff & (decrypted >> 32)), (u8)(0xff & (decrypted >> 24))
        );
    }
}

static
i64 binary_search(u64 *dict, i64 lo, i64 hi, u64 target, u8 m2[3], u8 c2[3])
{
    // Check that high index is greater than low index
    if (hi > lo)
    {
        // Compute the middle index
        i64 mid = lo + (hi - lo) / 2;

        // If the target is equal to dict[mid], there is a collision
        if ((target & MASK_T64) == (dict[mid] & MASK_T64))
        {
            // Check for possible collisions around the found target
            i64 cur = mid - 1;
            while ((cur >= lo) && ((target & MASK_T64) == (dict[cur] & MASK_T64)))
            {
                verify_keys(target, dict[cur], m2, c2);
                cur--;
            }

            cur = mid + 1;
            while ((cur <= hi) && ((target & MASK_T64) == (dict[cur] & MASK_T64)))
            {
                verify_keys(target, dict[cur], m2, c2);
                cur++;
            }

            // Return the found index
            return mid;
        }
        // If the target is less than dict[mid], call recursively
        // on the lower part of the array
        else if ((target & MASK_T64) < (dict[mid] & MASK_T64))
        {
            return binary_search(dict, lo, mid - 1, target, m2, c2);
        }
        // Else, the target is in the higher part of the array
        else
            {
            return binary_search(dict, mid + 1, hi, target, m2, c2);
        }
    }

    // If no match was found, return -1
    return -1;
}

void *attack_dictionaries(void *arg)
{
    // Cast the void argument to an attack_t
    attack_t *atk= (attack_t *)arg;

    // Iterate over the decrypted array from the given start position to
    // the given end
    // Use binary search to find possible collisions with the encrypted array
    for (i64 i = atk->start; i < atk->end; i++)
    {
        i64 index = binary_search(
                        atk->decrypted,
                        0,
                        DICT_SIZE - 1,
                        atk->encrypted[i],
                        atk->m,
                        atk->c
        );

        // If the binary search returned a valid index, check that
        // the pair of keys (k1, k2) is valid
        if (index != -1)
        {
            verify_keys(atk->encrypted[i], atk->decrypted[index], atk->m, atk->c);
        }
    }

    return NULL;
}

void *generate_dictionaries(void *arg)
{
    // Cast the void argument to an attack_t
    dictionary_t *dict = (dictionary_t*)arg;
    // Declarations for the key register and round key array
    u8 k_reg[10], rk[11][3];

    // Iterate over the arrays from the given start position to the given end
    for (u32 i = dict->start; i < dict->end; i++)
    {
        // Declare and initialize temporary copies of m and c
        u8 tmp_m[3], tmp_c[3];
        for (u8 i = 0; i < 3; i++)
        {
            tmp_m[i] = dict->m[i];
            tmp_c[i] = dict->c[i];
        }

        // Initialize the key register based on i (master key generation)
        k_reg[0] = (i & 0xff0000) >> 16;
        k_reg[1] = (i & 0x00ff00) >> 8;
        k_reg[2] =  i & 0x0000ff;

        // Place the key into the arrays (bits 48 - 63)
        dict->encrypted[i] |= k_reg[0] << 16 | k_reg[1] << 8 | k_reg[2];
        dict->decrypted[i] |= k_reg[0] << 16 | k_reg[1] << 8 | k_reg[2];
        // Shift the key in the right position in the arrays (bits 24 - 47)
        dict->encrypted[i] <<= 24;
        dict->decrypted[i] <<= 24;

        // Generate the round keys for the `i`th master key
        generate_round_keys(k_reg, rk);

        // Encrypt m using the `i`th round keys
        PRESENT24_encrypt(tmp_m, rk);
        // Decrypt c using the `i`th round keys
        PRESENT24_decrypt(tmp_c, rk);

        // Place the text in the right position in the arrays (bits 48 - 63)
        dict->encrypted[i] |= tmp_m[0] << 16 | tmp_m[1] << 8 | tmp_m[2];
        dict->decrypted[i] |= tmp_c[0] << 16 | tmp_c[1] << 8 | tmp_c[2];
    }

    return NULL;
}

static inline
void dictionary_part(
    u64 *encrypted,
    u64 *decrypted,
    u8 m1[3],
    u8 c1[3],
    size_t NB_THREADS)
{
    // Declare for measuring time
    struct timespec before, after;

    // Allocate threads and dictionary structure
    pthread_t *tid1 = malloc(sizeof(pthread_t) * NB_THREADS);
    dictionary_t *dict = malloc(sizeof(dictionary_t) * NB_THREADS);

    // Initialize function pointer for the dictionary generation part
    fn_ptr handle1 = generate_dictionaries;

    // Start time measurement for the dictionary generation
#if __linux__
    clock_gettime(CLOCK_MONOTONIC_RAW, &before);
#endif

    // Initialize dictionary structure and start threads
    for (u8 i = 0; i < NB_THREADS; i++)
    {
        dict[i].decrypted = decrypted;
        dict[i].encrypted = encrypted;
        dict[i].start = i * (DICT_SIZE / NB_THREADS);
        dict[i].end = (i + 1) * (DICT_SIZE / NB_THREADS);
        for (u8 j = 0; j < 3; j++)
        {
            dict[i].m[j] = m1[j];
            dict[i].c[j] = c1[j];
        }
        pthread_create(tid1 + i, NULL, handle1, dict + i);
    }

    // Wait for threads to finish with join
    for (u8 i = 0; i < NB_THREADS; i++)
    {
        pthread_join(tid1[i], NULL);
    }

    // Stop time measurement for the dictionary generation
#if __linux__
    clock_gettime(CLOCK_MONOTONIC_RAW, &after);
    // Print time taken to terminal
    printf("done in %.3lf secs\n", measure_time(&before, &after));
#endif

    // Free the threads and dictionary structure
    free(dict);
    free(tid1);
}

static inline
void sorting_part(u64 *encrypted, u64 *decrypted)
{
    // Declare for measuring time
    struct timespec before, after;

    // Allocate a temporary array for the radix sort
    u64 *tmp = malloc(sizeof(u64) * DICT_SIZE);

    // Start time measurement for the sorting part
#if __linux__
    clock_gettime(CLOCK_MONOTONIC_RAW, &before);
#endif

    // Sorting both dictionaries for faster lookup
    radix_sort(decrypted, tmp, DICT_SIZE);
    radix_sort(encrypted, tmp, DICT_SIZE);

    // Stop time measurement for the sorting part
#if __linux__
    clock_gettime(CLOCK_MONOTONIC_RAW, &after);
    // Print time taken to terminal
    printf("done in %.3lf secs\n", measure_time(&before, &after));
#endif

    // Free the temporary array
    free(tmp);
}

static inline
void attack_part(
    u64 *encrypted,
    u64 *decrypted,
    u8 m2[3],
    u8 c2[3],
    size_t NB_THREADS)
{
    // Declare for measuring time
    struct timespec before, after;

    // Allocate threads and attack structure
    pthread_t *tid2 = malloc(sizeof(pthread_t) * NB_THREADS);
    attack_t *atk = malloc(sizeof(attack_t) * NB_THREADS);

    // Initialize function pointer for attack part
    fn_ptr handle2 = attack_dictionaries;

    // Start time measurement for the attack part
#if __linux__
    clock_gettime(CLOCK_MONOTONIC_RAW, &before);
#endif

    // Initialize attaack structure and start threads
    for (u8 i = 0; i < NB_THREADS; i++)
    {
        atk[i].start = i * (DICT_SIZE / NB_THREADS);
        atk[i].end = (i + 1) * (DICT_SIZE / NB_THREADS);
        atk[i].decrypted = decrypted;
        atk[i].encrypted = encrypted;
        for (u8 j = 0; j < 3; j++)
        {
            atk[i].m[j] = m2[j];
            atk[i].c[j] = c2[j];
        }
        pthread_create(tid2 + i, NULL, handle2, atk + i);
    }

    // Wait for threads to finish with join
    for (u8 i = 0; i < NB_THREADS; i++)
    {
        pthread_join(tid2[i], NULL);
    }

    // Stop time measurement for the attack part
#if __linux__
    clock_gettime(CLOCK_MONOTONIC_RAW, &after);
    // Print time taken to terminal
    info(); printf("Attack finished in %.3lf secs\n", measure_time(&before, &after));
#endif

    // Free threads and attack structure
    free(tid2);
    free(atk);
}

void PRESENT24_attack(u8 m1[3], u8 c1[3], u8 m2[3], u8 c2[3], size_t NB_THREADS)
{
    info(); printf("Attack parallelized with %lu threads\n", NB_THREADS);

    // Allocate arrays
    u64 *encrypted = malloc(sizeof(u64) * DICT_SIZE);
    u64 *decrypted = malloc(sizeof(u64) * DICT_SIZE);

#if __linux__
    info(); printf("Generating dictionaries... ");
#else
    info(); printf("Generating dictionaries\n");
#endif
    dictionary_part(encrypted, decrypted, m1, c1, NB_THREADS);

#if __linux__
    info(); printf("Sorting dictionaries... ");
#else
    info(); printf("Sorting dictionaries\n");
#endif
    sorting_part(encrypted, decrypted);

    info(); printf("Searching for a valid pair of keys...\n");
    attack_part(encrypted, decrypted, m2, c2, NB_THREADS);

    // Free arrays
    free(decrypted);
    free(encrypted);
}

void main_attack(i32 numb_args, i8 **args)
{
    struct timespec before, after;
    i32 a2 = strtol(args[2], NULL, 16);
    i32 a3 = strtol(args[3], NULL, 16);
    i32 a4 = strtol(args[4], NULL, 16);
    i32 a5 = strtol(args[5], NULL, 16);
    size_t NB_THREADS = 4;

    if (numb_args == 8)
    {
        if (!strcmp(args[6], "-t"))
        {
            size_t a7 = atoi(args[7]);
            if (a7 > 0 && a7 < 1025)
            {
                NB_THREADS = a7;
            }
            else
            {
                warn();
                printf("%lu is an invalid number of threads, running with 4 by default\n", a7);
            }
        }
        else {
            warn();
            printf("Invalid thread option, running with 4 by default\n");
        }
    }

    u8 m1[3] = {
        (a2 & 0xff0000) >> 16,
        (a2 & 0x00ff00) >> 8,
        (a2 & 0x0000ff)
    };

    u8 c1[3] = {
        (a3 & 0xff0000) >> 16,
        (a3 & 0x00ff00) >> 8,
        (a3 & 0x0000ff)
    };

    u8 m2[3] = {
        (a4 & 0xff0000) >> 16,
        (a4 & 0x00ff00) >> 8,
        (a4 & 0x0000ff)
    };

    u8 c2[3] = {
        (a5 & 0xff0000) >> 16,
        (a5 & 0x00ff00) >> 8,
        (a5 & 0x0000ff)
    };

    printf("\x1b[1mMan In The Middle attack on 2PRESENT24 with:\x1b[0m\n");
    printf("    Message 1: %02x%02x%02x | ", m1[0], m1[1], m1[2]);
    printf("Cipher 1:  %02x%02x%02x\n", c1[0], c1[1], c1[2]);
    printf("    Message 2: %02x%02x%02x | ", m2[0], m2[1], m2[2]);
    printf("Cipher 2:  %02x%02x%02x\n\n", c2[0], c2[1], c2[2]);

#if __linux__
    clock_gettime(CLOCK_MONOTONIC_RAW, &before);
#endif
    PRESENT24_attack(m1, c1, m2, c2, NB_THREADS);
#ifdef __linux__
    clock_gettime(CLOCK_MONOTONIC_RAW, &after);

    info(); printf("Program run in \x1b[1m%.3lf secs\x1b[0m\n", measure_time(&before, &after));
#endif
}
