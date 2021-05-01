#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "common.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

typedef void *(*fn_ptr)(void *arg);

static inline
void radix_sort_pass(u64 *src, u64 *dst, size_t n, size_t shift)
{
    size_t next_index = 0, index[256] = { 0 };

    for (size_t i = 0; i < n; i++)
    {
        index[(src[i] >> shift) & 0x00000000000000ff]++;
    }

    for (size_t i = 0; i < 256; i++)
    {
        size_t count = index[i];
        index[i] = next_index;
        next_index += count;
    }

    for (size_t i = 0; i < n; i++)
    {
        dst[index[(src[i] >> shift) & 0x00000000000000ff]++] = src[i];
    }
}

static inline
void radix_sort(u64 *arr, u64 *tmp, size_t n)
{
    radix_sort_pass(arr, tmp, n, 0 * 8);
    radix_sort_pass(tmp, arr, n, 1 * 8);
    radix_sort_pass(arr, tmp, n, 2 * 8);

    for (size_t i = 0; i < n; i++)
    {
        arr[i] = tmp[i];
    }
}

static
void valid_key(u64 encrypted, u64 decrypted, u8 m2[3], u8 c2[3])
{
    u8 rk1[11][3], rk2[11][3], tmp_m2[3];
    u8 k1[10], k3[10], k2[10], k4[10];

    for (u8 i = 0; i < 3; i++)
    {
        tmp_m2[i] = m2[i];
        k1[i] = k3[i] = (encrypted & MASK_K64) >> (40 - (i * 8));
        k2[i] = k4[i] = (decrypted & MASK_K64) >> (40 - (i * 8));
    }

    generate_round_keys(k1, rk1);
    generate_round_keys(k2, rk2);

    u8 *res1 = PRESENT24_encrypt(tmp_m2, rk1);
    u8 *res2 = PRESENT24_encrypt(res1, rk2);

    if ((res2[0] == c2[0]) && (res2[1] == c2[1]) && (res2[2] == c2[2]))
    {
        printf("\nFound pair!\n    k1: %02x%02x%02x | k2: %02x%02x%02x\n",
            k3[0], k3[1], k3[2],
            k4[0], k4[1], k4[2]
        );
    }
}

static
i64 binary_search(u64 *dict, i64 lo, i64 hi, u64 target, u8 m2[3], u8 c2[3])
{
    if (hi >= lo)
    {
        i64 mid = lo + (hi - lo) / 2;

        if ((dict[mid] & MASK_T64) == (target & MASK_T64))
        {
            i64 i = 1;
            while (((mid - i) >= lo) && ((dict[mid - i] & MASK_T64) == (target & MASK_T64)))
            {
                valid_key(target, dict[mid - i], m2, c2);
                i++;
            }

            i = 1;
            while (((mid + i) <= hi) && ((dict[mid + i] & MASK_T64) == (target & MASK_T64)))
            {
                valid_key(target, dict[mid + i], m2, c2);
                i++;
            }

            return mid;
        }

        if ((dict[mid] & MASK_T64) > (target & MASK_T64))
        {
            return binary_search(dict, lo, mid - 1, target, m2, c2);
        }

        return binary_search(dict, mid + 1, hi, target, m2, c2);
    }

    return -1;
}

void *attack_dictionaries(void *arg)
{
    attack_t *r = (attack_t *)arg;

    for (i64 i = r->start; i < r->end; i++)
    {
        i64 index = binary_search(r->sorted, 0, DICT_SIZE - 1, r->unsorted[i], r->m, r->c);

        if (index != -1)
        {
            valid_key(r->unsorted[i], r->sorted[index], r->m, r->c);
        }
    }

    return NULL;
}

void *generate_dictionaries(void *arg)
{
    dictionary_t *dict = (dictionary_t*)arg;
    u8 rk[11][3], k_reg[10];

    for (u32 i = dict->start; i < dict->end; i++)
    {
        u8 tmp_m[3], tmp_c[3];
        for (u8 i = 0; i < 3; i++)
        {
            tmp_m[i] = dict->m[i];
            tmp_c[i] = dict->c[i];
        }

        k_reg[0] = (i & 0xff0000) >> 16;
        k_reg[1] = (i & 0x00ff00) >> 8;
        k_reg[2] =  i & 0x0000ff;

        dict->encrypted[i] |= k_reg[0] << 16 | k_reg[1] << 8 | k_reg[2];
        dict->decrypted[i] |= k_reg[0] << 16 | k_reg[1] << 8 | k_reg[2];

        generate_round_keys(k_reg, rk);

        u8 *res1 = PRESENT24_encrypt(tmp_m, rk);
        u8 *res2 = PRESENT24_decrypt(tmp_c, rk);

        dict->encrypted[i] <<= 24;
        dict->decrypted[i] <<= 24;

        dict->encrypted[i] |= res1[0] << 16 | res1[1] << 8 | res1[2];
        dict->decrypted[i] |= res2[0] << 16 | res2[1] << 8 | res2[2];
    }

    return NULL;
}

void PRESENT24_attack(u8 m1[3], u8 c1[3], u8 m2[3], u8 c2[3], size_t NB_THREADS)
{
    struct timespec before, after;

    u64 *decrypted = malloc(sizeof(u64) * DICT_SIZE);
    u64 *encrypted = malloc(sizeof(u64) * DICT_SIZE);
    pthread_t *tid1 = malloc(sizeof(pthread_t) * NB_THREADS);
    dictionary_t *dict = malloc(sizeof(dictionary_t) * NB_THREADS);
    fn_ptr handle1 = generate_dictionaries;

    printf("\nAttack parallelized with %lu threads\n", NB_THREADS);
    printf("Generating dictionaries... ");
    clock_gettime(CLOCK_MONOTONIC_RAW, &before);
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
    for (u8 i = 0; i < NB_THREADS; i++)
    {
        pthread_join(tid1[i], NULL);
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &after);
    measure_time(&before, &after);
    free(dict);
    free(tid1);

    u64 *tmp = malloc(sizeof(u64) * DICT_SIZE);
    printf("Sorting dictionaries... ");
    clock_gettime(CLOCK_MONOTONIC_RAW, &before);
    radix_sort(decrypted, tmp, DICT_SIZE);
    radix_sort(encrypted, tmp, DICT_SIZE);
    clock_gettime(CLOCK_MONOTONIC_RAW, &after);
    measure_time(&before, &after);
    free(tmp);

    pthread_t *tid2 = malloc(sizeof(pthread_t) * NB_THREADS);
    attack_t *atk = malloc(sizeof(attack_t) * NB_THREADS);
    fn_ptr handle2 = attack_dictionaries;
    printf("Checking for a valid key pair...\n");
    for (u8 i = 0; i < NB_THREADS; i++)
    {
        atk[i].start = i * (DICT_SIZE / NB_THREADS);
        atk[i].end = (i + 1) * (DICT_SIZE / NB_THREADS);
        atk[i].sorted = decrypted;
        atk[i].unsorted = encrypted;
        for (u8 j = 0; j < 3; j++)
        {
            atk[i].m[j] = m2[j];
            atk[i].c[j] = c2[j];
        }
        pthread_create(tid2 + i, NULL, handle2, atk + i);
    }
    for (u8 i = 0; i < NB_THREADS; i++)
    {
        pthread_join(tid2[i], NULL);
    }
    free(tid2);
    free(atk);
    free(decrypted);
    free(encrypted);
}

void main_attack(i32 numb_args, i8 **args) {
     struct timespec before, after;
    i32 a2 = strtol(args[2], NULL, 16);
    i32 a3 = strtol(args[3], NULL, 16);
    i32 a4 = strtol(args[4], NULL, 16);
    i32 a5 = strtol(args[5], NULL, 16);
    size_t NB_THREADS = 4;

    if (numb_args == 8) {
        if (!strcmp(args[6], "-t")) {
            size_t a7 = atoi(args[7]);
            if (a7 < 1) {
                warn("Invalid number of threads, running with default (4)");
            }
            else {
                NB_THREADS = a7;
            }
        }
    }

    u8 m1[3] = {
        (a2 & 0x00ff0000) >> 16,
        (a2 & 0x0000ff00) >> 8,
        (a2 & 0x000000ff)
    };

    u8 c1[3] = {
        (a3 & 0x00ff0000) >> 16,
        (a3 & 0x0000ff00) >> 8,
        (a3 & 0x000000ff)
    };

    u8 m2[3] = {
        (a4 & 0x00ff0000) >> 16,
        (a4 & 0x0000ff00) >> 8,
        (a4 & 0x000000ff)
    };

    u8 c2[3] = {
        (a5 & 0x00ff0000) >> 16,
        (a5 & 0x0000ff00) >> 8,
        (a5 & 0x000000ff)
    };

    printf("\nStarting man in the middle attack on 2PRESENT24 with:\n");
    printf("\tMessage 1: %02x%02x%02x | ", m1[0], m1[1], m1[2]);
    printf("Cipher 1:  %02x%02x%02x\n", c1[0], c1[1], c1[2]);
    printf("\tMessage 2: %02x%02x%02x | ", m2[0], m2[1], m2[2]);
    printf("Cipher 2:  %02x%02x%02x\n", c2[0], c2[1], c2[2]);

    clock_gettime(CLOCK_MONOTONIC_RAW, &before);
    PRESENT24_attack(m1, c1, m2, c2, NB_THREADS);
    clock_gettime(CLOCK_MONOTONIC_RAW, &after);

    printf("\nAttack ");
    measure_time(&before, &after);
}