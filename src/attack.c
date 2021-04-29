#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "common.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

typedef void *(*func_ptr)(void *arg);

static inline
void swap(u64 *x, u64 *y) {
    u64 tmp = *x;
    *x = *y;
    *y = tmp;
}

//
u64 partition(u64 *arr, i64 low, i64 high) {
    u64 pivot = arr[high] & 0x0000000000ffffff;
    i64 i = (low - 1);

    for (i64 j = low; j < high; j++) {
        if ((arr[j] & 0x0000000000ffffff) < pivot) {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);

    return (i + 1);
}

//
void quick_sort(u64 *arr, i64 low, i64 high) {
    if (arr) {
        if (low < high) {
            u64 part_index = partition(arr, low, high);
            quick_sort(arr, low, part_index - 1);
            quick_sort(arr, part_index + 1, high);
        }
    } else {
        printf("Error: arr_t pointer is already NULL\n");
    }
}

void valid_key(u64 ciphers, u64 clears, u8 m2[3], u8 c2[3]) {
    // First step
    u8 k1[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    u8 k3[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    u8 k2[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    u8 k4[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    u8 round_key1[11][3];
    k1[0] = k3[0] = (ciphers & 0x0000ffffff000000) >> 40;
    k1[1] = k3[1] = (ciphers & 0x0000ffffff000000) >> 32;
    k1[2] = k3[2] = (ciphers & 0x0000ffffff000000) >> 24;
    generate_round_keys(k1, round_key1);

    u8 message[3];
    message[0] = m2[0];
    message[1] = m2[1];
    message[2] = m2[2];
    u8 *result1 = PRESENT24_encrypt(message, round_key1);

    u8 round_key2[11][3];
    k2[0] = k4[0] = (clears & 0x0000ffffff000000) >> 40;
    k2[1] = k4[1] = (clears & 0x0000ffffff000000) >> 32;
    k2[2] = k4[2] = (clears & 0x0000ffffff000000) >> 24;
    generate_round_keys(k2, round_key2);

    u8 *result2 = PRESENT24_encrypt(result1, round_key2);

    if ((result2[0] == c2[0]) && (result2[1] == c2[1]) && (result2[2] == c2[2])) {
        printf("Found pair:\n\tk1: %x%x%x | k2: %x%x%x\n", k3[0], k3[1], k3[2], k4[0], k4[1], k4[2]);
    }
}

i64 binary_search(u64 *arr, i64 low, i64 high, u64 target, u8 m2[3], u8 c2[3]) {
    if (high >= low) {
        i64 mid = low + (high - low) / 2;

        if ((arr[mid] & 0x0000000000ffffff) == (target & 0x0000000000ffffff)) {
            i64 i = 1;
            while (((mid - i) >= low) && ((arr[mid - i] & 0x0000000000ffffff) == (target & 0x0000000000ffffff))) {
                valid_key(target, arr[mid - i], m2, c2);
                i++;
            }

            i64 j = 1;
            while (((mid + j) <= high) && ((arr[mid + j] & 0x0000000000ffffff) == (target & 0x0000000000ffffff))) {
                valid_key(target, arr[mid + j], m2, c2);
                j++;
            }

            return mid;
        }

        if ((arr[mid] & 0x0000000000ffffff) > (target & 0x0000000000ffffff)) {
            return binary_search(arr, low, mid - 1, target, m2, c2);
        }

        return binary_search(arr, mid + 1, high, target, m2, c2);
    }

    return -1;
}

void *research_valid_key(void *arg) {
    research_t *r = (research_t *)arg;

    for (i64 i = r->start; i < r->end; i++) {
        i64 index = binary_search(r->sorted, 0, (0x01 << 24) - 1, r->unsorted[i], r->m, r->c);

        if (index != -1) {
            valid_key(r->unsorted[i], r->sorted[index], r->m, r->c);
        }
    }
    return NULL;
}

void *generate_clear_cipher(void *arg) {
    generate_t *g = (generate_t*)arg;

    u8 round_key[11][3];
    u8 key_reg[10] = {
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    };

    for (u32 i = g->start; i < g->end; i++) {
        key_reg[0] = (i & 0xff0000) >> 16;
        key_reg[1] = (i & 0x00ff00) >> 8;
        key_reg[2] =  i & 0x0000ff;

        g->ciphers[i] |= key_reg[2] | key_reg[1] << 8 | key_reg[0] << 16;
        g->clears[i]  |= key_reg[2] | key_reg[1] << 8 | key_reg[0] << 16;

        generate_round_keys(key_reg, round_key);

        u8 cp_clear[3];
        cp_clear[0] = g->m[0];
        cp_clear[1] = g->m[1];
        cp_clear[2] = g->m[2];
        u8 *result1 = PRESENT24_encrypt(cp_clear, round_key);

        u8 cp_cipher[3];
        cp_cipher[0] = g->c[0];
        cp_cipher[1] = g->c[1];
        cp_cipher[2] = g->c[2];
        u8 *result2 = PRESENT24_decrypt(cp_cipher, round_key);

        g->ciphers[i] <<= 24;
        g->ciphers[i] |= result1[2] | result1[1] << 8 | result1[0] << 16;

        g->clears[i] <<= 24;
        g->clears[i] |= result2[2] | result2[1] << 8 | result2[0] << 16;
    }

    return NULL;
}

void PRESENT24_attack(u8 m1[3], u8 c1[3], u8 m2[3], u8 c2[3]) {
    static const u8 NB_THREADS = 8;
    pthread_t *tid1 = malloc(sizeof(pthread_t) * NB_THREADS);
    generate_t *dict = malloc(sizeof(generate_t) * NB_THREADS);
    func_ptr thread_func = generate_clear_cipher;

    u64 *clears = malloc(sizeof(u64) * (0x01 << 24));
    u64 *ciphers = malloc(sizeof(u64) * (0x01 << 24));

    printf("\nAttack parallelized with %u threads\n", NB_THREADS);
    printf("Generating dictionnaries...\n");
    for (u8 i = 0; i < NB_THREADS; i++) {
        dict[i].clears = clears;
        dict[i].ciphers = ciphers;
        dict[i].start = i * ((0x01 << 24) / NB_THREADS);
        dict[i].end = (i + 1) * ((0x01 << 24) / NB_THREADS);
        for (u8 j = 0; j < 3; j++) {
            dict[i].m[j] = m1[j];
            dict[i].c[j] = c1[j];
        }
        pthread_create(tid1 + i, NULL, thread_func, dict + i);
    }

    for (u8 i = 0; i < NB_THREADS; i++) {
        pthread_join(tid1[i], NULL);
    }

    free(dict);
    free(tid1);

    printf("Sorting dictionnaries...\n");
    quick_sort(clears, 0, ((0x01 << 24) - 1));

    pthread_t *tid2 = malloc(sizeof(pthread_t) * NB_THREADS);
    research_t *rsch = malloc(sizeof(research_t) * NB_THREADS);
    func_ptr thread_func2 = research_valid_key;

    printf("Checking for a valid key pair...\n");
    for (u8 i = 0; i < NB_THREADS; i++) {
        rsch[i].start = i * ((0x01 << 24) / NB_THREADS);
        rsch[i].end = (i + 1) * ((0x01 << 24) / NB_THREADS);
        rsch[i].sorted = clears;
        rsch[i].unsorted = ciphers;
        for (u8 j = 0; j < 3; j++) {
            rsch[i].m[j] = m2[j];
            rsch[i].c[j] = c2[j];
        }
        pthread_create(tid2 + i, NULL, thread_func2, rsch + i);
    }

    for (u8 i = 0; i < NB_THREADS; i++) {
        pthread_join(tid2[i], NULL);
    }

    free(rsch);
    free(tid2);

    free(clears);
    free(ciphers);
}
