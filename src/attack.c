#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pthread.h>

#include "common.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

typedef void *(*generate_ptr)(void *arg);
typedef void *(*research_ptr)(void *arg);

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

void valid_key(u64 ciphers, u64 clears, u8 clear_text2[3], u8 cipher_text2[3]) {
    // First step
    u8 k1[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    u8 k3[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    u8 round_key1[11][3];

    k1[0] = k3[0] = (ciphers & 0x0000ffffff000000) >> 40;
    k1[1] = k3[1] = (ciphers & 0x0000ffffff000000) >> 32;
    k1[2] = k3[2] = (ciphers & 0x0000ffffff000000) >> 24;

    generate_round_keys(k1, round_key1);

    u8 message[3];
    message[0] = clear_text2[0];
    message[1] = clear_text2[1];
    message[2] = clear_text2[2];

    u8 *result1 = PRESENT24_encrypt(message, round_key1);

    // Second step
    u8 k2[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    u8 k4[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    u8 round_key2[11][3];

    k2[0] = k4[0] = (clears & 0x0000ffffff000000) >> 40;
    k2[1] = k4[1] = (clears & 0x0000ffffff000000) >> 32;
    k2[2] = k4[2] = (clears & 0x0000ffffff000000) >> 24;

    generate_round_keys(k2, round_key2);

    u8 *result2 = PRESENT24_encrypt(result1, round_key2);

    if ((result2[0] == cipher_text2[0]) && (result2[1] == cipher_text2[1]) && (result2[2] == cipher_text2[2])) {
        printf("k1: %x%x%x\nk2: %x%x%x\n\n", k3[0], k3[1], k3[2], k4[0], k4[1], k4[2]);
    }
}

i64 binary_search(u64 *arr, i64 low, i64 high, u64 target, u8 clear_text2[3], u8 cipher_text2[3]) {
    if (high >= low) {
        i64 mid = low + (high - low) / 2;

        if ((arr[mid] & 0x0000000000ffffff) == (target & 0x0000000000ffffff)) {
            i64 i = 1;
            while (((mid - i) >= low) && ((arr[mid - i] & 0x0000000000ffffff) == (target & 0x0000000000ffffff))) {
                valid_key(target, arr[mid - i], clear_text2, cipher_text2);
                i++;
            }

            i64 j = 1;
            while (((mid + j) <= high) && ((arr[mid + j] & 0x0000000000ffffff) == (target & 0x0000000000ffffff))) {
                valid_key(target, arr[mid + j], clear_text2, cipher_text2);
                j++;
            }

            return mid;
        }

        if ((arr[mid] & 0x0000000000ffffff) > (target & 0x0000000000ffffff)) {
            return binary_search(arr, low, mid - 1, target, clear_text2, cipher_text2);
        }

        return binary_search(arr, mid + 1, high, target, clear_text2, cipher_text2);
    }

    return -1;
}

void *research_valid_key(void *arg) {
    research_t *msg = (research_t *)arg;

    for (i64 i = msg->start; i < msg->end; i++) {
        i64 index = binary_search(msg->sorted, 0, pow(2, 24) - 1, msg->unsorted[i], msg->clear_text, msg->cipher_text);

        if (index != -1) {
            valid_key(msg->unsorted[i], msg->sorted[index], msg->clear_text, msg->cipher_text);
        }
    }
    return NULL;
}

void *generate_clear_cipher(void *arg) {
    u8 round_key[11][3];
    u8 key_reg[10] = {
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    };

    generate_t *msg = (generate_t*)arg;

    for (u32 i = msg->start; i < msg->end; i++) {
        key_reg[0] = (i & 0xff0000) >> 16;
        key_reg[1] = (i & 0x00ff00) >> 8;
        key_reg[2] =  i & 0x0000ff;

        msg->ciphers[i] |= key_reg[2] | key_reg[1] << 8 | key_reg[0] << 16;
        msg->clears[i]  |= key_reg[2] | key_reg[1] << 8 | key_reg[0] << 16;

        generate_round_keys(key_reg, round_key);

        u8 cp_clear[3];
        cp_clear[0] = msg->clear_text[0];
        cp_clear[1] = msg->clear_text[1];
        cp_clear[2] = msg->clear_text[2];

        u8 cp_cipher[3];
        cp_cipher[0] = msg->cipher_text[0];
        cp_cipher[1] = msg->cipher_text[1];
        cp_cipher[2] = msg->cipher_text[2];

        u8 *result1 = PRESENT24_encrypt(cp_clear, round_key);
        u8 *result2 = PRESENT24_decrypt(cp_cipher, round_key);

        msg->ciphers[i] <<= 24;
        msg->ciphers[i] |= result1[2] | result1[1] << 8 | result1[0] << 16;

        msg->clears[i] <<= 24;
        msg->clears[i] |= result2[2] | result2[1] << 8 | result2[0] << 16;
    }

    return NULL;
}

u8 *PRESENT24_attack(u8 clear_text[3], u8 cipher_text[3], u8 clear_text2[3], u8 cipher_text2[3]) {
    u8 threads = 8;
    pthread_t *tid = malloc(sizeof(pthread_t) * threads);
    generate_t *msg = malloc(sizeof(generate_t) * threads);
    generate_ptr thread_func = generate_clear_cipher;

    u64 *clears = malloc(sizeof(u64) * pow(2, 24));
    u64 *ciphers = malloc(sizeof(u64) * pow(2, 24));

    for (u8 i = 0; i < threads; i++) {
        msg[i].clears = clears;
        msg[i].ciphers = ciphers;
        for (u8 j = 0; j < 3; j++) {
            msg[i].clear_text[j] = clear_text[j];
            msg[i].cipher_text[j] = cipher_text[j];
        }
        msg[i].start = i * (pow(2, 24) / threads);
        msg[i].end = (i + 1) * (pow(2, 24) / threads);
        pthread_create(tid + i, NULL, thread_func, msg + i);
    }

    for (u8 i = 0; i < threads; i++) {
        pthread_join(tid[i], NULL);
    }

    free(msg);
    free(tid);

    quick_sort(clears, 0, (pow(2, 24) - 1));

    pthread_t *tid2 = malloc(sizeof(pthread_t) * threads);
    research_t *msg2 = malloc(sizeof(research_t) * threads);
    research_ptr thread_func2 = research_valid_key;

    for (u8 i = 0; i < threads; i++) {
        msg2[i].start = i * (pow(2, 24) / threads);
        msg2[i].end = (i + 1) * (pow(2, 24) / threads);
        msg2[i].sorted = clears;
        msg2[i].unsorted = ciphers;
        for (u8 j = 0; j < 3; j++) {
            msg2[i].clear_text[j] = clear_text2[j];
            msg2[i].cipher_text[j] = cipher_text2[j];
        }
        pthread_create(tid2 + i, NULL, thread_func2, msg2 + i);
    }

    for (u8 i = 0; i < threads; i++) {
        pthread_join(tid2[i], NULL);
    }

    free(msg2);
    free(tid2);

    free(clears);
    free(ciphers);

    return clear_text;
}
