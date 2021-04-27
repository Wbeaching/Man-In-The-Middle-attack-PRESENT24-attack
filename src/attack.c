#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pthread.h>

#include "common.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

typedef void *(*func_ptr)(void *arg);

void swap(u64 *x, u64 *y)
{
    u64 tmp = *x;
    *x = *y;
    *y = tmp;
}

//
u64 partition(u64 *arr, i64 low, i64 high)
{
    u64 pivot = arr[high] & 0x0000000000ffffff;
    i64 i = (low - 1);

    for (i64 j = low; j < high; j++)
    {
        if ((arr[j] & 0x0000000000ffffff) < pivot)
        {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);

    return (i + 1);
}

//
void quick_sort(u64 *arr, i64 low, i64 high)
{
    if (arr)
    {
        if (low < high)
        {
            u64 part_index = partition(arr, low, high);
            quick_sort(arr, low, part_index - 1);
            quick_sort(arr, part_index + 1, high);
        }
    }
    else
    {
        printf("Error: arr_t pointer is already NULL\n");
    }
}

i64 binary_search(u64 *arr, i64 low, i64 high, u64 target) {
    if (high >= low) {
        i64 mid = low + (high - low) / 2;

        // If the element is present at the middle
        // itself
        if ((arr[mid] & 0x0000000000ffffff) == (target & 0x0000000000ffffff)) {
            return mid;
        }

        // If element is smaller than mid, then
        // it can only be present in left subarray
        if ((arr[mid] & 0x0000000000ffffff) > (target & 0x0000000000ffffff)) {
            return binary_search(arr, low, mid - 1, target);
        }

        // Else the element can only be present
        // in right subarray
        return binary_search(arr, mid + 1, high, target);
    }

    // We reach here when element is not
    // present in array
    return -1;
}

void *generate_clear_cipher(void *arg) {
    u8 round_key[11][3];
    u8 key_reg[10] = {
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    };

    message_t *msg = (message_t*)arg;

    for (u32 i = msg->start; i < msg->end; i++) {
        key_reg[0] = (i & 0xff0000) >> 16;
        key_reg[1] = (i & 0x00ff00) >> 8;
        key_reg[2] =  i & 0x0000ff;

        msg->ciphers[i] |= key_reg[2] | key_reg[1] << 8 | key_reg[0] << 16;
        msg->clears[i]  |= key_reg[2] | key_reg[1] << 8 | key_reg[0] << 16;

        generate_round_keys(key_reg, round_key);

        u8 *result1 = PRESENT24_encrypt(msg->clear_text, round_key);
        u8 *result2 = PRESENT24_decrypt(msg->cipher_text, round_key);

        msg->ciphers[i] <<= 24;
        msg->ciphers[i] |= result1[2] | result1[1] << 8 | result1[0] << 16;

        msg->clears[i] <<= 24;
        msg->clears[i] |= result2[2] | result2[1] << 8 | result2[0] << 16;
    }

    return NULL;
}

u8 *PRESENT24_attack(u8 clear_text[3], u8 cipher_text[3]) {
    u8 threads = 8;
    pthread_t *tid = malloc(sizeof(pthread_t) * threads);
    message_t *msg = malloc(sizeof(message_t) * threads);
    func_ptr thread_func = generate_clear_cipher;

    if (tid && msg) {
        u64 *clears = malloc(sizeof(u64) * (pow(2, 24) - 1));
        u64 *ciphers = malloc(sizeof(u64) * (pow(2, 24) - 1));

        if (clears && ciphers) {
            for (u8 i = 0; i < threads; i++) {
                msg[i].clears = clears;
                msg[i].ciphers = ciphers;
                msg[i].clear_text[0] = clear_text[0];
                msg[i].clear_text[1] = clear_text[1];
                msg[i].clear_text[2] = clear_text[2];
                msg[i].cipher_text[0] = cipher_text[0];
                msg[i].cipher_text[1] = cipher_text[1];
                msg[i].cipher_text[2] = cipher_text[2];
                msg[i].start = i * ((pow(2, 24) - 1) / threads);
                msg[i].end = (i + 1) * ((pow(2, 24) - 1) / threads);
                pthread_create(tid + i, NULL, thread_func, msg + i);
            }

            for (u8 i = 0; i < threads; i++) {
                pthread_join(tid[i], NULL);
            }

            quick_sort(clears, 0, (pow(2, 24) - 2));

            for (u64 i = 0; i < (pow(2, 24) - 1); i++) {
                i64 index = binary_search(clears, 0, pow(2, 24) - 1, ciphers[i]);
            }

            free(clears);
            free(ciphers);
            free(msg);
            free(tid);
        } else {
            return printf("ERROR: cannot allocate memory for arrays\n"), NULL;
        }
    } else {
        return printf("ERROR: cannot allocate memory for threads\n"), NULL;
    }

/*
    u32 counter = 0;
    for (u32 i = 0; i < (pow(2, 24) - 1); i++) {
        for (u32 j = 0; j < (pow(2, 24) - 1); j++) {
            u32 clear = (clears[i] & 0x0000000000FFFFFF);
            u32 cipher = (ciphers[j] & 0x0000000000FFFFFF);

            if (clear == cipher) {
                counter++;
            }
        }
    }

    printf("Found: %d\n", counter);
*/

    return clear_text;
}
