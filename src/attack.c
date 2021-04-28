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

// void calcul_m2_c2(int indice, u8 clear_text2[3], u8 cipher_text2[3], ciphers, clears){
//     k1[0] = (ciphers[indice] & 0x0000FFFFFF000000) >> 40;
//     k1[1] = (ciphers[indice] & 0x0000FFFFFF000000) >> 32;
//     k1[2] = (ciphers[indice] & 0x0000FFFFFF000000) >> 24;

//     k2[0] = (clears[indice] & 0x0000FFFFFF000000) >> 40;
//     k2[1] = (clears[indice] & 0x0000FFFFFF000000) >> 32;
//     k2[2] = (clears[index] & 0x0000FFFFFF000000) >> 24;

//     generate_round_keys(k1, round_key1);
//     generate_round_keys(k2, round_key2);

//     u8 *result1 = PRESENT24_encrypt(clear_text2, round_key1);
//     u8 *result2 = PRESENT24_encrypt(result1, round_key2);
    
//     if ((result2[0] == cipher_text2[0]) && (result2[1] == cipher_text2[1]) && (result2[2] == cipher_text2[2])) {
//         printf("K1: %x%x%x\nK2: %x%x%x\n\n", k1[0], k1[1], k1[2], k2[0], k2[1], k2[2]);
//     }
// }

// void nouvelle_recherche(u64 *tab_chiffre_clef, int indice, unsigned int k2, unsigned int m2, unsigned int c2){
//     unsigned int recherche = tab_chiffre_clef[indice] & 0x0000000000ffffff;
//     int gauche = indice - 1;
//     int droite = indice + 1;
//     while(gauche>0 && tab_chiffre_clef[gauche] & 0x0000000000ffffff == recherche){
//         calcul_m2_c2(tab_chiffre_clef[gauche] & 0x0000ffffff000000, k2, m2, c2);
//         gauche--;
//     }
//     while(droite<pow(2, 24) && tab_chiffre_clef[droite] & 0x0000000000ffffff == recherche){
//         calcul_m2_c2(tab_chiffre_clef[droite] & 0x0000ffffff000000, k2, m2, c2);
//         droite++;
//     }
// }

void valid_key(u64 ciphers, u64 clears, u8 clear_text2[3], u8 cipher_text2[3]){
    printf("test\n");
    u8 k1[3] = { 0x00, 0x00, 0x00};
    k1[0] = (ciphers & 0x0000FFFFFF000000) >> 40;
    k1[1] = (ciphers & 0x0000FFFFFF000000) >> 32;
    k1[2] = (ciphers & 0x0000FFFFFF000000) >> 24;
    printf("Fin K1\n");
    
    u8 k2[3] = { 0x00, 0x00, 0x00};
    k2[0] = (clears & 0x0000FFFFFF000000) >> 40;
    k2[1] = (clears & 0x0000FFFFFF000000) >> 32;
    k2[2] = (clears & 0x0000FFFFFF000000) >> 24;
    printf("Fin K2\n");
    
    u8 round_key1[11][3];
    generate_round_keys(k1, round_key1);
    printf("Fin sous clé K1\n");

    u8 *result1 = PRESENT24_encrypt(clear_text2, round_key1);
    printf("Fin encrypt 1\n");
    
    u8 round_key2[11][3];
    generate_round_keys(k2, round_key2);
    printf("Fin sous clé K2\n");

    u8 *result2 = PRESENT24_encrypt(result1, round_key2);
    printf("Fin encrypt 2\n");

    if ((result2[0] == cipher_text2[0]) && (result2[1] == cipher_text2[1]) && (result2[2] == cipher_text2[2])) {
        printf("K1: %x%x%x\nK2: %x%x%x\n\n", k1[0], k1[1], k1[2], k2[0], k2[1], k2[2]);
    }

    printf("Fin recherche supp\n");
}

i64 binary_search(u64 *arr, i64 low, i64 high, u64 target, u8 clear_text2[3], u8 cipher_text2[3]) {
    if (high >= low) {
        i64 mid = low + (high - low) / 2;

        // If the element is present at the middle
        // itself
        if ((arr[mid] & 0x0000000000ffffff) == (target & 0x0000000000ffffff)) {
            i64 i = 1;
            while (mid-i >= 0 && ((arr[mid-i] & 0x0000000000ffffff) == (target & 0x0000000000ffffff))) {
                printf("debut sous recherche 1 : %lld, %lld\n", i, mid-i);
                //printf("debut sous recherche %lld\n", i);
                valid_key(target, arr[mid-i], clear_text2, cipher_text2);
                //printf("fin sous recherche\n");
                i++;
            }
            
            
            i64 j = 1;
            while (mid+j < pow(2, 24) && ((arr[mid+j] & 0x0000000000ffffff) == (target & 0x0000000000ffffff))) {
                printf("debut sous recherche 2 : %lld, %lld\n", j, mid+j);
                valid_key(target, arr[mid+j], clear_text2, cipher_text2);
                // printf("fin sous recherche 2 : %lld\n", j);
                j++;
            }

            return mid;
        }

        // If element is smaller than mid, then
        // it can only be present in left subarray
        if ((arr[mid] & 0x0000000000ffffff) > (target & 0x0000000000ffffff)) {
            return binary_search(arr, low, mid - 1, target, clear_text2, cipher_text2);
        }

        // Else the element can only be present
        // in right subarray
        return binary_search(arr, mid + 1, high, target, clear_text2, cipher_text2);
    }

    // We reach here when element is not
    // present in array
    return -1;
}

// i64 binary_search(u64 *arr, i64 low, i64 high, u64 target) {
//     if (high >= low) {
//         i64 mid = low + (high - low) / 2;

//         // If the element is present at the middle
//         // itself
//         if ((arr[mid] & 0x0000000000ffffff) == (target & 0x0000000000ffffff)) {
//             return mid;
//         }

//         // If element is smaller than mid, then
//         // it can only be present in left subarray
//         if ((arr[mid] & 0x0000000000ffffff) > (target & 0x0000000000ffffff)) {
//             return binary_search(arr, low, mid - 1, target);
//         }

//         // Else the element can only be present
//         // in right subarray
//         return binary_search(arr, mid + 1, high, target);
//     }

//     // We reach here when element is not
//     // present in array
//     return -1;
// }

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

u8 *PRESENT24_attack(u8 clear_text[3], u8 cipher_text[3], u8 clear_text2[3], u8 cipher_text2[3]) {
    u8 threads = 1;
    pthread_t *tid = malloc(sizeof(pthread_t) * threads);
    message_t *msg = malloc(sizeof(message_t) * threads);
    func_ptr thread_func = generate_clear_cipher;

    if (tid && msg) {
        u64 *clears = malloc(sizeof(u64) * pow(2, 24));
        u64 *ciphers = malloc(sizeof(u64) * pow(2, 24));

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
                msg[i].start = i * (pow(2, 24) / threads);
                msg[i].end = ((i + 1) * (pow(2, 24) / threads)) - 1;
                pthread_create(tid + i, NULL, thread_func, msg + i);
            }

            for (u8 i = 0; i < threads; i++) {
                pthread_join(tid[i], NULL);
            }

            printf("debut tri\n");
            quick_sort(clears, 0, (pow(2, 24) - 1));
            printf("fin tri\n");
            
            for (u64 i = 0; i < pow(2, 24); i++) {
                u8 k1[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                u8 k2[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

                u8 round_key1[11][3];
                u8 round_key2[11][3];

                i64 index = binary_search(clears, 0, pow(2, 24), ciphers[i], clear_text2, cipher_text2);
                
                if(index != -1) {
                    k1[0] = (ciphers[i] & 0x0000FFFFFF000000) >> 40;
                    k1[1] = (ciphers[i] & 0x0000FFFFFF000000) >> 32;
                    k1[2] = (ciphers[i] & 0x0000FFFFFF000000) >> 24;

                    k2[0] = (clears[index] & 0x0000FFFFFF000000) >> 40;
                    k2[1] = (clears[index] & 0x0000FFFFFF000000) >> 32;
                    k2[2] = (clears[index] & 0x0000FFFFFF000000) >> 24;

                    generate_round_keys(k1, round_key1);
                    generate_round_keys(k2, round_key2);

                    u8 *result1 = PRESENT24_encrypt(clear_text2, round_key1);
                    u8 *result2 = PRESENT24_encrypt(result1, round_key2);
                    
                    if ((result2[0] == cipher_text2[0]) && (result2[1] == cipher_text2[1]) && (result2[2] == cipher_text2[2])) {
                        printf("K1: %x%x%x\nK2: %x%x%x\n\n", k1[0], k1[1], k1[2], k2[0], k2[1], k2[2]);
                    }
                }
                
            }
            // TEST des clées
            // k1[0] = 0x6D;
            // k1[1] = 0xED;
            // k1[2] = 0xA7;

            // k2[0] = 0xE7;
            // k2[1] = 0x14;
            // k2[2] = 0x1F;

            // u8 round_key3[11][3];
            // u8 round_key4[11][3];

            // generate_round_keys(k1, round_key3);
            // generate_round_keys(k2, round_key4);

            // u8 *result1 = PRESENT24_encrypt(clear_text, round_key3);
            // printf("C1: %x%x%x\n", result1[0], result1[1], result1[2]);
            
            // u8 *result2 = PRESENT24_encrypt(result1, round_key4);
            // printf("C2: %x%x%x\n", result2[0], result2[1], result2[2]);

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
