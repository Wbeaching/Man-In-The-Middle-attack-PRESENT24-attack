#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "common.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        return printf("Usage: %s -[e | d | a | h]\n", argv[0]), 1;
    }

    if (!strcmp(argv[1], "-e")) {
        if (argc == 4) {
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0) {
                i32 a2 = strtol(argv[2], NULL, 16);
                i32 a3 = strtol(argv[3], NULL, 16);

                u8 m[3] = {
                    (a2 & 0x00ff0000) >> 16,
                    (a2 & 0x0000ff00) >> 8,
                    (a2 & 0x000000ff)
                };

                u8 k_reg[10] = {
                    (a3 & 0x00ff0000) >> 16,
                    (a3 & 0x0000ff00) >> 8,
                    (a3 & 0x000000ff), 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00
                };
                u8 rk[11][3];

                printf("Starting PRESENT24 encryption with:\n");
                printf("\tMessage: %02x%02x%02x\n", m[0], m[1], m[2]);
                printf("\tKey:\t %02x%02x%02x\n", k_reg[0], k_reg[1], k_reg[2]);

                generate_round_keys(k_reg, rk);
                u8 *c = PRESENT24_encrypt(m, rk);
                printf("\nOutput cipher:\t %02x%02x%02x\n", c[0], c[1], c[2]);
            }
        }
        else {
            return printf("Usage: %s -e MESSAGE KEY\n", argv[0]), 1;
        }
    }
    else if (!strcmp(argv[1], "-d")) {
        if (argc == 4) {
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0) {
                i32 a2 = strtol(argv[2], NULL, 16);
                i32 a3 = strtol(argv[3], NULL, 16);

                u8 c[3] = {
                    (a2 & 0x00ff0000) >> 16,
                    (a2 & 0x0000ff00) >> 8,
                    (a2 & 0x000000ff)
                };

                u8 k_reg[10] = {
                    (a3 & 0x00ff0000) >> 16,
                    (a3 & 0x0000ff00) >> 8,
                    (a3 & 0x000000ff), 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00
                };
                u8 rk[11][3];

                printf("Starting PRESENT24 decryption with:\n");
                printf("\tCipher:  %02x%02x%02x\n", c[0], c[1], c[2]);
                printf("\tKey:\t %02x%02x%02x\n", k_reg[0], k_reg[1], k_reg[2]);

                generate_round_keys(k_reg, rk);
                u8 *m = PRESENT24_encrypt(c, rk);
                printf("\nOutput message:\t %02x%02x%02x\n", m[0], m[1], m[2]);
            }
        }
        else {
            return printf("Usage: %s -d CIPHER KEY\n", argv[0]), 1;
        }
    }
    else if (!strcmp(argv[1], "-a")) {
        if (argc == 6) {
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0 &&
                check_args(argv[4]) == 0 && check_args(argv[5]) == 0)
            {
                i32 a2 = strtol(argv[2], NULL, 16);
                i32 a3 = strtol(argv[3], NULL, 16);
                i32 a4 = strtol(argv[4], NULL, 16);
                i32 a5 = strtol(argv[5], NULL, 16);

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

                printf("Starting man in the middle attack on 2PRESENT24 with:\n");
                printf("\tMessage 1: %02x%02x%02x | ", m1[0], m1[1], m1[2]);
                printf("Cipher 1:  %02x%02x%02x\n", c1[0], c1[1], c1[2]);
                printf("\tMessage 2: %02x%02x%02x | ", m2[0], m2[1], m2[2]);
                printf("Cipher 2:  %02x%02x%02x\n", c2[0], c2[1], c2[2]);
                PRESENT24_attack(m1, c1, m2, c2);
            }
        }
        else {
            return printf("Usage: %s -a m1 c1 m2 c2\n", argv[0]), 1;
        }
    }
    else {
        return printf("Usage: %s -[e | d | a]\n", argv[0]), 1;
    }

    return 0;
}

