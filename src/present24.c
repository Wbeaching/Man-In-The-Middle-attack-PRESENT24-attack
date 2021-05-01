#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "types.h"
#include "common.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        return printf("USAGE: %s -[e | d | a]\n", argv[0]), 1;
    }

    if (!strcmp(argv[1], "-e")) {
        if (argc == 4) {
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0) {
                main_encrypt(argv[2], argv[3]);
            }
        }
        else {
            return printf("USAGE: %s -e MESSAGE KEY\n", argv[0]), 1;
        }
    }
    else if (!strcmp(argv[1], "-d")) {
        if (argc == 4) {
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0) {
                main_decrypt(argv[2], argv[3]);
            }
        }
        else {
            return printf("USAGE: %s -d CIPHER KEY\n", argv[0]), 1;
        }
    }
    else if (!strcmp(argv[1], "-a")) {
        if (argc > 5) {
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0 &&
                check_args(argv[4]) == 0 && check_args(argv[5]) == 0)
            {
                main_attack(argc, argv);
            }
        }
        else {
            return printf("USAGE: %s -a m1 c1 m2 c2\n", argv[0]), 1;
        }
    }
    else {
        return printf("USAGE: %s -[e | d | a]\n", argv[0]), 1;
    }

    return 0;
}

