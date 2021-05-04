#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "types.h"
#include "common.h"
#include "err.h"
#include "encrypt.h"
#include "decrypt.h"
#include "attack.h"

int main(int argc, char **argv)
{
    // Check that user passes at least 2 arguments
    if (argc < 2)
    {
        err(ERR_INVALID_RUN_CMD);
        printf("USAGE: %s -[e | d | a]\n", argv[0]);
        return 1;
    }

    // If the passed option is `-e`, start encryption mode
    if (!strcmp(argv[1], "-e"))
    {
        // Check that the number of argument is correct
        if (argc == 4)
        {
            // Check that the arguments are valid before executing
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0)
            {
                main_encrypt(argv[2], argv[3]);
            }
        }
        else
        {
            err(ERR_IVALID_ENCRYPTION_CMD);
            printf("USAGE: %s -e MESSAGE KEY\n", argv[0]);
            return 2;
        }
    }
    // If the passed option is `-d`, start decryption mode
    else if (!strcmp(argv[1], "-d"))
    {
        // Check that the number of argument is correct
        if (argc == 4)
        {
            // Check that the arguments are valid before executing
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0)
            {
                main_decrypt(argv[2], argv[3]);
            }
        }
        else
        {
            err(ERR_INVALID_DECRYPTION_CMD);
            printf("USAGE: %s -d CIPHER KEY\n", argv[0]);
            return 3;
        }
    }
    // If the passed option is `-a`, start decryption mode
    else if (!strcmp(argv[1], "-a"))
    {
        // Check that the number of argument is valid
        if (argc > 5)
        {
            // Check that the arguments are valid before executing
            if (check_args(argv[2]) == 0 && check_args(argv[3]) == 0 &&
                check_args(argv[4]) == 0 && check_args(argv[5]) == 0)
            {
                main_attack(argc, argv);
            }
        }
        else
        {
            err(ERR_INVALID_ATTACK_CMD);
            printf("USAGE: %s -a m1 c1 m2 c2\n", argv[0]);
            return 4;
        }
    }
    else
    {
        err(ERR_INVALID_OPTION);
        printf("USAGE: %s -[e | d | a]\n", argv[0]);
        return 1;
    }

    return 0;
}

