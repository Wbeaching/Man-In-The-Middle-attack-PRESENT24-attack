#include <stdio.h>
#include "types.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        return printf("Usage: %s -[e | d]\n", argv[0]), 1;
    }

    return 0;
}

