#include <stdio.h>

#include "types.h"
#include "err.h"

inline
void info()
{
    printf("\x1b[1m[INFO]:\x1b[0m ");
}

inline
void warn()
{
    printf("\x1b[1m\x1b[33m[WARNING]:\x1b[0m ");
}

inline
void err(size_t nb_err)
{
    printf("\x1b[1m\x1b[31m[ERROR #%lu]:\x1b[0m ", nb_err);
}

