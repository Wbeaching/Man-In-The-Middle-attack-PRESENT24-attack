#include <stdio.h>

#include "types.h"
#include "err.h"

inline
void info()
{
#if __linux__ || __APPLE__
    printf("\x1b[1m[INFO]:\x1b[0m ");
#else
    printf("[INFO]: ");
#endif
}

inline
void warn()
{
#if __linux__ || __APPLE__
    printf("\x1b[1m\x1b[33m[WARNING]:\x1b[0m ");
#else
    printf("[WARNING]: ");
#endif
}

inline
void err(size_t nb_err)
{
#if __linux__ || __APPLE__
    printf("\x1b[1m\x1b[31m[ERROR #%lu]:\x1b[0m ", nb_err);
#else
    printf("[ERROR #%lu]: ", nb_err);
#endif
}

