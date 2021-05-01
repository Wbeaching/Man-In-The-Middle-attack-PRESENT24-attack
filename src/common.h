#pragma once

#include "types.h"
#include <bits/types/struct_timespec.h>
#include <time.h>

#define MASK_T64 0x0000000000ffffff
#define MASK_K64 0x0000ffffff000000
#define DICT_SIZE (0x01 << 24)

void info();
void warn();
void err(size_t nb_err);
void measure_time(struct timespec *before, struct timespec *after);

u8 check_args(i8 *arg);
void generate_round_keys(u8 key_reg[10], u8 round_key[11][3]);
