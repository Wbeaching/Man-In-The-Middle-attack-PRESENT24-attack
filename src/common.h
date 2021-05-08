#pragma once

#include <time.h>

#include "types.h"

#define MASK_T64 0x000000ffffff
#define MASK_K64 0xffffff000000
#define DICT_SIZE 0xffffff

/**
 * Measures the time that has passed between two points in time.
 *
 * Internally uses CLOCK_MONOTONIC_RAW for more precise measurements.
 *
 * @param before The point in time when the measurement was started.
 * @param after The point in time when the measurement was stoped.
 * @return The time that has passed between
 * the two points in nanoseconds.
 */
f64 measure_time(struct timespec *before, struct timespec *after);

/**
 * Checks that a given argument is valid.
 *
 * Checks that the length of the argument is valid and
 * that it respects hexadecimal format.
 *
 * @param arg The string to check.
 * @return 0 if the string is valid, an error code otherwise.
 */
u8 check_args(i8 *arg);

/**
 * Generates the round keys using the keyschedule algorithm.
 *
 * The algorithm takes a key register K and an array to be filled with
 * the generated round keys. The latter is composed of 11 boxes, each holding
 * 24 bits divided into 3 bytes.
 *
 * @param k_reg The key register holding the master key.
 * @param rk The round key array.
 */
void generate_round_keys(u8 k_reg[10], u8 rk[11][3]);
