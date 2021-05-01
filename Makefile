# Macros
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -g3
LFLAGS = -pthread
OFLAGS = -O3 -march=native -mtune=native -funroll-loops -faggressive-loop-optimizations -fdelete-null-pointer-checks -finline-functions -floop-interchange -floop-unroll-and-jam -fpeel-loops -fsplit-loops -ftree-loop-vectorize -ftree-slp-vectorize
FILES = src/*.c
AR = PRESENT24

# Rules
all: present24

present24: $(FILES)
	$(CC) $(CFLAGS) $(LFLAGS) $(OFLAGS) $(FILES) -o $@

archive:
	@mkdir -p $(AR)
	@cp -r src/ Makefile README.md $(AR)
	@tar zcvf $(AR).tar.gz $(AR)
	@rm -Rf $(AR)

clean:
	@rm -Rf present24 $(AR).tar.gz
