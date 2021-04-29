# Macros
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -g3
LFLAGS = -pthread
OFLAGS = -O3 -march=x86-64 -funroll-loops -faggressive-loop-optimizations -fdelete-null-pointer-checks -finline-functions -funsafe-math-optimizations
FILES = src/*.c
AR = present24_encrypt

# Rules
all: present24

present24: $(FILES)
	$(CC) $(CFLAGS) $(LFLAGS) $(OFLAGS) $(FILES) -o $@

archive:
	@mkdir -p $(AR)
	@cp -r src/ Makefile $(AR)
	@tar zcvf $(AR).tar.gz $(AR)
	@rm -Rf $(AR)

clean:
	@rm -Rf present24 $(AR).tar.gz
