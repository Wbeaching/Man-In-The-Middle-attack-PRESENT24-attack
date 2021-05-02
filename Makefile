# Macros
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -g3
LFLAGS = -pthread
OFLAGS = -O3 -march=native -mtune=native -funroll-loops -faggressive-loop-optimizations -fdelete-null-pointer-checks -finline-functions -floop-interchange -floop-unroll-and-jam -fpeel-loops -fsplit-loops -ftree-loop-vectorize -ftree-slp-vectorize
FILES = src/*.c
AR = MOLINATTI_DOS-SANTOS

# Rules
all: present24

present24: $(FILES)
	$(CC) $(CFLAGS) $(LFLAGS) $(OFLAGS) $(FILES) -o $@

encrypt: present24
	@echo "\033[1mRunning encryption with test vectors\033[0m\n"
	@./present24 -e 000000 000000
	@echo -e ''
	@./present24 -e ffffff 000000
	@echo -e ''
	@./present24 -e 000000 ffffff
	@echo -e ''
	@./present24 -e f955b9 d1bd2d

decrypt: present24
	@echo "\033[1mRunning decryption with test vectors\033[0m\n"
	@./present24 -d bb57e6 000000
	@echo -e ''
	@./present24 -d 739293 000000
	@echo -e ''
	@./present24 -d 1b56ce ffffff
	@echo -e ''
	@./present24 -d 47a929 d1bd2d

attack_theophile: present24
	@./present24 -a ce157a 0ed3f0 4181c8 650e1e -t 4

attack_gabriel: present24
	@./present24 -a b404cc 23714f 576dcf 45051b -t 4

archive:
	@mkdir -p $(AR)
	@cp -r src/ Makefile README.md $(AR)
	@tar zcvf $(AR).tar.gz $(AR)
	@rm -Rf $(AR)

clean:
	@rm -Rf present24 $(AR).tar.gz
