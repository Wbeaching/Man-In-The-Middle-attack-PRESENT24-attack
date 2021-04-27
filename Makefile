# Macros
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -g3 -pthread
OFLAGS = -Ofast
FILES = src/*.c
AR = present24_encrypt

# Rules
all: present24

present24: $(FILES)
	$(CC) $(CFLAGS) $(OFLAGS) $(FILES) -o $@

archive:
	@mkdir -p $(AR)
	@cp -r src/ Makefile $(AR)
	@tar zcvf $(AR).tar.gz $(AR)
	@rm -Rf $(AR)

clean:
	@rm -Rf present24 $(AR).tar.gz
