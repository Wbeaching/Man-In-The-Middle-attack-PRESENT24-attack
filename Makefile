# Macros
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -g3
OFLAGS = -O1
FILES = src/*.c

# Rules
all: present24

present24: $(FILES)
	$(CC) $(CFLAGS) $(OFLAGS) $(FILES) -o $@

clean:
	@rm -Rf present24
