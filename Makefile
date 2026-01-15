CC      ?= cc
CFLAGS  ?= -O2 -g
WFLAGS   = -Wall -Wextra -std=c11
IFLAGS   = -Iinclude -Isrc
SRCS     = $(wildcard src/*.c)
OBJS     = $(SRCS:.c=.o)

all: mdntool tests/test_main

%.o: %.c
	$(CC) $(CFLAGS) $(WFLAGS) $(IFLAGS) -c $< -o $@

mdntool: $(OBJS) cli/mdntool.o
	$(CC) $(CFLAGS) $^ -lm -o $@

cli/mdntool.o: cli/mdntool.c
	$(CC) $(CFLAGS) $(WFLAGS) $(IFLAGS) -c $< -o $@

tests/test_main: $(OBJS) tests/test_main.c
	$(CC) $(CFLAGS) $(WFLAGS) $(IFLAGS) tests/test_main.c $(OBJS) -lm -o $@

fuzz-local: $(OBJS)
	$(CXX) $(CFLAGS) -Iinclude -Isrc fuzz/meridian_fuzzer.cc fuzz/standalone_main.c \
	    $(OBJS) -lm -o fuzz/standalone_asan

test: tests/test_main
	./tests/test_main

clean:
	rm -f src/*.o cli/*.o mdntool tests/test_main fuzz/standalone_asan

.PHONY: all test fuzz-local clean
