CC = clang # use musl-clang with -static
CFLAGS = -march=native -O3 -s -Wall -Werror
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -Wl,--gc-sections,--as-needed -std=c99

build:
	@$(CC) $(CFLAGS) $$(fd -tf -ec --full-path "src/") -o main

run: build
	@sudo ./main
