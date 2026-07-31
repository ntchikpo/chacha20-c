# Makefile pour l'implementation ChaCha20
# Cibles :
#   make        -> compile l'outil CLI et les tests
#   make test   -> compile puis lance les tests de validation RFC
#   make clean  -> supprime les fichiers generes

CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -Isrc
BUILD   := build

CORE     := src/chacha20.c
CLI      := src/main.c
TEST     := tests/test_chacha20.c

CLI_BIN  := $(BUILD)/chacha20
TEST_BIN := $(BUILD)/test_chacha20

.PHONY: all test clean

all: $(CLI_BIN) $(TEST_BIN)

$(CLI_BIN): $(CORE) $(CLI) | $(BUILD)
	$(CC) $(CFLAGS) $(CORE) $(CLI) -o $(CLI_BIN)

$(TEST_BIN): $(CORE) $(TEST) | $(BUILD)
	$(CC) $(CFLAGS) $(CORE) $(TEST) -o $(TEST_BIN)

$(BUILD):
	mkdir -p $(BUILD)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -rf $(BUILD)
