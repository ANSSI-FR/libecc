ROOT_DIR=../..
BUILD_DIR=$(ROOT_DIR)/build
include $(ROOT_DIR)/common.mk

BIN_CFLAGS += -I$(ROOT_DIR)/src/ -Wno-shadow -Wno-conversion -Wno-cast-align -Wno-unused-macros

all: bin tests

bin:
	$(CC) $(BIN_CFLAGS) -DDEBUG -DWITH_STDLIB arithmetic_tests.c $(LIBARITH) $(ROOT_DIR)/src/external_deps/print.c $(BIN_LDFLAGS) -o arithmetic_tests

tests:	bin
	# Get the word size and maximum nn bit length
	$(eval WORDSZ := $(shell ./arithmetic_tests -info | cut -d ' ' -f1))
	$(eval MAXBITS := $(shell ./arithmetic_tests -info | cut -d ' ' -f2))
	python arithmetic_tests_generator.py stdout $(WORDSZ) $(MAXBITS) 1000 | ./arithmetic_tests

clean:
	@rm -f arithmetic_tests
