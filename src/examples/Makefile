ROOT_DIR=../../
ROOT_DIR=../..
BUILD_DIR=$(ROOT_DIR)/build
include $(ROOT_DIR)/common.mk

CFLAGS += -I$(ROOT_DIR)/src/ -I$(ROOT_DIR)/src/external_deps

all:	nn_example fp_example curve_basic_examples curve_ecdh

nn_example:
	$(CC) $(BIN_CFLAGS) -DNN_EXAMPLE nn_miller_rabin.c nn_pollard_rho.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(LIBARITH) $(BIN_LDFLAGS) -o nn_pollard_rho

fp_example:
	$(CC) $(BIN_CFLAGS) -DFP_EXAMPLE nn_miller_rabin.c fp_square_residue.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(LIBARITH) $(BIN_LDFLAGS) -o fp_square_residue

curve_basic_examples:
	$(CC) $(BIN_CFLAGS) -DCURVE_BASIC_EXAMPLES fp_square_residue.c curve_basic_examples.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(ROOT_DIR)/src/external_deps/time.c $(LIBEC) $(BIN_LDFLAGS) -o curve_basic_examples
curve_ecdh:
	$(CC) $(BIN_CFLAGS) -DCURVE_ECDH curve_ecdh.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) $(LIBEC) -o curve_ecdh

clean:
	@rm -f nn_pollard_rho fp_square_residue curve_basic_examples curve_ecdh

.PHONY: all clean 16 32 64 debug debug16 debug32 debug64 force_arch32 force_arch64
