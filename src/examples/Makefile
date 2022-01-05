ROOT_DIR=../..
BUILD_DIR=$(ROOT_DIR)/build
include $(ROOT_DIR)/common.mk

HASH_DIR=hash/
RSA_DIR=rsa/
DSA_DIR=dsa/
SDSA_DIR=sdsa/
GOST_DIR=gostr34_10_94/
SSS_DIR=sss/

CFLAGS += -I$(ROOT_DIR)/src/ -I$(ROOT_DIR)/src/external_deps

all:	nn_example fp_example curve_basic_examples curve_ecdh _hash _rsa _dsa _sdsa _gost _sss
ifeq ($(WITH_DYNAMIC_LIBS),1)
# If the user asked for dynamic libraries, compile versions of our binaries against them
all:	nn_example_dyn fp_example_dyn curve_basic_examples_dyn curve_ecdh_dyn _hash_dyn _rsa_dyn _dsa_dyn _sdsa_dyn _gost_dyn _sss_dyn
endif

nn_example:
	$(CC) $(BIN_CFLAGS) -DNN_EXAMPLE nn_miller_rabin.c nn_pollard_rho.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(LIBARITH) $(BIN_LDFLAGS) -o nn_pollard_rho

fp_example:
	$(CC) $(BIN_CFLAGS) -DFP_EXAMPLE nn_miller_rabin.c fp_square_residue.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(LIBARITH) $(BIN_LDFLAGS) -o fp_square_residue

curve_basic_examples:
	$(CC) $(BIN_CFLAGS) -DCURVE_BASIC_EXAMPLES fp_square_residue.c curve_basic_examples.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(ROOT_DIR)/src/external_deps/time.c $(LIBEC) $(BIN_LDFLAGS) -o curve_basic_examples
curve_ecdh:
	$(CC) $(BIN_CFLAGS) -DCURVE_ECDH curve_ecdh.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) $(LIBEC) -o curve_ecdh

_hash:
	cd $(HASH_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_rsa:
	cd $(RSA_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_dsa:
	cd $(DSA_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_sdsa:
	cd $(SDSA_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_gost:
	cd $(GOST_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_sss:
	cd $(SSS_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make

# If the user asked for dynamic libraries, compile versions of our binaries against them
ifeq ($(WITH_DYNAMIC_LIBS),1)
nn_example_dyn:
	$(CC) $(BIN_CFLAGS) -DNN_EXAMPLE nn_miller_rabin.c nn_pollard_rho.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) -L$(BUILD_DIR) -larith -o nn_pollard_rho_dyn

fp_example_dyn:
	$(CC) $(BIN_CFLAGS) -DFP_EXAMPLE nn_miller_rabin.c fp_square_residue.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) -L$(BUILD_DIR) -larith -o fp_square_residue_dyn

curve_basic_examples_dyn:
	$(CC) $(BIN_CFLAGS) -DCURVE_BASIC_EXAMPLES fp_square_residue.c curve_basic_examples.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(ROOT_DIR)/src/external_deps/time.c  $(BIN_LDFLAGS) -L$(BUILD_DIR) -lec -o curve_basic_examples_dyn
curve_ecdh_dyn:
	$(CC) $(BIN_CFLAGS) -DCURVE_ECDH curve_ecdh.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) -L$(BUILD_DIR) -lec -o curve_ecdh_dyn

_hash_dyn:
	cd $(HASH_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_rsa_dyn:
	cd $(RSA_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_dsa_dyn:
	cd $(DSA_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_sdsa_dyn:
	cd $(SDSA_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_gost_dyn:
	cd $(GOST_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
_sss_dyn:
	cd $(SSS_DIR) && EXTRA_CFLAGS="$(CFLAGS)" make
endif


clean:
	@rm -f nn_pollard_rho fp_square_residue curve_basic_examples curve_ecdh
	@rm -f nn_pollard_rho_dyn fp_square_residue_dyn curve_basic_examples_dyn curve_ecdh_dyn
	cd $(HASH_DIR) && make clean
	cd $(RSA_DIR) && make clean
	cd $(DSA_DIR) && make clean
	cd $(SDSA_DIR) && make clean
	cd $(GOST_DIR) && make clean
	cd $(SSS_DIR) && make clean

.PHONY: all clean 16 32 64 debug debug16 debug32 debug64 force_arch32 force_arch64
