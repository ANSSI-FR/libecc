HOST_CC = gcc
DPU_CC = dpu-upmem-dpurte-clang

ROOT_DIR=../..
BUILD_DIR=$(ROOT_DIR)/build
include $(ROOT_DIR)/common.mk

CFLAGS += -I$(ROOT_DIR)/src/ -I$(ROOT_DIR)/src/external_deps

WARNING_CFLAGS ?= -Wall -Wextra
HOST_LDFLAGS = `dpu-pkg-config --libs dpu`
HOST_CFLAGS = $(WARNING_CFLAGS) -std=c11 `dpu-pkg-config --cflags dpu` -O2
ifdef SW
HOST_CFLAGS += -DGEN_BY_SW=1 -DLOG_GENERATED=1
endif

all:	dpu  host
ifeq ($(WITH_DYNAMIC_LIBS),1)
# If the user asked for dynamic libraries, compile versions of our binaries against them
all:	nn_example_dyn fp_example_dyn curve_basic_examples_dyn curve_ecdh_dyn
endif

dpu:
	$(DPU_CC) $(BIN_CFLAGS) ecdsa_dpu.c $(ROOT_DIR)/src/external_deps/rand.c  $(LIBSIGN) $(BIN_LDFLAGS) -o ecdsa_dpu

host:
	$(HOST_CC) $(HOST_CFLAGS) ecdsa_host.c $(HOST_LDFLAGS) -o ecdsa_host

clean:
	@rm -f ecdsa_dpu ecdsa_host

.PHONY: all clean
