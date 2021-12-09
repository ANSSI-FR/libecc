ROOT_DIR=../../..
BUILD_DIR=$(ROOT_DIR)/build
include $(ROOT_DIR)/common.mk

# Remove old includes with bad relative folders
CFLAGS := $(patsubst -I%,,$(CFLAGS))
# Add proper includes
CFLAGS += -I$(ROOT_DIR)/src/ -I$(ROOT_DIR)/src/external_deps

all:	sss
ifeq ($(WITH_DYNAMIC_LIBS),1)
# If the user asked for dynamic libraries, compile versions of our binaries against them
all:	sss_dyn
endif

sss:
	$(CC) $(BIN_CFLAGS) -DSSS sss.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) $(LIBSIGN) -o sss

# If the user asked for dynamic libraries, compile versions of our binaries against them
ifeq ($(WITH_DYNAMIC_LIBS),1)
sss_dyn:
	$(CC) $(BIN_CFLAGS) -DSSS sss.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) $(LIBSIGN) -L$(BUILD_DIR) -lsign -o sss_dyn
endif


clean:
	@rm -f sss
	@rm -f sss_dyn

.PHONY: all clean 16 32 64 debug debug16 debug32 debug64 force_arch32 force_arch64
