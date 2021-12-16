ROOT_DIR=../../..
BUILD_DIR=$(ROOT_DIR)/build
include $(ROOT_DIR)/common.mk

# Remove old includes with bad relative folders
CFLAGS := $(patsubst -I%,,$(CFLAGS))
# Add proper includes
CFLAGS += -I$(ROOT_DIR)/src/ -I$(ROOT_DIR)/src/external_deps

KEEP_SYMBOLS=--keep-global-symbol=sss_generate --keep-global-symbol=sss_combine --keep-global-symbol=sss_regenerate

all:	sss
ifeq ($(WITH_DYNAMIC_LIBS),1)
# If the user asked for dynamic libraries, compile versions of our binaries against them
all:	sss_dyn
endif

sss:
	$(CC) $(BIN_CFLAGS) -DSSS sss.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) $(LIBSIGN) -o sss

sss_lib:
	# Compile libsss archive
	$(CC) $(LIB_CFLAGS) -c sss.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c
	cp $(LIBSIGN) ./
	$(AR) xv libsign.a
	# Make unnecessary symbols local
	for f in `ls *.o`; do objcopy $(KEEP_SYMBOLS) $$f && echo "Processing $$f"; done
	# Combine the archives
	$(AR) $(AR_FLAGS) libsss.a *.o
	@rm -f *.o libsign.a

# If the user asked for dynamic libraries, compile versions of our binaries against them
ifeq ($(WITH_DYNAMIC_LIBS),1)
sss_dyn:
	$(CC) $(BIN_CFLAGS) -DSSS sss.c $(ROOT_DIR)/src/external_deps/print.c $(ROOT_DIR)/src/external_deps/rand.c $(BIN_LDFLAGS) $(LIBSIGN) -L$(BUILD_DIR) -lsign -o sss_dyn
endif


clean:
	@rm -f *.o
	@rm -f sss
	@rm -f sss_dyn

.PHONY: all clean 16 32 64 debug debug16 debug32 debug64 force_arch32 force_arch64
