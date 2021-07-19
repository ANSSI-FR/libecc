.SUFFIXES:

# Where to put generated objects
BUILD_DIR ?= build
include common.mk


# Static libraries to build
LIBS = $(LIBARITH) $(LIBEC) $(LIBSIGN)

# Compile dynamic libraries if the user asked to
ifeq ($(WITH_DYNAMIC_LIBS),1)
LIBS += $(LIBARITH_DYN) $(LIBEC_DYN) $(LIBSIGN_DYN)
endif

# Executables to build
TESTS_EXEC = $(BUILD_DIR)/ec_self_tests $(BUILD_DIR)/ec_utils
# We also compile executables with dynamic linking if asked to
ifeq ($(WITH_DYNAMIC_LIBS),1)
TESTS_EXEC += $(BUILD_DIR)/ec_self_tests_dyn $(BUILD_DIR)/ec_utils_dyn
endif

EXEC_TO_CLEAN = $(BUILD_DIR)/ec_self_tests $(BUILD_DIR)/ec_utils $(BUILD_DIR)/ec_self_tests_dyn $(BUILD_DIR)/ec_utils_dyn

# all and clean, as you might expect
all: depend $(LIBS) $(TESTS_EXEC)

clean:
	@rm -f $(LIBS) $(EXEC_TO_CLEAN)
	@find . -name '*.o' -exec rm -f '{}' \;
	@find . -name '*.d' -exec rm -f '{}' \;
	@find . -name '*.a' -exec rm -f '{}' \;
	@find . -name '*.so' -exec rm -f '{}' \;
	@find . -name '*~'  -exec rm -f '{}' \;

# library configuration files

CFG_DEPS = $(wildcard src/*.h)

# external dependencies

EXT_DEPS_SRC = $(wildcard src/external_deps/*.c)
EXT_DEPS_OBJECTS = $(patsubst %.c, %.o, $(EXT_DEPS_SRC))
EXT_DEPS_DEPS = $(patsubst %.c, %.d, $(EXT_DEPS_SRC))

src/external_deps/%.d: src/external_deps/%.c
	$(CC) $(LIB_CFLAGS) -MM $< -MF $@

src/external_deps/%.o: src/external_deps/%.c
	$(CC) $(LIB_CFLAGS) -c $< -o $@

# utils module (for the ARITH layer, we only need
# NN and FP - and not curves - related stuff. Same goes
# for EC and SIGN. Hence the distinction between three
# sets of utils objects.

UTILS_ARITH_SRC = src/utils/utils.c
UTILS_ARITH_SRC += $(wildcard src/utils/*_nn.c)
UTILS_ARITH_SRC += $(wildcard src/utils/*_fp.c)
UTILS_ARITH_SRC += $(wildcard src/utils/*_buf.c)
UTILS_ARITH_OBJECTS = $(patsubst %.c, %.o, $(UTILS_ARITH_SRC))
UTILS_ARITH_DEPS = $(patsubst %.c, %.d, $(UTILS_ARITH_SRC))

UTILS_EC_SRC = $(wildcard src/utils/*_curves.c)
UTILS_EC_OBJECTS = $(patsubst %.c, %.o, $(UTILS_EC_SRC))
UTILS_EC_DEPS = $(patsubst %.c, %.d, $(UTILS_EC_SRC))

UTILS_SIGN_SRC = $(wildcard src/utils/*_keys.c)
UTILS_SIGN_OBJECTS = $(patsubst %.c, %.o, $(UTILS_SIGN_SRC))
UTILS_SIGN_DEPS = $(patsubst %.c, %.d, $(UTILS_SIGN_SRC))

src/utils/%.d: src/utils/%.c
	$(CC) $(LIB_CFLAGS) -MM $< -MF $@

src/utils/%.o: src/utils/%.c
	$(CC) $(LIB_CFLAGS) -c $< -o $@


# nn module

NN_CONFIG = src/nn/nn_config.h
NN_SRC = $(wildcard src/nn/n*.c)
NN_OBJECTS = $(patsubst %.c, %.o, $(NN_SRC))
NN_DEPS = $(patsubst %.c, %.d, $(NN_SRC))

src/nn/%.d: src/nn/%.c $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/nn/*.c), $<), @$(CC) $(LIB_CFLAGS) -MM $< -MF $@)

src/nn/%.o: src/nn/%.c $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/nn/*.c), $<), $(CC) $(LIB_CFLAGS) -c $< -o $@)

# fp module

FP_SRC = $(wildcard src/fp/fp*.c)
FP_OBJECTS = $(patsubst %.c, %.o, $(FP_SRC))
FP_DEPS = $(patsubst %.c, %.d, $(FP_SRC))

src/fp/%.d: src/fp/%.c $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/fp/*.c), $<), @$(CC) $(LIB_CFLAGS) -MM $< -MF $@)

src/fp/%.o: src/fp/%.c $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/fp/*.c), $<), $(CC) $(LIB_CFLAGS) -c $< -o $@)


LIBARITH_OBJECTS = $(FP_OBJECTS) $(NN_OBJECTS) $(RAND_OBJECTS) $(UTILS_ARITH_OBJECTS)
$(LIBARITH): $(LIBARITH_OBJECTS)
	$(AR) $(AR_FLAGS) $@ $^
	$(RANLIB) $(RANLIB_FLAGS) $@

# Compile dynamic libraries if the user asked to
ifeq ($(WITH_DYNAMIC_LIBS),1)
$(LIBARITH_DYN): $(LIBARITH_OBJECTS)
	$(CC) $(LIB_CFLAGS) $(LIB_DYN_LDFLAGS) $^ -o $@
endif

# curve module

CURVES_SRC = $(wildcard src/curves/*.c)
CURVES_OBJECTS = $(patsubst %.c, %.o, $(CURVES_SRC))
CURVES_DEPS = $(patsubst %.c, %.d, $(CURVES_SRC))

src/curves/%.d: src/curves/%.c $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/curves/*.c), $<), @$(CC) $(LIB_CFLAGS) -MM $< -MF $@)

src/curves/%.o: src/curves/%.c $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/curves/*.c), $<), $(CC) $(LIB_CFLAGS) -c $< -o $@)


LIBEC_OBJECTS = $(LIBARITH_OBJECTS) $(CURVES_OBJECTS) $(UTILS_EC_OBJECTS)
$(LIBEC): $(LIBEC_OBJECTS)
	$(AR) $(AR_FLAGS) $@ $^
	$(RANLIB) $(RANLIB_FLAGS) $@

# Compile dynamic libraries if the user asked to
ifeq ($(WITH_DYNAMIC_LIBS),1)
$(LIBEC_DYN): $(LIBEC_OBJECTS)
	$(CC) $(LIB_CFLAGS) $(LIB_DYN_LDFLAGS) $^ -o $@
endif

# Hash module

HASH_SRC = $(wildcard src/hash/sha*.c) src/hash/hash_algs.c src/hash/sm3.c src/hash/streebog.c src/hash/hmac.c
HASH_OBJECTS = $(patsubst %.c, %.o, $(HASH_SRC))
HASH_DEPS = $(patsubst %.c, %.d, $(HASH_SRC))

src/hash/%.d: src/hash/%.c $(CFG_DEPS)
	$(if $(filter $(wildcard src/hash/*.c), $<), @$(CC) $(LIB_CFLAGS) -MM $< -MF $@)

src/hash/%.o: src/hash/%.c $(CFG_DEPS)
	$(if $(filter $(wildcard src/hash/*.c), $<), $(CC) $(LIB_CFLAGS) -c $< -o $@)


# Key/Signature/Verification module

SIG_SRC = $(wildcard src/sig/*dsa.c) src/sig/ecdsa_common.c src/sig/ecsdsa_common.c src/sig/sig_algs.c src/sig/sm2.c src/sig/decdsa.c
SIG_OBJECTS = $(patsubst %.c, %.o, $(SIG_SRC))
SIG_DEPS = $(patsubst %.c, %.d, $(SIG_SRC))

src/sig/%.d: src/sig/%.c $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/sig/*.c), $<), @$(CC) $(LIB_CFLAGS) -MM $< -MF $@)

src/sig/%.o: src/sig/%.c $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/sig/*.c), $<), $(CC) $(LIB_CFLAGS) -c $< -o $@)


KEY_SRC = src/sig/ec_key.c
KEY_OBJECTS = $(patsubst %.c, %.o, $(KEY_SRC))
KEY_DEPS = $(patsubst %.c, %.d, $(KEY_SRC))

$(KEY_DEPS): $(KEY_SRC) $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/sig/*.c), $<), @$(CC) $(LIB_CFLAGS) -MM $< -MF $@)

$(KEY_OBJECTS): $(KEY_SRC) $(NN_CONFIG) $(CFG_DEPS)
	$(if $(filter $(wildcard src/sig/*.c), $<), $(CC) $(LIB_CFLAGS) -c $< -o $@)


LIBSIGN_OBJECTS = $(LIBEC_OBJECTS) $(HASH_OBJECTS) $(SIG_OBJECTS) $(KEY_OBJECTS) $(UTILS_SIGN_OBJECTS)
$(LIBSIGN): $(LIBSIGN_OBJECTS)
	$(AR) $(AR_FLAGS) $@ $^
	$(RANLIB) $(RANLIB_FLAGS) $@

# Compile dynamic libraries if the user asked to
ifeq ($(WITH_DYNAMIC_LIBS),1)
$(LIBSIGN_DYN): $(LIBSIGN_OBJECTS)
	$(CC) $(LIB_CFLAGS) $(LIB_DYN_LDFLAGS) $^ -o $@
endif

# Test elements (objects and binaries)

TESTS_OBJECTS_CORE_SRC = src/tests/ec_self_tests_core.c
TESTS_OBJECTS_CORE = $(patsubst %.c, %.o, $(TESTS_OBJECTS_CORE_SRC))
TESTS_OBJECTS_CORE_DEPS = $(patsubst %.c, %.d, $(TESTS_OBJECTS_CORE_SRC))
TESTS_OBJECTS_SELF_SRC = src/tests/ec_self_tests.c
TESTS_OBJECTS_SELF = $(patsubst %.c, %.o, $(TESTS_OBJECTS_SELF_SRC))
TESTS_OBJECTS_SELF_DEPS = $(patsubst %.c, %.d, $(TESTS_OBJECTS_SELF_SRC))
TESTS_OBJECTS_UTILS_SRC = src/tests/ec_utils.c
TESTS_OBJECTS_UTILS = $(patsubst %.c, %.o, $(TESTS_OBJECTS_UTILS_SRC))
TESTS_OBJECTS_UTILS_DEPS = $(patsubst %.c, %.d, $(TESTS_OBJECTS_UTILS_SRC))

$(TESTS_OBJECTS_CORE_DEPS): $(TESTS_OBJECTS_CORE_SRC) $(CFG_DEPS)
	$(if $(filter $(wildcard src/tests/*.c), $<), @$(CC) $(LIB_CFLAGS) -MM $< -MF $@)

$(TESTS_OBJECTS_CORE): $(TESTS_OBJECTS_CORE_SRC) $(CFG_DEPS)
	$(if $(filter $(wildcard src/tests/*.c), $<), $(CC) $(LIB_CFLAGS) -c $< -o $@)

src/tests/%.d:  src/tests/%.c $(CFG_DEPS)
	$(if $(filter src/tests/ec_utils.c, $<), $(CC) $(LIB_CFLAGS) -MM $< -MF $@)
	$(if $(filter-out src/tests/ec_utils.c, $<), $(CC) $(LIB_CFLAGS) -MM $< -MF $@)

$(BUILD_DIR)/ec_self_tests: $(TESTS_OBJECTS_CORE) $(TESTS_OBJECTS_SELF_SRC) $(EXT_DEPS_OBJECTS) $(LIBSIGN)
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) $^ -o $@

$(BUILD_DIR)/ec_utils: $(TESTS_OBJECTS_CORE) $(TESTS_OBJECTS_UTILS_SRC) $(EXT_DEPS_OBJECTS) $(LIBSIGN)
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) -DWITH_STDLIB  $^ -o $@

# If the user asked for dynamic libraries, compile versions of our binaries against them
ifeq ($(WITH_DYNAMIC_LIBS),1)
$(BUILD_DIR)/ec_self_tests_dyn: $(TESTS_OBJECTS_CORE) $(TESTS_OBJECTS_SELF_SRC) $(EXT_DEPS_OBJECTS)
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) -L$(BUILD_DIR) $^ -lsign -o $@

$(BUILD_DIR)/ec_utils_dyn: $(TESTS_OBJECTS_CORE) $(TESTS_OBJECTS_UTILS_SRC) $(EXT_DEPS_OBJECTS)
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) -L$(BUILD_DIR) -DWITH_STDLIB  $^ -lsign -o $@
endif


DEPENDS = $(EXT_DEPS_DEPS) $(UTILS_ARITH_DEPS) $(UTILS_EC_DEPS) $(UTILS_SIGN_DEPS) $(NN_DEPS) $(FP_DEPS) $(CURVES_DEPS) \
	  $(HASH_DEPS) $(SIG_DEPS) $(KEY_DEPS) $(TESTS_OBJECTS_CORE_DEPS) $(TESTS_OBJECTS_SELF_DEPS) $(TESTS_OBJECTS_UTILS_DEPS)
depend: $(DEPENDS)

.PHONY: all depend clean 16 32 64 debug debug16 debug32 debug64 force_arch32 force_arch64
