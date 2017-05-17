# Detect mingw, since some versions throw a warning with the -fPIC option
# (which would be caught as an error in our case with -Werror)
# The ELF PIE related hardening flags are also non sense for Windows
MINGW := $(shell $(CC) -dumpmachine 2>&1 | grep -v mingw)
# Detect Mac OS compilers: these usually don't like ELF pie related flags ...
APPLE := $(shell $(CC) -dumpmachine 2>&1 | grep -v apple)
ifneq ($(MINGW),)
FPIC_CFLAG=-fPIC
ifneq ($(APPLE),)
FPIE_CFLAG=-fPIE
FPIE_LDFLAGS=-pie -Wl,-z,relro,-z,now
endif
STACK_PROT_FLAG=-fstack-protector-strong
endif

# The first goal here is to define a meaningful set of CFLAGS based on compiler,
# debug mode, expected word size (16, 32, 64), etc. Those are then used to
# define two differents kinds of CFLAGS we will use for building our library
# (LIB_CFLAGS) and binaries (BIN_CFLAGS) objects.
#
# When compiler is *explicitly* set to clang, use its -Weverything option by
# default but disable the sepcific options we cannot support:
#
#   -Wno-reserved-id-macro: our header files use __XXX___ protection macros.
#   -Wno-padded: padding warnings
#   -Wno-packed: warning about packed structure we want to keep that way
#   -Wno-covered-switch-default
#   -Wno-used-but-marked-unused
#
ifeq ($(CC),clang)
WARNING_CFLAGS = -Weverything -Werror \
		 -Wno-reserved-id-macro -Wno-padded \
		 -Wno-packed -Wno-covered-switch-default \
		 -Wno-used-but-marked-unused
else
WARNING_CFLAGS = -W -Werror -Wextra -Wall -Wunreachable-code
endif

# If the user has overridden the CFLAGS or LDFLAGS, let's detect it
# and adapt our compilation process
ifdef CFLAGS
USER_DEFINED_CFLAGS = $(CFLAGS)
endif
ifdef LDFLAGS
USER_DEFINED_LDFLAGS = $(LDFLAGS)
endif

CFLAGS ?= $(WARNING_CFLAGS) -pedantic -fno-builtin -std=c99 \
	  -D_FORTIFY_SOURCE=2 $(STACK_PROT_FLAG) -O3
LDFLAGS ?=

# Default AR and RANLIB if not overriden by user
AR ?= ar
RANLIB ?= ranlib

# Our debug flags
DEBUG_CFLAGS = -DDEBUG -O -g

# Default all and clean target that will be expanded
# later in the Makefile
all:
clean:

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: clean all

# Force 64-bit word size
64: CFLAGS += -DWORDSIZE=64
64: clean all
debug64: CFLAGS += -DWORDSIZE=64 $(DEBUG_CFLAGS)
debug64: clean all

# Force 32-bit word size
32: CFLAGS += -DWORDSIZE=32
32: clean all
debug32: CFLAGS += -DWORDSIZE=32 $(DEBUG_CFLAGS)
debug32: clean all

# Force 16-bit word size
16: CFLAGS += -DWORDSIZE=16
16: clean all
debug16: CFLAGS += -DWORDSIZE=16 $(DEBUG_CFLAGS)
debug16: clean all

# Force to compile with 64-bit arch
force_arch64: CFLAGS += -m64
force_arch64: clean all

# Force to compile with 32-bit arch
force_arch32: CFLAGS += -m32
force_arch32: clean all

# By default, we use an stdlib
ifneq ($(LIBECC_NOSTDLIB),1)
CFLAGS += -DWITH_STDLIB
endif

# Let's now define the two kinds of CFLAGS we will use for building our
# library (LIB_CFLAGS) and binaries (BIN_CFLAGS) objects.
# If the user has not overriden the CFLAGS, we add the usual gcc/clang
# flags to produce binaries compatible with hardening technologies.
ifndef USER_DEFINED_CFLAGS
BIN_CFLAGS  ?= $(CFLAGS) $(FPIE_CFLAG)
LIB_CFLAGS  ?= $(CFLAGS) $(FPIC_CFLAG) -ffreestanding
else
BIN_CFLAGS  ?= $(USER_DEFINED_CFLAGS)
LIB_CFLAGS  ?= $(USER_DEFINED_CFLAGS)
endif
ifndef USER_DEFINED_LDFLAGS
BIN_LDFLAGS ?= $(LDFLAGS) $(FPIE_LDFLAGS)
else
BIN_LDFLAGS ?= $(LDFLAGS)
endif

# Static libraries to produce or link to
LIBARITH = $(BUILD_DIR)/libarith.a
LIBEC = $(BUILD_DIR)/libec.a
LIBSIGN = $(BUILD_DIR)/libsign.a
