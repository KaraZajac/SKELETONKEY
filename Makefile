# IAMROOT — top-level Makefile (Phase 1)
#
# Builds one binary `iamroot` linked from:
#   - core/         module interface + registry
#   - modules/<f>/  one family per subdir, contributes objects to the
#                   final binary
#   - iamroot.c     top-level dispatcher
#
# Each family is currently flat (Phase 1 keeps copy_fail_family's
# absorbed DIRTYFAIL source in modules/copy_fail_family/src/).
# Future families register the same way: add their register_* call to
# iamroot.c's main() and add their src dir to MODULE_DIRS below.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -Wno-pointer-arith \
           -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS ?=

BUILD   := build
BIN     := iamroot

# core/
CORE_SRC := core/registry.c
CORE_OBJ := $(BUILD)/core/registry.o

# Family: copy_fail_family
# All DIRTYFAIL .c files contribute; iamroot_modules.c is the bridge.
CFF_DIR  := modules/copy_fail_family
CFF_SRCS := $(wildcard $(CFF_DIR)/src/*.c) $(CFF_DIR)/iamroot_modules.c
# Filter out the original dirtyfail.c (its main() conflicts with iamroot.c's main).
CFF_SRCS := $(filter-out $(CFF_DIR)/src/dirtyfail.c, $(CFF_SRCS))
CFF_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CFF_SRCS))

# Top-level dispatcher
TOP_OBJ  := $(BUILD)/iamroot.o

ALL_OBJS := $(TOP_OBJ) $(CORE_OBJ) $(CFF_OBJS)

.PHONY: all clean debug static help

all: $(BIN)

$(BIN): $(ALL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

# Generic compile: any .c → corresponding .o under build/
$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Icore -I$(CFF_DIR)/src -c -o $@ $<

debug: CFLAGS := -O0 -g3 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
debug: clean $(BIN)

static: LDFLAGS += -static
static: clean $(BIN)

clean:
	rm -rf $(BUILD) $(BIN)

help:
	@echo "Targets:"
	@echo "  make           build optimized iamroot binary"
	@echo "  make debug     build with -O0 -g3"
	@echo "  make static    build a fully static binary"
	@echo "  make clean     remove build artifacts"
	@echo ""
	@echo "Per-module (legacy) — not built by default:"
	@echo "  cd modules/copy_fail_family && make"
