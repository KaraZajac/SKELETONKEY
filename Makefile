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
CORE_SRCS := core/registry.c core/kernel_range.c
CORE_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CORE_SRCS))

# Family: copy_fail_family
# All DIRTYFAIL .c files contribute; iamroot_modules.c is the bridge.
CFF_DIR  := modules/copy_fail_family
CFF_SRCS := $(wildcard $(CFF_DIR)/src/*.c) $(CFF_DIR)/iamroot_modules.c
# Filter out the original dirtyfail.c (its main() conflicts with iamroot.c's main).
CFF_SRCS := $(filter-out $(CFF_DIR)/src/dirtyfail.c, $(CFF_SRCS))
CFF_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CFF_SRCS))

# Family: dirty_pipe (single-CVE family, no shared infrastructure)
DP_DIR   := modules/dirty_pipe_cve_2022_0847
DP_SRCS  := $(DP_DIR)/iamroot_modules.c
DP_OBJS  := $(patsubst %.c,$(BUILD)/%.o,$(DP_SRCS))

# Family: entrybleed (single-CVE family, x86_64 only)
EB_DIR   := modules/entrybleed_cve_2023_0458
EB_SRCS  := $(EB_DIR)/iamroot_modules.c
EB_OBJS  := $(patsubst %.c,$(BUILD)/%.o,$(EB_SRCS))

# Family: pwnkit (userspace polkit bug, not kernel)
PK_DIR   := modules/pwnkit_cve_2021_4034
PK_SRCS  := $(PK_DIR)/iamroot_modules.c
PK_OBJS  := $(patsubst %.c,$(BUILD)/%.o,$(PK_SRCS))

# Family: nf_tables (CVE-2024-1086)
NFT_DIR  := modules/nf_tables_cve_2024_1086
NFT_SRCS := $(NFT_DIR)/iamroot_modules.c
NFT_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(NFT_SRCS))

# Family: overlayfs (CVE-2021-3493)
OVL_DIR  := modules/overlayfs_cve_2021_3493
OVL_SRCS := $(OVL_DIR)/iamroot_modules.c
OVL_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(OVL_SRCS))

# Family: cls_route4 (CVE-2022-2588)
CR4_DIR  := modules/cls_route4_cve_2022_2588
CR4_SRCS := $(CR4_DIR)/iamroot_modules.c
CR4_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CR4_SRCS))

# Family: dirty_cow (CVE-2016-5195) — requires -pthread
DCOW_DIR  := modules/dirty_cow_cve_2016_5195
DCOW_SRCS := $(DCOW_DIR)/iamroot_modules.c
DCOW_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(DCOW_SRCS))

# Family: ptrace_traceme (CVE-2019-13272)
PTM_DIR  := modules/ptrace_traceme_cve_2019_13272
PTM_SRCS := $(PTM_DIR)/iamroot_modules.c
PTM_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(PTM_SRCS))

# Family: netfilter_xtcompat (CVE-2021-22555)
NXC_DIR  := modules/netfilter_xtcompat_cve_2021_22555
NXC_SRCS := $(NXC_DIR)/iamroot_modules.c
NXC_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(NXC_SRCS))

# Family: af_packet (CVE-2017-7308)
AFP_DIR  := modules/af_packet_cve_2017_7308
AFP_SRCS := $(AFP_DIR)/iamroot_modules.c
AFP_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(AFP_SRCS))

# Family: fuse_legacy (CVE-2022-0185)
FUL_DIR  := modules/fuse_legacy_cve_2022_0185
FUL_SRCS := $(FUL_DIR)/iamroot_modules.c
FUL_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(FUL_SRCS))

# Family: stackrot (CVE-2023-3269)
STR_DIR  := modules/stackrot_cve_2023_3269
STR_SRCS := $(STR_DIR)/iamroot_modules.c
STR_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(STR_SRCS))

# Family: af_packet2 (CVE-2020-14386) — same family as af_packet
AFP2_DIR  := modules/af_packet2_cve_2020_14386
AFP2_SRCS := $(AFP2_DIR)/iamroot_modules.c
AFP2_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(AFP2_SRCS))

# Top-level dispatcher
TOP_OBJ  := $(BUILD)/iamroot.o

ALL_OBJS := $(TOP_OBJ) $(CORE_OBJS) $(CFF_OBJS) $(DP_OBJS) $(EB_OBJS) $(PK_OBJS) $(NFT_OBJS) $(OVL_OBJS) $(CR4_OBJS) $(DCOW_OBJS) $(PTM_OBJS) $(NXC_OBJS) $(AFP_OBJS) $(FUL_OBJS) $(STR_OBJS) $(AFP2_OBJS)

.PHONY: all clean debug static help

all: $(BIN)

$(BIN): $(ALL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpthread

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
