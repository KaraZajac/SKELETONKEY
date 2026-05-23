# SKELETONKEY — top-level Makefile (Phase 1)
#
# Builds one binary `skeletonkey` linked from:
#   - core/         module interface + registry
#   - modules/<f>/  one family per subdir, contributes objects to the
#                   final binary
#   - skeletonkey.c     top-level dispatcher
#
# Each family is currently flat (Phase 1 keeps copy_fail_family's
# absorbed DIRTYFAIL source in modules/copy_fail_family/src/).
# Future families register the same way: add their register_* call to
# skeletonkey.c's main() and add their src dir to MODULE_DIRS below.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -Wno-pointer-arith \
           -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS ?=

BUILD   := build
BIN     := skeletonkey

# core/
CORE_SRCS := core/registry.c core/kernel_range.c core/offsets.c core/finisher.c \
             core/host.c core/cve_metadata.c core/verifications.c
CORE_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CORE_SRCS))

# Register-every-module helper. Lives in its own translation unit so
# the kernel_range unit-test binary can link just CORE_OBJS without
# pulling in every module symbol via registry_all.o.
REGISTRY_ALL_OBJ := $(BUILD)/core/registry_all.o

# Family: copy_fail_family
# All DIRTYFAIL .c files contribute; skeletonkey_modules.c is the bridge.
CFF_DIR  := modules/copy_fail_family
CFF_SRCS := $(wildcard $(CFF_DIR)/src/*.c) $(CFF_DIR)/skeletonkey_modules.c
# Filter out the original dirtyfail.c (its main() conflicts with skeletonkey.c's main).
CFF_SRCS := $(filter-out $(CFF_DIR)/src/dirtyfail.c, $(CFF_SRCS))
CFF_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CFF_SRCS))

# Family: dirty_pipe (single-CVE family, no shared infrastructure)
DP_DIR   := modules/dirty_pipe_cve_2022_0847
DP_SRCS  := $(DP_DIR)/skeletonkey_modules.c
DP_OBJS  := $(patsubst %.c,$(BUILD)/%.o,$(DP_SRCS))

# Family: entrybleed (single-CVE family, x86_64 only)
EB_DIR   := modules/entrybleed_cve_2023_0458
EB_SRCS  := $(EB_DIR)/skeletonkey_modules.c
EB_OBJS  := $(patsubst %.c,$(BUILD)/%.o,$(EB_SRCS))

# Family: pwnkit (userspace polkit bug, not kernel)
PK_DIR   := modules/pwnkit_cve_2021_4034
PK_SRCS  := $(PK_DIR)/skeletonkey_modules.c
PK_OBJS  := $(patsubst %.c,$(BUILD)/%.o,$(PK_SRCS))

# Family: nf_tables (CVE-2024-1086)
NFT_DIR  := modules/nf_tables_cve_2024_1086
NFT_SRCS := $(NFT_DIR)/skeletonkey_modules.c
NFT_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(NFT_SRCS))

# Family: overlayfs (CVE-2021-3493)
OVL_DIR  := modules/overlayfs_cve_2021_3493
OVL_SRCS := $(OVL_DIR)/skeletonkey_modules.c
OVL_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(OVL_SRCS))

# Family: cls_route4 (CVE-2022-2588)
CR4_DIR  := modules/cls_route4_cve_2022_2588
CR4_SRCS := $(CR4_DIR)/skeletonkey_modules.c
CR4_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CR4_SRCS))

# Family: dirty_cow (CVE-2016-5195) — requires -pthread
DCOW_DIR  := modules/dirty_cow_cve_2016_5195
DCOW_SRCS := $(DCOW_DIR)/skeletonkey_modules.c
DCOW_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(DCOW_SRCS))

# Family: ptrace_traceme (CVE-2019-13272)
PTM_DIR  := modules/ptrace_traceme_cve_2019_13272
PTM_SRCS := $(PTM_DIR)/skeletonkey_modules.c
PTM_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(PTM_SRCS))

# Family: netfilter_xtcompat (CVE-2021-22555)
NXC_DIR  := modules/netfilter_xtcompat_cve_2021_22555
NXC_SRCS := $(NXC_DIR)/skeletonkey_modules.c
NXC_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(NXC_SRCS))

# Family: af_packet (CVE-2017-7308)
AFP_DIR  := modules/af_packet_cve_2017_7308
AFP_SRCS := $(AFP_DIR)/skeletonkey_modules.c
AFP_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(AFP_SRCS))

# Family: fuse_legacy (CVE-2022-0185)
FUL_DIR  := modules/fuse_legacy_cve_2022_0185
FUL_SRCS := $(FUL_DIR)/skeletonkey_modules.c
FUL_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(FUL_SRCS))

# Family: stackrot (CVE-2023-3269)
STR_DIR  := modules/stackrot_cve_2023_3269
STR_SRCS := $(STR_DIR)/skeletonkey_modules.c
STR_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(STR_SRCS))

# Family: af_packet2 (CVE-2020-14386) — same family as af_packet
AFP2_DIR  := modules/af_packet2_cve_2020_14386
AFP2_SRCS := $(AFP2_DIR)/skeletonkey_modules.c
AFP2_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(AFP2_SRCS))

# Family: cgroup_release_agent (CVE-2022-0492)
CRA_DIR  := modules/cgroup_release_agent_cve_2022_0492
CRA_SRCS := $(CRA_DIR)/skeletonkey_modules.c
CRA_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CRA_SRCS))

# Family: overlayfs_setuid (CVE-2023-0386) — joins overlayfs family
OSU_DIR  := modules/overlayfs_setuid_cve_2023_0386
OSU_SRCS := $(OSU_DIR)/skeletonkey_modules.c
OSU_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(OSU_SRCS))

# Family: nft_set_uaf (CVE-2023-32233)
NSU_DIR  := modules/nft_set_uaf_cve_2023_32233
NSU_SRCS := $(NSU_DIR)/skeletonkey_modules.c
NSU_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(NSU_SRCS))

# Family: af_unix_gc (CVE-2023-4622)
AUG_DIR  := modules/af_unix_gc_cve_2023_4622
AUG_SRCS := $(AUG_DIR)/skeletonkey_modules.c
AUG_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(AUG_SRCS))

# Family: nft_fwd_dup (CVE-2022-25636)
NFD_DIR  := modules/nft_fwd_dup_cve_2022_25636
NFD_SRCS := $(NFD_DIR)/skeletonkey_modules.c
NFD_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(NFD_SRCS))

# Family: nft_payload (CVE-2023-0179)
NPL_DIR  := modules/nft_payload_cve_2023_0179
NPL_SRCS := $(NPL_DIR)/skeletonkey_modules.c
NPL_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(NPL_SRCS))

SAM_DIR  := modules/sudo_samedit_cve_2021_3156
SAM_SRCS := $(SAM_DIR)/skeletonkey_modules.c
SAM_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(SAM_SRCS))

SEQ_DIR  := modules/sequoia_cve_2021_33909
SEQ_SRCS := $(SEQ_DIR)/skeletonkey_modules.c
SEQ_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(SEQ_SRCS))

SUE_DIR  := modules/sudoedit_editor_cve_2023_22809
SUE_SRCS := $(SUE_DIR)/skeletonkey_modules.c
SUE_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(SUE_SRCS))

VMW_DIR  := modules/vmwgfx_cve_2023_2008
VMW_SRCS := $(VMW_DIR)/skeletonkey_modules.c
VMW_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(VMW_SRCS))

# Family: dirtydecrypt (CVE-2026-31635) — rxgk page-cache write
DDC_DIR  := modules/dirtydecrypt_cve_2026_31635
DDC_SRCS := $(DDC_DIR)/skeletonkey_modules.c
DDC_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(DDC_SRCS))

# Family: fragnesia (CVE-2026-46300) — XFRM ESP-in-TCP page-cache write
FGN_DIR  := modules/fragnesia_cve_2026_46300
FGN_SRCS := $(FGN_DIR)/skeletonkey_modules.c
FGN_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(FGN_SRCS))

# Family: pack2theroot (CVE-2026-41651) — PackageKit TOCTOU userspace LPE.
# Needs GLib/GIO for D-Bus; the build autodetects via `pkg-config gio-2.0`.
# When absent (e.g. no libglib2.0-dev on the build host), the module
# compiles as a stub that returns PRECOND_FAIL with a hint to install
# the dev package and rebuild.
P2TR_DIR  := modules/pack2theroot_cve_2026_41651
P2TR_SRCS := $(P2TR_DIR)/skeletonkey_modules.c
P2TR_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(P2TR_SRCS))

P2TR_GIO_OK := $(shell pkg-config --exists gio-2.0 2>/dev/null && echo 1 || echo 0)
ifeq ($(P2TR_GIO_OK),1)
  P2TR_CFLAGS := $(shell pkg-config --cflags gio-2.0) -DPACK2TR_HAVE_GIO
  P2TR_LIBS   := $(shell pkg-config --libs gio-2.0)
else
  P2TR_CFLAGS :=
  P2TR_LIBS   :=
endif

# Per-object CFLAGS for the pack2theroot translation unit (GLib include
# paths). Target-specific vars are scoped to this object's recipe.
$(P2TR_OBJS): CFLAGS += $(P2TR_CFLAGS)

# Top-level dispatcher
TOP_OBJ  := $(BUILD)/skeletonkey.o

# All module objects in one var so both the main binary and the test
# binary can re-use the list without duplicating the long enumeration.
MODULE_OBJS := $(CFF_OBJS) $(DP_OBJS) $(EB_OBJS) $(PK_OBJS) $(NFT_OBJS) \
               $(OVL_OBJS) $(CR4_OBJS) $(DCOW_OBJS) $(PTM_OBJS) $(NXC_OBJS) \
               $(AFP_OBJS) $(FUL_OBJS) $(STR_OBJS) $(AFP2_OBJS) $(CRA_OBJS) \
               $(OSU_OBJS) $(NSU_OBJS) $(AUG_OBJS) $(NFD_OBJS) $(NPL_OBJS) \
               $(SAM_OBJS) $(SEQ_OBJS) $(SUE_OBJS) $(VMW_OBJS) \
               $(DDC_OBJS) $(FGN_OBJS) $(P2TR_OBJS)

ALL_OBJS := $(TOP_OBJ) $(CORE_OBJS) $(REGISTRY_ALL_OBJ) $(MODULE_OBJS)

# Tests — `make test` builds and runs both unit-test binaries.
#
#   skeletonkey-test          — detect() integration tests against
#                                synthetic host fingerprints. Links
#                                the full module corpus.
#   skeletonkey-test-kr       — pure unit tests for kernel_range +
#                                host comparison helpers. Tiny binary
#                                (core/ only); runs cross-platform.
TEST_DIR  := tests
TEST_SRCS := $(TEST_DIR)/test_detect.c
TEST_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(TEST_SRCS))
TEST_BIN  := skeletonkey-test
TEST_ALL_OBJS := $(TEST_OBJS) $(CORE_OBJS) $(REGISTRY_ALL_OBJ) $(MODULE_OBJS)

TEST_KR_SRCS := $(TEST_DIR)/test_kernel_range.c
TEST_KR_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(TEST_KR_SRCS))
TEST_KR_BIN  := skeletonkey-test-kr
TEST_KR_ALL_OBJS := $(TEST_KR_OBJS) $(CORE_OBJS)

.PHONY: all clean debug static help test

all: $(BIN)

$(BIN): $(ALL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpthread $(P2TR_LIBS)

$(TEST_BIN): $(TEST_ALL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpthread $(P2TR_LIBS)

$(TEST_KR_BIN): $(TEST_KR_ALL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

test: $(TEST_BIN) $(TEST_KR_BIN)
	@echo "[*] running kernel_range unit tests ($(TEST_KR_BIN))"
	./$(TEST_KR_BIN)
	@echo
	@echo "[*] running detect() integration tests ($(TEST_BIN))"
	./$(TEST_BIN)

# Generic compile: any .c → corresponding .o under build/
$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Icore -I$(CFF_DIR)/src -c -o $@ $<

debug: CFLAGS := -O0 -g3 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
debug: clean $(BIN)

static: LDFLAGS += -static
static: clean $(BIN)

clean:
	rm -rf $(BUILD) $(BIN) $(TEST_BIN) $(TEST_KR_BIN)

help:
	@echo "Targets:"
	@echo "  make           build optimized skeletonkey binary"
	@echo "  make debug     build with -O0 -g3"
	@echo "  make static    build a fully static binary"
	@echo "  make test      build + run the detect() unit test suite"
	@echo "  make clean     remove build artifacts"
	@echo ""
	@echo "Per-module (legacy) — not built by default:"
	@echo "  cd modules/copy_fail_family && make"
