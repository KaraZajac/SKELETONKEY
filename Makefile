# IAMROOT top-level Makefile
#
# Phase 0 (current): defers to modules/copy_fail_family/Makefile.
# Phase 1: real dispatcher build that links all modules into one
# binary. See ROADMAP.md.

MODULES := copy_fail_family

.PHONY: all clean $(MODULES)

all: $(MODULES)

$(MODULES):
	$(MAKE) -C modules/$@

clean:
	@for m in $(MODULES); do \
		$(MAKE) -C modules/$$m clean; \
	done
	rm -rf build/

# Convenience: scan the host using the absorbed DIRTYFAIL-as-module
# until Phase 1's real dispatcher lands.
scan:
	@modules/copy_fail_family/dirtyfail --scan 2>/dev/null || \
	 (echo "Build the copy_fail module first: make copy_fail_family" && exit 1)
