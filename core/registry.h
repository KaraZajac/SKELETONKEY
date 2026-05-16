/*
 * IAMROOT — module registry
 *
 * Global list of registered modules. Each family contributes via
 * register_<family>_modules() called from iamroot main() at startup.
 */

#ifndef IAMROOT_REGISTRY_H
#define IAMROOT_REGISTRY_H

#include "module.h"

void iamroot_register(const struct iamroot_module *m);

size_t iamroot_module_count(void);
const struct iamroot_module *iamroot_module_at(size_t i);

/* Find a module by name. Returns NULL if not found. */
const struct iamroot_module *iamroot_module_find(const char *name);

/* Each module family declares one of these in its public header. The
 * top-level iamroot main() calls them in order at startup. */
void iamroot_register_copy_fail_family(void);

#endif /* IAMROOT_REGISTRY_H */
