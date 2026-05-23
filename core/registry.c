/*
 * SKELETONKEY — module registry implementation
 *
 * Simple flat array. Resized in chunks of 16. We never expect more
 * than a few dozen modules, so this is fine.
 *
 * The canonical "register every family" enumeration lives in
 * registry_all.c — kept separate so this file links into the
 * standalone kernel_range unit-test binary without pulling in every
 * module's symbol.
 */

#include "registry.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REGISTRY_CHUNK 16

static const struct skeletonkey_module **g_modules = NULL;
static size_t g_count = 0;
static size_t g_cap = 0;

void skeletonkey_register(const struct skeletonkey_module *m)
{
    if (m == NULL || m->name == NULL) {
        fprintf(stderr, "[!] skeletonkey_register: NULL module or unnamed module\n");
        return;
    }
    if (g_count == g_cap) {
        size_t new_cap = g_cap + REGISTRY_CHUNK;
        const struct skeletonkey_module **n =
            realloc((void *)g_modules, new_cap * sizeof(*g_modules));
        if (n == NULL) {
            fprintf(stderr, "[!] skeletonkey_register: OOM\n");
            return;
        }
        g_modules = n;
        g_cap = new_cap;
    }
    g_modules[g_count++] = m;
}

size_t skeletonkey_module_count(void)
{
    return g_count;
}

const struct skeletonkey_module *skeletonkey_module_at(size_t i)
{
    if (i >= g_count) return NULL;
    return g_modules[i];
}

const struct skeletonkey_module *skeletonkey_module_find(const char *name)
{
    if (name == NULL) return NULL;
    for (size_t i = 0; i < g_count; i++) {
        if (strcmp(g_modules[i]->name, name) == 0)
            return g_modules[i];
    }
    return NULL;
}
