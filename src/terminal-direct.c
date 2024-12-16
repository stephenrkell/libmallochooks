#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>

/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_hook_ ## i
#include "mallochooks/hookapi.h"

/* Also prototype the 'real' malloc itself. */
#ifndef MALLOC_PREFIX
#define MALLOC_PREFIX(x) __real_ ## x
#endif
#include "mallochooks/userapi.h"

void __terminal_hook_init(void) __attribute__((visibility("hidden")));
void __terminal_hook_init(void) {}

void * __terminal_hook_malloc(size_t size, const void *caller) __attribute__((visibility("hidden")));
void * __terminal_hook_malloc(size_t size, const void *caller)
{
	return MALLOC_PREFIX(malloc)(size);
}
void __terminal_hook_free(void *ptr, const void *caller) __attribute__((visibility("hidden")));
void __terminal_hook_free(void *ptr, const void *caller)
{
	MALLOC_PREFIX(free)(ptr);
}
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller) __attribute__((visibility("hidden")));
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	return MALLOC_PREFIX(realloc)(ptr, size);
}
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller) __attribute__((visibility("hidden")));
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	return MALLOC_PREFIX(memalign)(boundary, size);
}
