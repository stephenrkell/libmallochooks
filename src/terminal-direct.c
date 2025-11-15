#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>

#ifndef OUR_HOOK
#define OUR_HOOK(m) __terminal_hook_ ## m
#endif

/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) OUR_HOOK(i)
#include "mallochooks/hookapi.h"

/* Also prototype the 'real' malloc itself. */
#ifndef MALLOC_PREFIX
#define MALLOC_PREFIX(x) __real_ ## x
#endif
#include "mallochooks/userapi.h"

void OUR_HOOK(init)(void) __attribute__((visibility("hidden")));
void OUR_HOOK(init)(void) {}

void * OUR_HOOK(malloc)(size_t size, const void *caller) __attribute__((visibility("hidden")));
void * OUR_HOOK(malloc)(size_t size, const void *caller)
{
	return MALLOC_PREFIX(malloc)(size);
}
void OUR_HOOK(free)(void *ptr, const void *caller) __attribute__((visibility("hidden")));
void OUR_HOOK(free)(void *ptr, const void *caller)
{
	MALLOC_PREFIX(free)(ptr);
}
void * OUR_HOOK(realloc)(void *ptr, size_t size, const void *caller) __attribute__((visibility("hidden")));
void * OUR_HOOK(realloc)(void *ptr, size_t size, const void *caller)
{
	return MALLOC_PREFIX(realloc)(ptr, size);
}
void * OUR_HOOK(memalign)(size_t boundary, size_t size, const void *caller) __attribute__((visibility("hidden")));
void * OUR_HOOK(memalign)(size_t boundary, size_t size, const void *caller)
{
	return MALLOC_PREFIX(memalign)(boundary, size);
}

size_t OUR_HOOK(malloc_usable_size)(void *ptr) __attribute__((visibility("hidden")));
size_t OUR_HOOK(malloc_usable_size)(void *ptr)
{
	return MALLOC_PREFIX(malloc_usable_size)(ptr);
}
