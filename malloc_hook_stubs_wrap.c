#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>

/* don't hide these symbols */
#define HIDDEN
#define HOOK_ATTRIBUTES

/* Prototype the hook_* functions. */
#undef HOOK_PREFIX
#define HOOK_PREFIX(i) hook_ ## i
#include "hook_protos.h"
#undef HOOK_PREFIX
/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_hook_ ## i
#include "hook_protos.h"

/* Also prototype malloc itself if necessary. */
#include "malloc_protos.h"

/* These are the underlying malloc and friends. */
void *MALLOC_PREFIX(__real_, malloc)(size_t size);
void *MALLOC_PREFIX(__real_, calloc)(size_t nmemb, size_t size);
void MALLOC_PREFIX(__real_, free)(void *ptr);
void *MALLOC_PREFIX(__real_, realloc)(void *ptr, size_t size);
void *MALLOC_PREFIX(__real_, memalign)(size_t boundary, size_t size);
int MALLOC_PREFIX(__real_, posix_memalign)(void **memptr, size_t alignment, size_t size);
size_t MALLOC_PREFIX(__real_, malloc_usable_size)(void *ptr);
/* NOTE: liballocs's preload.c wraps malloc_usable_size. Do we need to wrap it too? 
 * Since we don't use early malloc, I think the answer here is no. */

void __terminal_hook_init(void) __attribute__((visibility("hidden")));
void __terminal_hook_init(void) {}

void * __terminal_hook_malloc(size_t size, const void *caller) __attribute__((visibility("hidden")));
void * __terminal_hook_malloc(size_t size, const void *caller)
{
	return MALLOC_PREFIX(__real_, malloc)(size);
}
void __terminal_hook_free(void *ptr, const void *caller) __attribute__((visibility("hidden")));
void __terminal_hook_free(void *ptr, const void *caller)
{
	MALLOC_PREFIX(__real_, free)(ptr);
}
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller) __attribute__((visibility("hidden")));
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	return MALLOC_PREFIX(__real_, realloc)(ptr, size);
}
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller) __attribute__((visibility("hidden")));
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	return MALLOC_PREFIX(__real_, memalign)(boundary, size);
}

#include "wrappers.h"

DEFINE_WRAPPERS(__wrap_, hidden)

size_t MALLOC_PREFIX(__mallochooks_, malloc_usable_size)(void *ptr) __attribute__((visibility("hidden")));
size_t MALLOC_PREFIX(__mallochooks_, malloc_usable_size)(void *ptr)
{
	return MALLOC_PREFIX(__real_, malloc_usable_size)(ptr);
}
