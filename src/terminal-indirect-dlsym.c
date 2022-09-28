#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <link.h>
#include <err.h>
#include "relf.h"

#include <errno.h>

/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_hook_ ## i
#include "mallochooks/hookapi.h"

#define stringify(cond) #cond
// stringify expanded
#define stringifx(cond) stringify(cond)

#define HIDDEN __attribute__((visibility("hidden")))

/* Also prototype malloc itself if necessary. */

/* NOTE that we can easily get infinite regress, so we guard against it 
 * explicitly. The caller/client must ensure we never get reentrant calls.
 * One way to do this is fake_dlsym() rather than dlsym. We assume this is
 * taken care of and the token 'dlsym' will get us a viable dlsym function.
 * 
 * (Yes, reentrant calls really need to be an error. There's no way to
 * guarantee that a reentrant malloc isn't paired with a non-reentrant
 * free, or vice-versa. In liballocs, with early_malloc we used to get
 * around this because we could dynamically identify early_malloc's chunks,
 * but how do you know how much space yur early malloc pool needs? We then
 * got bugs where a special private malloc exhausted its initial arena and
 * suddenly we didn't recognise its newly mmap'd chunks. Nightmare....)
 *
 * To detect reentrancy, we share a single flag. This is because,
 * say, a calloc that gets hooked might end up calling malloc. We
 * still don't want reentrancy (e.g. we'll hang re-acquiring glibc
 * malloc's non-recursive arena mutex). */
static __thread _Bool we_are_active;
#define ABORT_ON_REENTRANCY do { \
	_Bool is_reentrant_call = we_are_active; \
	if (is_reentrant_call) abort(); \
	} while (0)
#ifndef dlsym_nomalloc
#warning "Expected a macro definition for dlsym_nomalloc, but continuing..."
#endif
#ifndef MALLOC_PREFIX
#define MALLOC_PREFIX(m) m
#endif
#ifndef MALLOC_DLSYM_TARGET
#define MALLOC_DLSYM_TARGET RTLD_NEXT
#endif
#define GET_UNDERLYING(ret_t, m, argts...) \
	static ret_t (*underlying_ ## m )( argts ); \
	if (!underlying_ ## m) underlying_ ## m = dlsym_nomalloc(MALLOC_DLSYM_TARGET, stringifx(MALLOC_PREFIX(m)) ); \
	if (!underlying_ ## m  || underlying_ ## m == (void*)-1) abort();

HIDDEN
void __terminal_hook_init(void) {}

HIDDEN
void * __terminal_hook_malloc(size_t size, const void *caller)
{
	ABORT_ON_REENTRANCY;
	we_are_active = 1;
	GET_UNDERLYING(void*, malloc, size_t);
	void *ret = underlying_malloc(size);
	we_are_active = 0;
	return ret;
}
HIDDEN
void __terminal_hook_free(void *ptr, const void *caller)
{
	ABORT_ON_REENTRANCY;
	we_are_active = 1;
	GET_UNDERLYING(void, free, void*);
	we_are_active = 0;
	underlying_free(ptr);
}
HIDDEN
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	ABORT_ON_REENTRANCY;
	we_are_active = 1;
	GET_UNDERLYING(void*, realloc, void*, size_t);
	void *ret = underlying_realloc(ptr, size);
	we_are_active = 0;
	return ret;
}
HIDDEN
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	ABORT_ON_REENTRANCY;
	we_are_active = 1;
	GET_UNDERLYING(void*, memalign, size_t, size_t);
	void *ret = underlying_memalign(boundary, size);
	we_are_active = 0;
	return ret;
}
