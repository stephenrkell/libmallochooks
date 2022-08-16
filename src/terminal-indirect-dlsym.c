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
#define GET_UNDERLYING(ret_t, m, argts...) \
	static ret_t (*underlying_ ## m )( argts ); \
	if (!underlying_ ## m) underlying_ ## m = dlsym_nomalloc(RTLD_NEXT, stringifx(MALLOC_PREFIX(m)) ); \
	if (!underlying_ ## m  || underlying_ ## m == (void*)-1) abort();

HIDDEN
void __terminal_hook_init(void) {}

HIDDEN
void * __terminal_hook_malloc(size_t size, const void *caller)
{
	ABORT_ON_REENTRANCY;
	GET_UNDERLYING(void*, malloc, size_t);
	return underlying_malloc(size);
}
HIDDEN
void __terminal_hook_free(void *ptr, const void *caller)
{
	ABORT_ON_REENTRANCY;
	GET_UNDERLYING(void, free, void*);
	underlying_free(ptr);
}
HIDDEN
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	ABORT_ON_REENTRANCY;
	GET_UNDERLYING(void*, realloc, void*, size_t);
	return underlying_realloc(ptr, size);
}
HIDDEN
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	ABORT_ON_REENTRANCY;
	GET_UNDERLYING(void*, memalign, size_t, size_t);
	return underlying_memalign(boundary, size);
}

#if 0
/* These are our actual hook stubs. */
void *malloc(size_t size)
{
	ABORT_ON_REENTRANCY;
	we_are_active = 1;
	void *ret = hook_malloc(size, __builtin_return_address(0));
	assert(we_are_active);
	we_are_active = 0;
	return ret;
}
void *calloc(size_t nmemb, size_t size)
{
	_Bool is_reentrant_call = we_are_active;
	if (!is_reentrant_call) we_are_active = 1;
	void *ret;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		ret = hook_malloc(nmemb * size, __builtin_return_address(0));
	} else ret = __private_calloc(nmemb, size);
	if (ret) bzero(ret, nmemb * size);
	if (!is_reentrant_call) we_are_active = 0;
	return ret;
}
void free(void *ptr)
{
	_Bool is_reentrant_call = we_are_active;
	if (!is_reentrant_call) we_are_active = 1;
	if ((!&__private_malloc_is_chunk_start && !is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
		|| (&__private_malloc_is_chunk_start && !__private_malloc_is_chunk_start(ptr)))
	{
		hook_free(ptr, __builtin_return_address(0));
	} else __private_free(ptr); // FIXME: seems dangerous: if we don't have
	// a __private_malloc_is_chunk_start, we might be __private_free-ing a
	// chunk that is not privately-alloc'd.
	if (!is_reentrant_call) we_are_active = 0;
}
void *realloc(void *ptr, size_t size)
{
	_Bool is_reentrant_call = we_are_active;
	void *ret;
	if ((!&__private_malloc_is_chunk_start && !is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
		|| (&__private_malloc_is_chunk_start && !__private_malloc_is_chunk_start(ptr)))
	{
		ret = hook_realloc(ptr, size, __builtin_return_address(0));
	} else ret = __private_realloc(ptr, size);
	if (!is_reentrant_call) we_are_active = 0;
	return ret;
}
void *memalign(size_t boundary, size_t size)
{
	_Bool is_reentrant_call = we_are_active;
	if (!is_reentrant_call) we_are_active = 1;
	void *ret;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		ret = hook_memalign(boundary, size, __builtin_return_address(0));
	} else ret = __private_memalign(boundary, size);
	if (!is_reentrant_call) we_are_active = 0;
	return ret;
}
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	_Bool is_reentrant_call = we_are_active;
	if (!is_reentrant_call) we_are_active = 1;
	void *retptr;
	int retval;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		retptr = hook_memalign(alignment, size, __builtin_return_address(0));

		if (!retptr) retval = EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
		else
		{
			*memptr = retptr;
			retval = 0;
		}
	}
	else retval = __private_posix_memalign(memptr, alignment, size);
	if (!is_reentrant_call) we_are_active = 0;
	return retval;
}
#endif
