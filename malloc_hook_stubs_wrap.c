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
#define HOOK_PREFIX(i) i
#include "hook_protos.h"
#undef HOOK_PREFIX
/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_ ## i
#include "hook_protos.h"

/* These are the libc's malloc and friends. */
void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void __real_free(void *ptr);
void *__real_realloc(void *ptr, size_t size);
void *__real_memalign(size_t boundary, size_t size);
int __real_posix_memalign(void **memptr, size_t alignment, size_t size);
size_t __real_malloc_usable_size(void *ptr);
/* NOTE: liballocs's preload.c wraps malloc_usable_size. Do we need to wrap it too? 
 * Since we don't use early malloc, I think the answer here is no. */

void __terminal_hook_init(void) {}

void * __terminal_hook_malloc(size_t size, const void *caller)
{
	return __real_malloc(size);
}
void __terminal_hook_free(void *ptr, const void *caller)
{
	__real_free(ptr);
}
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	return __real_realloc(ptr, size);
}
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	return __real_memalign(boundary, size);
}

/* These are our actual hook stubs. */
void *__wrap_malloc(size_t size)
{
	void *ret;
	ret = hook_malloc(size, __builtin_return_address(0));
	return ret;
}
void *__wrap_calloc(size_t nmemb, size_t size)
{
	void *ret;
	ret = hook_malloc(nmemb * size, __builtin_return_address(0));
	if (ret) bzero(ret, nmemb * size);
	return ret;
}
void __wrap_free(void *ptr)
{
	hook_free(ptr, __builtin_return_address(0));
}
void *__wrap_realloc(void *ptr, size_t size)
{
	void *ret;
	ret = hook_realloc(ptr, size, __builtin_return_address(0));
	return ret;
}
void *__wrap_memalign(size_t boundary, size_t size)
{
	void *ret;
	ret = hook_memalign(boundary, size, __builtin_return_address(0));
	return ret;
}
int __wrap_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *ret;
	ret = hook_memalign(alignment, size, __builtin_return_address(0));
	
	if (!ret) return EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
	else
	{
		*memptr = ret;
		return 0;
	}
}

size_t __mallochooks_malloc_usable_size(void *ptr)
{
	return __real_malloc_usable_size(ptr);
}
