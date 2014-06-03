#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>

#include <errno.h>

/* Prototype the hook_* functions. */
#undef HOOK_PREFIX
#include "hook_protos.h"
/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_ ## i
#include "hook_protos.h"

extern void *early_malloc(size_t size);
extern void early_free(void *ptr);
#define EARLY_MALLOC_LIMIT (10*1024*1024)
char early_malloc_buf[EARLY_MALLOC_LIMIT]; /* 10MB should suffice */
char *early_malloc_pos;
#define EARLY_MALLOC_END (&early_malloc_buf[EARLY_MALLOC_LIMIT])

void *early_malloc(size_t size)
{
	if (early_malloc_pos + size < EARLY_MALLOC_END)
	{
		void *allocated = early_malloc_pos;
		early_malloc_pos += size;
		return allocated;
	}
	else return NULL;
}

void early_free(void *ptr) {}

/* These are our pointers to the dlsym-returned RTLD_NEXT malloc and friends. */
void *(*__underlying_malloc)(size_t size);
void *(*__underlying_calloc)(size_t nmemb, size_t size);
void (*__underlying_free)(void *ptr);
void *(*__underlying_realloc)(void *ptr, size_t size);
void *(*__underlying_memalign)(size_t boundary, size_t size);
int (*__underlying_posix_memalign)(void **memptr, size_t alignment, size_t size);

#ifndef NO_TLS
static __thread _Bool dlsym_active; // NOTE: this is NOT subsumed by in_hook
#else
static _Bool dlsym_active;
#endif
static _Bool tried_to_initialize;
static _Bool failed_to_initialize;
static void initialize_underlying_malloc()
{
	if (dlsym_active) return;
	assert(!(tried_to_initialize && failed_to_initialize));
	if (tried_to_initialize && !failed_to_initialize)
	{
		// we should be okay (shouldn't really have been called though)
		assert(__underlying_malloc && __underlying_free && 
			__underlying_memalign && __underlying_realloc && 
			__underlying_calloc && __underlying_posix_memalign);
		return;
	}
	else
	{
#define fail(symname) do { \
fprintf(stderr, "dlsym(" #symname ") error: %s\n", dlerror()); \
failed_to_initialize = 1; \
 } while(0)
		tried_to_initialize = 1;
		dlsym_active = 1;
		dlerror();
		__underlying_malloc = (void*(*)(size_t)) dlsym(RTLD_NEXT, "malloc");
		if (!__underlying_malloc) fail(malloc);
		__underlying_free = (void(*)(void*)) dlsym(RTLD_NEXT, "free");
		if (!__underlying_free) fail(free);
		__underlying_memalign = (void*(*)(size_t, size_t)) dlsym(RTLD_NEXT, "memalign");
		/* Don't fail for memalign -- it's optional. */
		__underlying_realloc = (void*(*)(void*, size_t)) dlsym(RTLD_NEXT, "realloc");
		if (!__underlying_realloc) fail(realloc);
		__underlying_calloc = (void*(*)(size_t, size_t)) dlsym(RTLD_NEXT, "calloc");
		if (!__underlying_calloc) fail(calloc);
		__underlying_posix_memalign = (int(*)(void**, size_t, size_t)) dlsym(RTLD_NEXT, "posix_memalign");
		if (!__underlying_posix_memalign) fail(posix_memalign);
		dlsym_active = 0;
#undef fail
	}
}

/* Now the "real" functions. These will rely on early_malloc early on, 
 * when it's not safe to call dlsym(), then switch to underlying_malloc et al. */
void *__terminal_hook_malloc(size_t size, const void *caller)
{
	if (!__underlying_malloc) initialize_underlying_malloc();
	if (__underlying_malloc) return __underlying_malloc(size);
	else return early_malloc(size);
}
void __terminal_hook_free(void *ptr, const void *caller)
{
	if (!__underlying_free) initialize_underlying_malloc();
	if (__underlying_free) __underlying_free(ptr);
	else early_free(ptr);
}
void *__terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	if (!__underlying_realloc) initialize_underlying_malloc();
	if (__underlying_realloc) return __underlying_realloc(ptr, size);
	else 
	{
		void *to_return = early_malloc(size);
		if (to_return)
		{
			memcpy(to_return, ptr, size);
		}
		return to_return;
	}
}
void *__terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	if (!__underlying_memalign) initialize_underlying_malloc();
	assert(__underlying_memalign);
	return __underlying_memalign(boundary, size);
}
// void *__terminal_hook_calloc(size_t nmemb, size_t size, const void *caller)
// {
// 	if (!__underlying_calloc) initialize_underlying_malloc();
// 	if (__underlying_calloc) return __underlying_calloc(nmemb, size);
// 	else 
// 	{
// 		void *to_return = early_malloc(nmemb * size);
// 		if (to_return) bzero(to_return, nmemb * size);
// 		return to_return;
// 	}
// 
// }
// int __terminal_hook_posix_memalign(void **memptr, size_t alignment, size_t size, const void *caller)
// {
// 	if (!__underlying_posix_memalign) initialize_underlying_malloc();
// 	assert(__underlying_posix_memalign);
// 	return __underlying_posix_memalign(memptr, alignment, size);
// }

/* These are our actual hook stubs. */
void *malloc(size_t size)
{
	return hook_malloc(size, __builtin_return_address(0));
}
void *calloc(size_t nmemb, size_t size)
{
	void *ret = hook_malloc(nmemb * size, __builtin_return_address(0));
	if (ret) bzero(ret, size);
	return ret;
}
void free(void *ptr)
{
	hook_free(ptr, __builtin_return_address(0));
}
void *realloc(void *ptr, size_t size)
{
	return hook_realloc(ptr, size, __builtin_return_address(0));
}
void *memalign(size_t boundary, size_t size)
{
	return hook_memalign(boundary, size, __builtin_return_address(0));
}
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *ret = hook_memalign(alignment, size, __builtin_return_address(0));
	if (!ret) return EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
	else
	{
		*memptr = ret;
		return 0;
	}
}
