#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>

#include <errno.h>

extern void *early_malloc(size_t size);
extern void early_free(void *ptr);

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
 * but will switch to using underlying_malloc et al. */
void *__real_malloc(size_t size)
{
	if (!__underlying_malloc) initialize_underlying_malloc();
	if (__underlying_malloc) return __underlying_malloc(size);
	else return early_malloc(size);
}
void __real_free(void *ptr)
{
	if (!__underlying_free) initialize_underlying_malloc();
	if (__underlying_free) __underlying_free(ptr);
	else early_free(ptr);
}
void *__real_realloc(void *ptr, size_t size)
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
void *__real_memalign(size_t boundary, size_t size)
{
	if (!__underlying_memalign) initialize_underlying_malloc();
	assert(__underlying_memalign);
	return __underlying_memalign(boundary, size);
}
void *__real_calloc(size_t nmemb, size_t size)
{
	if (!__underlying_calloc) initialize_underlying_malloc();
	if (__underlying_calloc) return __underlying_calloc(nmemb, size);
	else 
	{
		void *to_return = early_malloc(nmemb * size);
		if (to_return) bzero(to_return, nmemb * size);
		return to_return;
	}

}
int __real_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	if (!__underlying_posix_memalign) initialize_underlying_malloc();
	assert(__underlying_posix_memalign);
	return __underlying_posix_memalign(memptr, alignment, size);

}
