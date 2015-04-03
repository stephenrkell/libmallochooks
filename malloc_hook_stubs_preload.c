#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>

#define HIDDEN __attribute__((visibility("hidden")))

/* Prototype the hook_* functions. */
#undef HOOK_PREFIX
#define HOOK_PREFIX(i) i
#include "hook_protos.h"
#undef HOOK_PREFIX
/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_ ## i
#include "hook_protos.h"

static void *early_malloc(size_t size);
static void early_free(void *ptr);
#define EARLY_MALLOC_LIMIT (10*1024*1024)
static char early_malloc_buf[EARLY_MALLOC_LIMIT] __attribute__((aligned(2 * sizeof (size_t)))); /* 10MB should suffice */
static char *early_malloc_pos = &early_malloc_buf[sizeof (size_t)];
#define EARLY_MALLOC_END (&early_malloc_buf[EARLY_MALLOC_LIMIT])

static void *early_malloc(size_t size)
{
	/* Allocate a chunk that is 
	 * (usable size)
	 * data
	 * padding up to one-modulo-two size_t alignment
	 */
	assert((uintptr_t) early_malloc_pos % (2 * sizeof (size_t)) == sizeof (size_t));
	if (early_malloc_pos + size + sizeof (size_t) < EARLY_MALLOC_END)
	{
		char *initial_pos = early_malloc_pos;
		early_malloc_pos += sizeof (size_t);
		void *allocated = early_malloc_pos;
		early_malloc_pos += size;
		while ((uintptr_t) early_malloc_pos % (2 * sizeof (size_t)) != sizeof (size_t))
		{
			++early_malloc_pos;
		}
		size_t usable_size = early_malloc_pos - (char*) allocated;
		*(size_t*)initial_pos = usable_size;
		return allocated;
	}
	else return NULL;
}

static void early_free(void *ptr) {}

static size_t early_malloc_usable_size(void *ptr) 
{
	return *(((size_t*) ptr) - 1);
}

/* These are our pointers to the dlsym-returned RTLD_NEXT malloc and friends. */
static void *(*__underlying_malloc)(size_t size);
static void *(*__underlying_calloc)(size_t nmemb, size_t size);
static void (*__underlying_free)(void *ptr);
static void *(*__underlying_realloc)(void *ptr, size_t size);
static void *(*__underlying_memalign)(size_t boundary, size_t size);
static int (*__underlying_posix_memalign)(void **memptr, size_t alignment, size_t size);
static size_t (*__underlying_malloc_usable_size)(void *userptr);

#ifndef NO_TLS
static __thread _Bool dlsym_active; // NOTE: this is NOT subsumed by in_hook
#else
static _Bool dlsym_active;
#endif

/* All our client to tell us more precisely that we should avoid dlopen
 * and use early_malloc instead.
 * 
 * FIXME: the "right solution" is probably that the loader avoids using
 * the main malloc, and we handle it specially (including instrumenting
 * its calls to malloc, i.e. have liballocs etc. extend the loader directly). */
extern _Bool __avoid_calling_dl_functions __attribute__((weak));

// #ifndef NO_TLS
// static __thread _Bool in_hook;
// #else
// static _Bool in_hook;
// #endif

static _Bool tried_to_initialize;
static _Bool failed_to_initialize;
static void initialize_underlying_malloc()
{
	if (dlsym_active || (&__avoid_calling_dl_functions && __avoid_calling_dl_functions))
	{
		return; /* fail without prejudice -- will try again */
	}
	assert(!(tried_to_initialize && failed_to_initialize));
	if (tried_to_initialize && !failed_to_initialize)
	{
		// we should be okay (shouldn't really have been called though)
		assert(__underlying_malloc && __underlying_free && 
			__underlying_memalign && __underlying_realloc && 
			__underlying_calloc && __underlying_posix_memalign &&
			__underlying_malloc_usable_size);
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
		__underlying_malloc_usable_size = (size_t(*)(void*)) dlsym(RTLD_NEXT, "malloc_usable_size");
		if (!__underlying_malloc_usable_size) fail(malloc_usable_size);
		dlsym_active = 0;
#undef fail
	}
}

/* Now the "real" functions. These will rely on early_malloc early on, 
 * when it's not safe to call dlsym(), then switch to underlying_malloc et al. */
void __terminal_hook_init(void) {}

void * __terminal_hook_malloc(size_t size, const void *caller)
{
	if (!__underlying_malloc) initialize_underlying_malloc();
	if (__underlying_malloc) return __underlying_malloc(size);
	else return early_malloc(size);
}
void __terminal_hook_free(void *ptr, const void *caller)
{
	if ((char*) ptr >= early_malloc_buf && (char*) ptr < EARLY_MALLOC_END)
	{
		early_free(ptr);
	}
	else
	{
		if (!__underlying_free) initialize_underlying_malloc();
		if (__underlying_free) __underlying_free(ptr);
		else
		{
			// do nothing -- we couldn't get a pointer to free
		}
	}
}
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	if (!__underlying_realloc) initialize_underlying_malloc();
	if (__underlying_realloc) return __underlying_realloc(ptr, size);
	else 
	{
		// unconditionally do the reallocation
		void *to_return = early_malloc(size);
		if (to_return)
		{
			memcpy(to_return, ptr, size);
		}
		return to_return;
	}
}
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
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

/* also override malloc_usable_size s.t. we divert queries about the
 * early_malloc buffer into early_malloc_usable_size. */
size_t __mallochooks_malloc_usable_size(void *userptr);
size_t malloc_usable_size(void *userptr) __attribute__((weak,alias("__mallochooks_malloc_usable_size")));
size_t __mallochooks_malloc_usable_size(void *userptr)
{
	size_t ret;

	// this might silently return if we're in the middle of an early dlsym...
	if (!__underlying_malloc_usable_size) initialize_underlying_malloc();
	// ... in which case this test should succeed
	if ((char*) userptr >= early_malloc_buf && (char*) userptr < EARLY_MALLOC_END)
	{
		ret = early_malloc_usable_size(userptr);
	}
	else
	{
		assert(__underlying_malloc_usable_size);
		ret = __underlying_malloc_usable_size(userptr);
	}

	return ret;
}

/* NOTE that we can easily get infinite regress here, so we guard against it 
 * explicitly. We guard against the dlsym case separately, but another case
 * that I've seen in event_hooks/liballocs is as follows:
 * 
 * - alloc succeeds
 * - call post_successful_alloc
 * - initialize index using mmap()
 * - mmap trapped by liballocs
 * - ... calls dlsym
 * - ... calls calloc, succeeds
 * - ... call post_successful_alloc
 * - ... initialize index using mmap()... 
 * 
 * In short, our policy is that allocs made while servicing hooks shouldn't
 * themselves be hooked. This includes calloc()s subservient to dlsym() subservient
 * to the wrapped mmap(). So we call __terminal_hook_* if a hook is already active.
 * Arguably, what should happen is that the mmap itself is not hooked if its callsite
 * is in the hooking code. Actually I've applied that fix to preload.c/heap_index_hooks.c 
 * anyway, by deferring setting safe_to_call_malloc until the heap_index is init'd, 
 * so this should not arise.
 */

/* These are our actual hook stubs. */
void *malloc(size_t size)
{
	void *ret;
	//if (!in_hook)
	//{
	//	in_hook = 1;
		ret = hook_malloc(size, __builtin_return_address(0));
	//	in_hook = 0;
	//} else ret = __terminal_hook_malloc(size, __builtin_return_address(0));
	return ret;
}
void *calloc(size_t nmemb, size_t size)
{
	void *ret;
	//if (!in_hook)
	//{
	//	in_hook = 1;
		ret = hook_malloc(nmemb * size, __builtin_return_address(0));
	//	in_hook = 0;
	//} else ret = __terminal_hook_malloc(nmemb * size, __builtin_return_address(0));
	if (ret) bzero(ret, nmemb * size);
	return ret;
}
void free(void *ptr)
{
	//if (!in_hook)
	//{
	//	in_hook = 1;
		hook_free(ptr, __builtin_return_address(0));
	//	in_hook = 0;
	//} else __terminal_hook_free(ptr, __builtin_return_address(0));
}
void *realloc(void *ptr, size_t size)
{
	void *ret;
	//if (!in_hook)
	//{
	//	in_hook = 1;
		ret = hook_realloc(ptr, size, __builtin_return_address(0));
	//	in_hook = 0;
	//} else ret = __terminal_hook_realloc(ptr, size, __builtin_return_address(0));
	return ret;
}
void *memalign(size_t boundary, size_t size)
{
	void *ret;
	//if (!in_hook)
	//{
	//	in_hook = 1;
		ret = hook_memalign(boundary, size, __builtin_return_address(0));
	//	in_hook = 0;
	//} else ret = __terminal_hook_memalign(boundary, size, __builtin_return_address(0));
	return ret;
}
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *ret;
	//if (!in_hook)
	//{
	//	in_hook = 1;
		ret = hook_memalign(alignment, size, __builtin_return_address(0));
	//	in_hook = 0;
	//} else ret = __terminal_hook_memalign(alignment, size, __builtin_return_address(0));
	
	if (!ret) return EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
	else
	{
		*memptr = ret;
		return 0;
	}
}
