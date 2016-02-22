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

/* These are our pointers to the allocator we use if we detect a 
 * reentrant call or a self-call. FIXME: reentrant calls should really
 * be an error. There's no way to guarantee that a reentrant malloc
 * isn't paired with a non-reentrant free, or vice-versa. With
 * early_malloc we used to get around this because we could dynamically
 * identify its chunks. We might need to do something similar here. */
void *__private_malloc(size_t size) __attribute__((visibility("protected")));
void *__private_calloc(size_t nmemb, size_t size) __attribute__((visibility("protected")));
void __private_free(void *ptr) __attribute__((visibility("protected")));
void *__private_realloc(void *ptr, size_t size) __attribute__((visibility("protected")));
void *__private_memalign(size_t boundary, size_t size) __attribute__((visibility("protected")));
int __private_posix_memalign(void **memptr, size_t alignment, size_t size) __attribute__((visibility("protected")));
size_t __private_malloc_usable_size(void *userptr) __attribute__((visibility("protected")));

/* These are our pointers to the dlsym-returned RTLD_NEXT malloc and friends. */
static void *(*__underlying_malloc)(size_t size);
static void *(*__underlying_calloc)(size_t nmemb, size_t size);
static void (*__underlying_free)(void *ptr);
static void *(*__underlying_realloc)(void *ptr, size_t size);
static void *(*__underlying_memalign)(size_t boundary, size_t size);
static int (*__underlying_posix_memalign)(void **memptr, size_t alignment, size_t size);
static size_t (*__underlying_malloc_usable_size)(void *userptr);

static _Bool tried_to_initialize;
static _Bool failed_to_initialize;
static void initialize_underlying_malloc()
{
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
#undef fail
	}
}

/* Now the "real" functions. These will rely on private_malloc early on, 
 * when it's not safe to call dlsym(), then switch to underlying_malloc et al. */
void __terminal_hook_init(void) {}

void * __terminal_hook_malloc(size_t size, const void *caller)
{
	if (!__underlying_malloc) initialize_underlying_malloc();
	if (__underlying_malloc) return __underlying_malloc(size);
	else return __private_malloc(size);
}
void __terminal_hook_free(void *ptr, const void *caller)
{
	if (!__underlying_free) initialize_underlying_malloc();
	if (__underlying_free) __underlying_free(ptr);
}
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	if (!__underlying_realloc) initialize_underlying_malloc();
	if (__underlying_realloc) return __underlying_realloc(ptr, size);
	else return NULL;
}
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	if (!__underlying_memalign) initialize_underlying_malloc();
	assert(__underlying_memalign);
	return __underlying_memalign(boundary, size);
}

/* FIXME: also override malloc_usable_size s.t. we divert queries about the
 * private buffer into early_malloc_usable_size. */
size_t __mallochooks_malloc_usable_size(void *userptr);
size_t malloc_usable_size(void *userptr) __attribute__((weak,alias("__mallochooks_malloc_usable_size")));
size_t __mallochooks_malloc_usable_size(void *userptr)
{
	size_t ret;

	// this might silently return if we're in the middle of an early dlsym...
	if (!__underlying_malloc_usable_size) initialize_underlying_malloc();
	// ... in which case this test should succeed
	assert(__underlying_malloc_usable_size);
	ret = __underlying_malloc_usable_size(userptr);

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

/* Stolen from relf.h, but pasted here to stay self-contained. */
extern struct r_debug _r_debug;
extern int _etext; /* NOTE: to resolve to *this object*'s _etext, we *must* be linked -Bsymbolic. */
static inline
struct link_map*
get_highest_loaded_object_below(void *ptr)
{
	/* Walk all the loaded objects' load addresses. 
	 * The load address we want is the next-lower one. */
	struct link_map *highest_seen = NULL;
	for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
	{
		if (!highest_seen || 
				((char*) l->l_addr > (char*) highest_seen->l_addr
					&& (char*) l->l_addr <= (char*) ptr))
		{
			highest_seen = l;
		}
	}
	return highest_seen;
}

static 
_Bool
is_self_call(const void *caller)
{
	static char *our_load_addr;
	if (!our_load_addr) our_load_addr = (char*) get_highest_loaded_object_below(&is_self_call)->l_addr;
	if (!our_load_addr) abort(); /* we're supposed to be preloaded, not executable */
	static char *text_segment_end;
	if (!text_segment_end) text_segment_end = our_load_addr + (unsigned long) &_etext; /* HACK: ABS symbol, so not relocated. */
	return ((char*) caller >= our_load_addr && (char*) caller < text_segment_end);
}

/* These are our actual hook stubs. */
void *malloc(size_t size)
{
	static __thread _Bool malloc_active;
	_Bool is_reentrant_call = malloc_active;
	if (!is_reentrant_call) malloc_active = 1;
	void *ret;
	if (!is_reentrant_call && !is_self_call(__builtin_return_address(0)))
	{
		ret = hook_malloc(size, __builtin_return_address(0));
	} else ret = __private_malloc(size);
	if (!is_reentrant_call) malloc_active = 0;
	return ret;
}
void *calloc(size_t nmemb, size_t size)
{
	static __thread _Bool calloc_active;
	_Bool is_reentrant_call = calloc_active;
	if (!is_reentrant_call) calloc_active = 1;
	void *ret;
	if (!is_reentrant_call && !is_self_call(__builtin_return_address(0)))
	{
		ret = hook_malloc(nmemb * size, __builtin_return_address(0));
	} else ret = __private_calloc(nmemb, size);
	if (ret) bzero(ret, nmemb * size);
	if (!is_reentrant_call) calloc_active = 0;
	return ret;
}
void free(void *ptr)
{
	static __thread _Bool free_active;
	_Bool is_reentrant_call = free_active;
	if (!is_reentrant_call) free_active = 1;
	if (!is_reentrant_call && !is_self_call(__builtin_return_address(0)))
	{
		hook_free(ptr, __builtin_return_address(0));
	} else __private_free(ptr);
	if (!is_reentrant_call) free_active = 0;
}
void *realloc(void *ptr, size_t size)
{
	static __thread _Bool realloc_active;
	_Bool is_reentrant_call = realloc_active;
	void *ret;
	if (!is_reentrant_call && !is_self_call(__builtin_return_address(0)))
	{
		ret = hook_realloc(ptr, size, __builtin_return_address(0));
	} else ret = __private_realloc(ptr, size);
	if (!is_reentrant_call) realloc_active = 0;
	return ret;
}
void *memalign(size_t boundary, size_t size)
{
	static __thread _Bool memalign_active;
	_Bool is_reentrant_call = memalign_active;
	void *ret;
	if (!is_reentrant_call && !is_self_call(__builtin_return_address(0)))
	{
		ret = hook_memalign(boundary, size, __builtin_return_address(0));
	} else ret = __private_memalign(boundary, size);
	if (!is_reentrant_call) memalign_active = 0;
	return ret;
}
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	static __thread _Bool posix_memalign_active;
	_Bool is_reentrant_call = posix_memalign_active;
	void *retptr;
	int retval;
	if (!is_reentrant_call && !is_self_call(__builtin_return_address(0)))
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
	if (!is_reentrant_call) posix_memalign_active = 0;
	return retval;
}
