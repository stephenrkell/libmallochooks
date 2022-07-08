#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>

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

/* This is like the usual wrap hooks, except we use fake_dlsym to 
 * get the __real_ function. It's useful when the __real_ function
 * is itself link-time-wrapped (--wrap __real_malloc)
 * for insertion of another layer of wrappers. In such a situation,
 * a reference to __real_malloc would bind us back to the top-level
 * __wrap_malloc, and a reference to __real___real_malloc would bind
 * to __real_malloc which is an undefined symbol (it's never actually
 * defined). Attempts to --defsym __real_malloc don't work, because
 * they are themselves subject to wrapping: --defsym __real_malloc=malloc
 * will give us __wrap_malloc again.
 *
 * Redux: we can't use --wrap to insert both caller and callee hooks
 * into a single binary in a single link step.
 * 
 * The fact that our terminating case uses libdl is now a source of the
 * usual problems: are we on a callchain from within libdl, e.g. dlsym()
 * doing its calloc()? If so, we should ourselves be sure not to call 
 * dlsym(). Two solutions suggest themselves: using our own dlsym() that never
 * allocates, or ensuring the first call through all these hooks (which
 * is the only one that should need dlsym()) does not itself come from dlsym. */

#define STRINGIFY2( x) #x
#define STRINGIFY(x) STRINGIFY2(x)

#define RELF_DEFINE_STRUCTURES
#include "relf.h"

void __terminal_hook_init(void) {}

void * __terminal_hook_malloc(size_t size, const void *caller)
{
	static void *(*real_malloc)(size_t);
	if (!real_malloc) real_malloc = fake_dlsym(RTLD_DEFAULT, STRINGIFY(MALLOC_PREFIX(__real_, malloc)));
	if (!real_malloc || real_malloc == (void*)-1) real_malloc = fake_dlsym(RTLD_DEFAULT, STRINGIFY(MALLOC_PREFIX( , malloc))); // probably infinite regress...
	if (!real_malloc || real_malloc == (void*)-1) abort();
	return real_malloc(size);
}
void __terminal_hook_free(void *ptr, const void *caller)
{
	static void (*real_free)(void*);
	if (!real_free) real_free = fake_dlsym(RTLD_DEFAULT, STRINGIFY(MALLOC_PREFIX(__real_, free)));
	if (!real_free || real_free == (void*)-1) real_free = fake_dlsym(RTLD_DEFAULT, STRINGIFY(MALLOC_PREFIX( , free))); // probably infinite regress...
	if (!real_free || real_free == (void*)-1) abort();
	real_free(ptr);
}
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	static void *(*real_realloc)(void*, size_t);
	if (!real_realloc) real_realloc = fake_dlsym(RTLD_DEFAULT, STRINGIFY(MALLOC_PREFIX(__real_, realloc)));
	if (!real_realloc || real_realloc == (void*)-1) real_realloc = fake_dlsym(RTLD_DEFAULT, STRINGIFY(MALLOC_PREFIX( , realloc))); // probably infinite regress...
	if (!real_realloc || real_realloc == (void*)-1) abort();
	return real_realloc(ptr, size);
}
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	static void *(*real_memalign)(size_t, size_t);
	if (!real_memalign) real_memalign = fake_dlsym(RTLD_DEFAULT, STRINGIFY(MALLOC_PREFIX(__real_, memalign)));
	if (!real_memalign || real_memalign == (void*)-1) real_memalign = fake_dlsym(RTLD_DEFAULT, STRINGIFY(MALLOC_PREFIX( , memalign))); // probably infinite regress...
	if (!real_memalign || real_memalign == (void*)-1) abort();
	return real_memalign(boundary, size);
}

#include "wrappers.h"
#ifndef WRAPDL_WRAPPER_PREFIX
#define WRAPDL_WRAPPER_PREFIX __wrap_
#endif
DEFINE_WRAPPERS(WRAPDL_WRAPPER_PREFIX, hidden)
