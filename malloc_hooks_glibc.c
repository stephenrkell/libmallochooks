/* Replicate the original glibc hooks. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <malloc.h>
#include <pthread.h> // HMM: want to make this a weak dependency

#ifndef __MALLOC_HOOK_VOLATILE
#define __MALLOC_HOOK_VOLATILE volatile
#endif

#include "hook_protos.h"

/* Declare the variables that point to the active hooks. This isn't necessary
 * on glibc... adding it here as a precursor to supporting more platforms. */
extern void (*__MALLOC_HOOK_VOLATILE __malloc_initialize_hook)(void);
extern void *(*__MALLOC_HOOK_VOLATILE __malloc_hook)(size_t, const void *);
extern void (*__MALLOC_HOOK_VOLATILE __free_hook)(void*, const void *);
extern void *(*__MALLOC_HOOK_VOLATILE __memalign_hook)(size_t alignment, size_t size, const void *caller);
extern void *(*__MALLOC_HOOK_VOLATILE __realloc_hook)(void *ptr, size_t size, const void *caller);

/* Saved copies of those global variables. */
static void (*__MALLOC_HOOK_VOLATILE underlying_initialize_hook)(void);
static void *(*__MALLOC_HOOK_VOLATILE underlying_malloc_hook)(size_t, const void *);
static void (*__MALLOC_HOOK_VOLATILE underlying_free_hook)(void*, const void *);
static void *(*__MALLOC_HOOK_VOLATILE underlying_memalign_hook)(size_t alignment, size_t size, const void *caller);
static void *(*__MALLOC_HOOK_VOLATILE underlying_realloc_hook)(void *ptr, size_t size, const void *caller);

/* Prototypes for the library-level hooks. */
static void glibc_initialize_hook(void);
static void *glibc_malloc_hook(size_t size, const void *caller);
static void glibc_free_hook(void *ptr, const void *caller);
static void *glibc_memalign_hook(size_t alignment, size_t size, const void *caller);
static void *glibc_realloc_hook(void *ptr, size_t size, const void *caller);

/* Prototypes for the library-level hooks. */
static void generic_initialize_hook(void);
static void *generic_malloc_hook(size_t size, const void *caller);
static void generic_free_hook(void *ptr, const void *caller);
static void *generic_memalign_hook(size_t alignment, size_t size, const void *caller);
static void *generic_realloc_hook(void *ptr, size_t size, const void *caller);

/* The generic hooks call into __real_malloc et al. In the glibc case, 
 * since we never mess with symbol resolution, we just define these to be
 * aliases of malloc et al. */
static void *__real_malloc(size_t size) __attribute__ ((weakref ("malloc")));
static void __real_free(void *ptr) __attribute__ ((weakref ("free")));
static void *__real_memalign(size_t alignment, size_t size) __attribute__ ((weakref ("memalign")));
static void *__real_realloc(void *ptr, size_t size) __attribute__ ((weakref ("realloc")));

/* Map the glibc hooks onto the generic hooks.
 * Since the glibc hooks are triggered by indirect calls through the globals above,
 * we have to protect in-hook calls from infinite regress. We do this by restoring
 * the saved hooks around all calls to the generic hooks. 
 * 
 * Note that this is inescapably thread-unsafe, because glibc's malloc will look
 * at the hook variables without any locking. So it will see the intermediate
 * state where one hook is substituted for the inner hook for the duration of the
 * hooked call in thread A, and will start a *non-hooked* call in thread B
 * because that's what the global variable is currently telling it to do. 
 * This is bad. Issue a warning. */

#warning "Using glibc malloc hooks. The generated code is not thread safe."

#define UPDATE_UNDERLYING_HOOKS \
	underlying_malloc_hook = __malloc_hook; \
	underlying_free_hook = __free_hook; \
	underlying_memalign_hook = __memalign_hook; \
	underlying_realloc_hook = __realloc_hook;
#define RESTORE_UNDERLYING_HOOKS \
	__malloc_hook = underlying_malloc_hook; \
	__free_hook = underlying_free_hook; \
	__memalign_hook = underlying_memalign_hook; \
	__realloc_hook = underlying_realloc_hook;
#define RESTORE_OUR_HOOKS \
	__malloc_hook = glibc_malloc_hook; \
	__free_hook = glibc_free_hook; \
	__memalign_hook = glibc_memalign_hook; \
	__realloc_hook = glibc_realloc_hook;

static void
glibc_initialize_hook(void)
{
	UPDATE_UNDERLYING_HOOKS /* actually, save them for the first time */
	
	// we call our initialize hooks with the underlying hooks active
	generic_initialize_hook();

	RESTORE_OUR_HOOKS
}

static void *
glibc_malloc_hook (size_t size, const void *caller)
{
	void *result;

	RESTORE_UNDERLYING_HOOKS

	result = generic_malloc_hook(size, caller);

	UPDATE_UNDERLYING_HOOKS
	RESTORE_OUR_HOOKS
	
	return result;
}

static void
glibc_free_hook(void *ptr, const void *caller)
{
	RESTORE_UNDERLYING_HOOKS
	
	generic_free_hook(ptr, caller);
	
	UPDATE_UNDERLYING_HOOKS
	RESTORE_OUR_HOOKS
}

static void *
glibc_memalign_hook(size_t alignment, size_t size, const void *caller)
{
	void *result;

	RESTORE_UNDERLYING_HOOKS

	result = generic_memalign_hook(alignment, size, caller);

	UPDATE_UNDERLYING_HOOKS
	RESTORE_OUR_HOOKS

	return result;
}

static void *
glibc_realloc_hook(void *ptr, size_t size, const void *caller)
{
	void *result;

	RESTORE_UNDERLYING_HOOKS

	result = generic_realloc_hook(ptr, size, caller);

	UPDATE_UNDERLYING_HOOKS
	RESTORE_OUR_HOOKS

	return result;
}

/* We are the toplevel hook. */
void (*__MALLOC_HOOK_VOLATILE __malloc_initialize_hook)(void) = glibc_initialize_hook;

/* We changed the name of init_hook. */
static void init_hook(void); 
static void initialize_hook(void) { init_hook(); }

/* Now include our generic hooks. */
#include "generic.inc.c"
