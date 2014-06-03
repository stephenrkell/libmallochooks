/* Replicate the original glibc hooks. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <malloc.h>

#ifndef __MALLOC_HOOK_VOLATILE
#define __MALLOC_HOOK_VOLATILE volatile
#endif

/* Prototype the hook_* functions. */
#undef HOOK_PREFIX
#include "hook_protos.h"
/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_ ## i
#include "hook_protos.h"
#undef HOOK_PREFIX

/* Saved copies of those global variables. */
static void (*__MALLOC_HOOK_VOLATILE underlying_initialize_hook)(void);
static void *(*__MALLOC_HOOK_VOLATILE underlying_malloc_hook)(size_t, const void *);
static void (*__MALLOC_HOOK_VOLATILE underlying_free_hook)(void*, const void *);
static void *(*__MALLOC_HOOK_VOLATILE underlying_memalign_hook)(size_t alignment, size_t size, const void *caller);
static void *(*__MALLOC_HOOK_VOLATILE underlying_realloc_hook)(void *ptr, size_t size, const void *caller);

/* Prototypes for our glue stubs a.k.a. top-level hooks. */
static void glibc_initialize_hook(void);
static void *glibc_malloc_hook(size_t size, const void *caller);
static void glibc_free_hook(void *ptr, const void *caller);
static void *glibc_memalign_hook(size_t alignment, size_t size, const void *caller);
static void *glibc_realloc_hook(void *ptr, size_t size, const void *caller);

/* The event hooks, like all hooks should, call into __next_malloc et al.
 * We define the glue to turn these calls back into actual malloc calls. 
 * It is up to the linker to bind the right __next_* calls to __terminal_*. */
void *__terminal_hook_malloc(size_t size, const void *caller) { return malloc(size); }
void __terminal_hook_free(void *ptr, const void *caller) { free(ptr); }
void *__terminal_hook_memalign(size_t alignment, size_t size, const void *caller) { return memalign(alignment, size); }
void *__terminal_hook_realloc(void *ptr, size_t size, const void *caller) { return realloc(ptr, size); }

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
	hook_init();

	RESTORE_OUR_HOOKS
}

static void *
glibc_malloc_hook (size_t size, const void *caller)
{
	void *result;

	RESTORE_UNDERLYING_HOOKS

	result = hook_malloc(size, caller);

	UPDATE_UNDERLYING_HOOKS
	RESTORE_OUR_HOOKS
	
	return result;
}

static void
glibc_free_hook(void *ptr, const void *caller)
{
	RESTORE_UNDERLYING_HOOKS
	
	hook_free(ptr, caller);
	
	UPDATE_UNDERLYING_HOOKS
	RESTORE_OUR_HOOKS
}

static void *
glibc_memalign_hook(size_t alignment, size_t size, const void *caller)
{
	void *result;

	RESTORE_UNDERLYING_HOOKS

	result = hook_memalign(alignment, size, caller);

	UPDATE_UNDERLYING_HOOKS
	RESTORE_OUR_HOOKS

	return result;
}

static void *
glibc_realloc_hook(void *ptr, size_t size, const void *caller)
{
	void *result;

	RESTORE_UNDERLYING_HOOKS

	result = hook_realloc(ptr, size, caller);

	UPDATE_UNDERLYING_HOOKS
	RESTORE_OUR_HOOKS

	return result;
}

/* We are the toplevel hook. */
void (*__MALLOC_HOOK_VOLATILE __malloc_initialize_hook)(void) = glibc_initialize_hook;
