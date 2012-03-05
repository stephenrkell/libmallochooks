#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <malloc.h>

/* Declare the variables that point to the active hooks. This isn't necessary
 * on glibc... adding it here as a precursor to supporting more platforms. */
extern void (*__malloc_initialize_hook)(void);
extern void *(*__malloc_hook)(size_t, const void *);
extern void (*__free_hook)(void*, const void *);
extern void *(*__memalign_hook)(size_t alignment, size_t size, const void *caller);
extern void *(*__realloc_hook)(void *ptr, size_t size, const void *caller);

/* Saved copies of those global variables. */
static void (*underlying_initialize_hook)(void);
static void *(*underlying_malloc_hook)(size_t, const void *);
static void (*underlying_free_hook)(void*, const void *);
static void *(*underlying_memalign_hook)(size_t alignment, size_t size, const void *caller);
static void *(*underlying_realloc_hook)(void *ptr, size_t size, const void *caller);

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

/* Map the glibc hooks onto the generic hooks.
 * Since the glibc hooks are triggered by indirect calls through the globals above,
 * we have to protect in-hook calls from infinite regress. We do this by restoring
 * the saved hooks around all calls to the generic hooks. */

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
