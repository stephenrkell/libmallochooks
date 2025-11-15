/* No #include guard because we're designed to be safely included >1 time */

/* We support a common prefix for the malloc-family functions. */
#if !defined(MALLOC_PREFIX) && !defined(MALLOC_LINKAGE)
/* Use the libc decls, which will get the attributes like 'nonnull' right. */
#include <stdlib.h>
#else
	/* We have a malloc prefix or malloc linkage, and we need to use them, so
	 * we cannot make do with libc's standard prototypes. */
	#include <stddef.h> /* for size_t */
	#ifndef MALLOC_LINKAGE
		#define MALLOC_LINKAGE
	#endif
	#if !defined(MALLOC_PREFIX)
		#define MALLOC_PREFIX(ident) ident
	#endif
	/* FIXME: add in the attributes like 'nonnull', 'malloc' etc,
	 * appropriately guarded. */
	MALLOC_LINKAGE void *MALLOC_PREFIX(malloc)(size_t size);
	MALLOC_LINKAGE void *MALLOC_PREFIX(calloc)(size_t nmemb, size_t size);
	MALLOC_LINKAGE void MALLOC_PREFIX(free)(void *ptr);
	MALLOC_LINKAGE void *MALLOC_PREFIX(realloc)(void *ptr, size_t size);
	MALLOC_LINKAGE void *MALLOC_PREFIX(memalign)(size_t boundary, size_t size);
	MALLOC_LINKAGE int MALLOC_PREFIX(posix_memalign)(void **memptr, size_t alignment, size_t size);
	MALLOC_LINKAGE size_t MALLOC_PREFIX(malloc_usable_size)(void *ptr);
#endif
