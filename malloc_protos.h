/* We support a common prefix for the malloc-family functions. */
#ifndef MALLOC_PREFIX
#define MALLOC_PREFIX(p,i) p ## i

/* Don't bother to prototype malloc -- we might conflict with the
 * libc definitions using funky attributes. */

#else

#include <stddef.h>

/* Declare the prefixed functions. */
#define DECLARE_MALLOC(extra_prefix) \
void *MALLOC_PREFIX( , malloc)(size_t size); \
void *MALLOC_PREFIX( , calloc)(size_t nmemb, size_t size); \
void MALLOC_PREFIX( , free)(void *ptr); \
void *MALLOC_PREFIX( , realloc)(void *ptr, size_t size); \
void *MALLOC_PREFIX( , memalign)(size_t boundary, size_t size); \
int MALLOC_PREFIX( , posix_memalign)(void **memptr, size_t alignment, size_t size); \
size_t MALLOC_PREFIX( , malloc_usable_size)(void *ptr);

DECLARE_MALLOC( )

#endif
