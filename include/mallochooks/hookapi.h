#ifndef MALLOCHOOKS_HOOKAPI_
#define MALLOCHOOKS_HOOKAPI_

#include <stdlib.h>

/* Prototypes for what we define. */
#ifndef HOOK_PREFIX
#define HOOK_PREFIX(i) hook_ ## i
#endif

#ifndef HOOK_ATTRIBUTES
#define HOOK_ATTRIBUTES __attribute__((visibility("hidden")))
#endif

/* The hook API is like the malloc API except
 * - no calloc() -- it is emulated using malloc
 * - no posix_memalign() -- it is emulated using memalign
 * - extra 'caller' arguments at the end
 * - extra init() function.
 */

void HOOK_PREFIX(init)(void) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(malloc)(size_t size, const void *caller) HOOK_ATTRIBUTES;
void HOOK_PREFIX(free)(void *ptr, const void *caller) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(realloc)(void *ptr, size_t size, const void *caller) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(memalign)(size_t alignment, size_t size, const void *caller) HOOK_ATTRIBUTES;

#endif
