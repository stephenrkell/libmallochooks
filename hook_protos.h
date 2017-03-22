#include <stdlib.h>

/* Prototypes for what we define. */
#ifndef HOOK_PREFIX
#define HOOK_PREFIX(i) hook_ ## i
#endif

#ifndef HOOK_ATTRIBUTES
#define HOOK_ATTRIBUTES __attribute__((visibility("hidden")))
#endif

void HOOK_PREFIX(init)(void) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(malloc)(size_t size, const void *caller) HOOK_ATTRIBUTES;
//void *HOOK_PREFIX(calloc)(size_t nmemb, size_t size, const void *caller);
void HOOK_PREFIX(free)(void *ptr, const void *caller) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(realloc)(void *ptr, size_t size, const void *caller) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(memalign)(size_t alignment, size_t size, const void *caller) HOOK_ATTRIBUTES;
//int HOOK_PREFIX(posix_memalign)(void **out, size_t alignment, size_t size, const void *caller);

#undef HOOK_PREFIX


