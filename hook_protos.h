#include <stdlib.h>

/* Prototypes for what we define. */
#ifndef HOOK_PREFIX
#define HOOK_PREFIX(i) i
#endif

#ifndef HOOK_ATTRIBUTES
#define HOOK_ATTRIBUTES __attribute__((visibility("hidden")))
#endif

void HOOK_PREFIX(hook_init)(void) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(hook_malloc)(size_t size, const void *caller) HOOK_ATTRIBUTES;
//void *HOOK_PREFIX(hook_calloc)(size_t nmemb, size_t size, const void *caller);
void HOOK_PREFIX(hook_free)(void *ptr, const void *caller) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(hook_realloc)(void *ptr, size_t size, const void *caller) HOOK_ATTRIBUTES;
void *HOOK_PREFIX(hook_memalign)(size_t alignment, size_t size, const void *caller) HOOK_ATTRIBUTES;
//int HOOK_PREFIX(hook_posix_memalign)(void **out, size_t alignment, size_t size, const void *caller);

#undef HOOK_PREFIX


