#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>

extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);
extern void __real_free(void *ptr);
extern void *__real_realloc(void *ptr, size_t size);
extern void *__real_memalign(size_t boundary, size_t size) __attribute__((weak));
extern int __real_posix_memalign(void **memptr, size_t alignment, size_t size);

void *(*__underlying_malloc)(size_t size) = &__real_malloc;
void *(*__underlying_calloc)(size_t nmemb, size_t size) = &__real_calloc;
void (*__underlying_free)(void *ptr) = &__real_free;
void *(*__underlying_realloc)(void *ptr, size_t size) = &__real_realloc;
void *(*__underlying_memalign)(size_t boundary, size_t size) = &__real_memalign;
int (*__underlying_posix_memalign)(void **memptr, size_t alignment, size_t size) 
 = &__real_posix_memalign;
