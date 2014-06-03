// #include <strings.h> // for bzero
#include <errno.h> // for EINVAL

#undef HOOK_PREFIX
#include "hook_protos.h"

#define HOOK_PREFIX(i) __next_ ## i
#include "hook_protos.h"
#undef HOOK_PREFIX

/* Avoid an implicit declaration of this helper. */
size_t malloc_usable_size(void *);

#ifndef ALLOCPTR_TO_USERPTR
#define ALLOCPTR_TO_USERPTR(a) (a)
#endif

#ifndef USERPTR_TO_ALLOCPTR
#define USERPTR_TO_ALLOCPTR(u) (u)
#endif

void
hook_init(void)
{
	// chain here
	post_init();
	__next_hook_init();
}

void *
hook_malloc(size_t size, const void *caller)
{
	void *result = __next_hook_malloc(size, caller);
	return ALLOCPTR_TO_USERPTR(result);
}

// void *
// hook_calloc(size_t nmemb, size_t size, const void *caller)
// {
// 	void *result = hook_malloc(size * nmemb, caller);
// 	bzero(result, size * nmemb);
// 	return ALLOCPTR_TO_USERPTR(result);
// }

void
hook_free(void *userptr, const void *caller)
{
	__next_hook_free(USERPTR_TO_ALLOCPTR(userptr), caller);
}

void *
hook_memalign(size_t alignment, size_t size, const void *caller)
{
	void *result = __next_hook_memalign(alignment, size, caller);
	return ALLOCPTR_TO_USERPTR(result);
}
// 
// int
// hook_posix_memalign(void **memptr, size_t alignment, size_t size, const void *caller)
// {
// 	void *ret = hook_memalign(alignment, size, caller);
// 	if (!ret) return EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
// 	else
// 	{
// 		*memptr = ret;
// 		return 0;
// 	}
// }

void *
hook_realloc(void *userptr, size_t size, const void *caller)
{
	void *result_allocptr = __next_hook_realloc(USERPTR_TO_ALLOCPTR(userptr), size, caller);
	return ALLOCPTR_TO_USERPTR(result_allocptr);
}
