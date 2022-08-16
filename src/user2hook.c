#include "mallochooks/userapi.h"
#include "mallochooks/hookapi.h"

#include <strings.h>  /* for bzero */
#include <errno.h> /* for EINVAL */

#ifndef MALLOC_ATTRIBUTES
#define MALLOC_ATTRIBUTES
#endif

#ifndef MALLOC_CALLER_EXPRESSION
#define MALLOC_CALLER_EXPRESSION __builtin_return_address(0)
#endif

MALLOC_ATTRIBUTES
void *MALLOC_PREFIX(malloc)(size_t size)
{
	void *ret;
	ret = HOOK_PREFIX(malloc)(size, MALLOC_CALLER_EXPRESSION);
	return ret;
}
MALLOC_ATTRIBUTES
void *MALLOC_PREFIX(calloc)(size_t nmemb, size_t size)
{
	void *ret;
	ret = HOOK_PREFIX(malloc)(nmemb * size, MALLOC_CALLER_EXPRESSION);
	if (ret) bzero(ret, nmemb * size);
	return ret;
}
MALLOC_ATTRIBUTES
void MALLOC_PREFIX(free)(void *ptr)
{
	HOOK_PREFIX(free)(ptr, MALLOC_CALLER_EXPRESSION);
}
MALLOC_ATTRIBUTES
void *MALLOC_PREFIX(realloc)(void *ptr, size_t size)
{
	void *ret;
	ret = HOOK_PREFIX(realloc)(ptr, size, MALLOC_CALLER_EXPRESSION);
	return ret;
}
MALLOC_ATTRIBUTES
void *MALLOC_PREFIX(memalign)(size_t boundary, size_t size)
{
	void *ret;
	ret = HOOK_PREFIX(memalign)(boundary, size, MALLOC_CALLER_EXPRESSION);
	return ret;
}
MALLOC_ATTRIBUTES
int MALLOC_PREFIX(posix_memalign)(void **memptr, size_t alignment, size_t size)
{
	void *ret;
	ret = HOOK_PREFIX(memalign)(alignment, size, MALLOC_CALLER_EXPRESSION);
	
	if (!ret) return EINVAL; /* FIXME: check alignment, return ENOMEM/EINVAL as appropriate */
	else
	{
		*memptr = ret;
		return 0;
	}
}
