#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>

#include <errno.h>

/* We link in toplevel_init to call our initialize hook. */
extern void __first_initialize_hook(void) __attribute__((weak));

/* These are the hooks that we will call through, if present. */
extern void *__first_malloc_hook(size_t size, const void *caller) __attribute__((weak));
extern void __first_free_hook(void *ptr, const void *caller) __attribute__((weak));
extern void *__first_memalign_hook(size_t alignment, size_t size, const void *caller) __attribute__((weak));
extern void *__first_realloc_hook(void *ptr, size_t size, const void *caller) __attribute__((weak));

/* These are the __real_ functions that the hooks will eventually call. 
 * memalign is weak because it may not be present. */
void *__real_malloc(size_t size);
void __real_free(void *ptr);
void *__real_realloc(void *ptr, size_t size);
void *__real_memalign(size_t boundary, size_t size) __attribute__((weak));
/* These two won't be called by hooks, but our __wrap_ functions do call them
 * in the event of no hooks being compiled in, so we provide them. */
void *__real_calloc(size_t nmemb, size_t size);
int __real_posix_memalign(void **memptr, size_t alignment, size_t size);

/* How do we get to the "real" malloc in the static-linking case?
 * It's probably in a shared library. So we have to do the dlsym() thing anyway.
 * OR it might be in the executable. Either way, dlsym() will find it. */
extern void *(*__underlying_malloc)(size_t size);
extern void *(*__underlying_calloc)(size_t nmemb, size_t size);
extern void (*__underlying_free)(void *ptr);
extern void *(*__underlying_realloc)(void *ptr, size_t size);
extern void *(*__underlying_memalign)(size_t boundary, size_t size);
extern int (*__underlying_posix_memalign)(void **memptr, size_t alignment, size_t size);

/* We want to avoid infinite regress. We need handling analogous to the
 * glibc case. If we have TLS, we use that. */
#ifndef NO_TLS
static __thread _Bool in_hook;
#else
static _Bool in_hook; /* FIXME: use pthread specific object */
#endif

/* This does the work; we provide two different interfaces. */
static void *do_malloc(size_t size, const void *caller);

/* If we're using the preload or wrap methods, we have to convert 
 * the signature of malloc (et al) calls into that expected by the
 * hooks. In particular, the hooks have an extra "caller" argument
 * that we source from the return address. */
void *__wrap_malloc(size_t size)
{
	return do_malloc(size, __builtin_return_address(0));
}

/* This is our internal interface, allowing us to pass a caller through. */
static void *do_malloc(size_t size, const void *caller)
{
	// if we have hooks, call through them
	if (__first_malloc_hook && !in_hook)
	{
		in_hook = 1;
		void *retval = __first_malloc_hook(size, caller);
		in_hook = 0;
		return retval;
	}
	else return __real_malloc(size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
	void *returned = do_malloc(
		nmemb * size, 
		__builtin_return_address(0)
	);
	if (returned) bzero(returned, nmemb * size);
	return returned;
}

void __wrap_free(void *ptr)
{
	if (__first_free_hook && !in_hook)
	{
		in_hook = 1;
		__first_free_hook(ptr, __builtin_return_address(0));
		in_hook = 0;
	}
	else __real_free(ptr);
}

void *__wrap_realloc(void *ptr, size_t size)
{
	if (__first_realloc_hook && !in_hook)
	{
		in_hook = 1;
		void *retval = __first_realloc_hook(ptr, size, __builtin_return_address(0));
		in_hook = 0;
		return retval;
	}
	else return __real_realloc(ptr, size);
}

void *__wrap_memalign(size_t boundary, size_t size)
{
	if (__first_memalign_hook && !in_hook)
	{
		in_hook = 1;
		void *retval = __first_memalign_hook(boundary, size, __builtin_return_address(0));
		in_hook = 0;
		return retval;
	}
	else return __real_memalign(boundary, size);
}

int __wrap_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *tmp_out;

	if (__first_memalign_hook && !in_hook)
	{
		in_hook = 1;
		tmp_out = __first_memalign_hook(alignment, size, __builtin_return_address(0));
		in_hook = 0;
		if (tmp_out) 
		{
			*memptr = tmp_out;
			return 0;
		}
		else return ENOMEM;
	}
	else return __real_posix_memalign(memptr, alignment, size);
}
