#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>

#include <errno.h>

extern void *early_malloc(size_t size);
extern void early_free(void *ptr);

/* IMPORTANT:
 * calls to malloc et al in the hooks should go to underlying
 * We should link the executable and the hooks with --wrap malloc,
 * BUT we should not link this file with __wrap_malloc! HMM.
 * Suppose that we have to; can we make it work? 
 * We want to make sure that references to "malloc" in shared libraries
 * come here, not to any malloc defined in a different shared library
 * or in the executable proper. */

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
void *(*__underlying_malloc)(size_t size);
void *(*__underlying_calloc)(size_t nmemb, size_t size);
void (*__underlying_free)(void *ptr);
void *(*__underlying_realloc)(void *ptr, size_t size);
void *(*__underlying_memalign)(size_t boundary, size_t size);
int (*__underlying_posix_memalign)(void **memptr, size_t alignment, size_t size);

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

#ifndef NO_TLS
static __thread _Bool dlsym_active; // NOTE: this is NOT subsumed by in_hook
#else
static _Bool dlsym_active;
#endif

/* All our client to tell us more precisely that we should avoid dlopen
 * and use early_malloc instead.
 * 
 * FIXME: the "right solution" is probably that the loader avoids using
 * the main malloc, and we handle it specially (including instrumenting
 * its calls to malloc, i.e. have liballocs etc. extend the loader directly). */
extern _Bool __avoid_calling_dl_functions __attribute__((weak));

static _Bool tried_to_initialize;
static _Bool failed_to_initialize;
static void initialize_underlying_malloc()
{
	if (dlsym_active || (&__avoid_calling_dl_functions && __avoid_calling_dl_functions))
	{
		return; // fail without prejudice -- will try again
	}
	assert(!(tried_to_initialize && failed_to_initialize));
	if (tried_to_initialize && !failed_to_initialize)
	{
		// we should be okay (shouldn't really have been called though)
		assert(__underlying_malloc && __underlying_free && 
			__underlying_memalign && __underlying_realloc && 
			__underlying_calloc && __underlying_posix_memalign);
		return;
	}
	else
	{
#define fail(symname) do { \
fprintf(stderr, "dlsym(" #symname ") error: %s\n", dlerror()); \
failed_to_initialize = 1; \
 } while(0)
		tried_to_initialize = 1;
		dlsym_active = 1;
		dlerror();
		__underlying_malloc = (void*(*)(size_t)) dlsym(RTLD_NEXT, "malloc");
		if (!__underlying_malloc) fail(malloc);
		__underlying_free = (void(*)(void*)) dlsym(RTLD_NEXT, "free");
		if (!__underlying_free) fail(free);
		__underlying_memalign = (void*(*)(size_t, size_t)) dlsym(RTLD_NEXT, "memalign");
		/* Don't fail for memalign -- it's optional. */
		__underlying_realloc = (void*(*)(void*, size_t)) dlsym(RTLD_NEXT, "realloc");
		if (!__underlying_realloc) fail(realloc);
		__underlying_calloc = (void*(*)(size_t, size_t)) dlsym(RTLD_NEXT, "calloc");
		if (!__underlying_calloc) fail(calloc);
		__underlying_posix_memalign = (int(*)(void**, size_t, size_t)) dlsym(RTLD_NEXT, "posix_memalign");
		if (!__underlying_posix_memalign) fail(posix_memalign);
		dlsym_active = 0;
#undef fail
	}
}

/* Now the "real" functions. These will rely on early_malloc early on, 
 * but will switch to using underlying_malloc et al. */
void *__real_malloc(size_t size)
{
	if (!__underlying_malloc) initialize_underlying_malloc();
	if (__underlying_malloc) return __underlying_malloc(size);
	else return early_malloc(size);
}
void __real_free(void *ptr)
{
	if (!__underlying_free) initialize_underlying_malloc();
	if (__underlying_free) __underlying_free(ptr);
	else early_free(ptr);
}
void *__real_realloc(void *ptr, size_t size)
{
	if (!__underlying_realloc) initialize_underlying_malloc();
	if (__underlying_realloc) return __underlying_realloc(ptr, size);
	else 
	{
		void *to_return = early_malloc(size);
		if (to_return)
		{
			memcpy(to_return, ptr, size);
		}
		return to_return;
	}
}
void *__real_memalign(size_t boundary, size_t size)
{
	if (!__underlying_memalign) initialize_underlying_malloc();
	assert(__underlying_memalign);
	return __underlying_memalign(boundary, size);
}
void *__real_calloc(size_t nmemb, size_t size)
{
	if (!__underlying_calloc) initialize_underlying_malloc();
	if (__underlying_calloc) return __underlying_calloc(nmemb, size);
	else 
	{
		void *to_return = early_malloc(nmemb * size);
		if (to_return) bzero(to_return, nmemb * size);
		return to_return;
	}

}
int __real_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	if (!__underlying_posix_memalign) initialize_underlying_malloc();
	assert(__underlying_posix_memalign);
	return __underlying_posix_memalign(memptr, alignment, size);

}
