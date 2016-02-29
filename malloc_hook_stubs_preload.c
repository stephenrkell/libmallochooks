#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <link.h>

#include <errno.h>

#define HIDDEN __attribute__((visibility("hidden")))

/* Prototype the hook_* functions. */
#undef HOOK_PREFIX
#define HOOK_PREFIX(i) i
#include "hook_protos.h"
#undef HOOK_PREFIX
/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_ ## i
#include "hook_protos.h"

/* NOTE that we can easily get infinite regress, so we guard against it 
 * explicitly. We use a private malloc if we detect a reentrant call or
 * a self-call (i.e. a call from the hooking object).
 * 
 * FIXME: reentrant calls should really be an error. There's no way to 
 * guarantee that a reentrant malloc isn't paired with a non-reentrant
 * free, or vice-versa. With early_malloc we used to get around this 
 * because we could dynamically identify early_malloc's chunks.
 * 
 * ... One option is to do something similar here. With help from 
 * liballocs, it's possible to detect the mmaps done by the private 
 * malloc and track them that way. 
 * 
 * ... But that's too much complexity for these hooks. Another option:
 * since our main source of reentrant calls is calls from libdl/ld.so,
 * we could detect when the caller is in libdl, and always handle that
 * with the private dlmalloc. However, it's not clear how to reliably
 * detect these calls, again except with liballocs's help.
 * 
 * The option I'm inclined to go with is "none of the above". We simply
 * forbid reentrant calls. In liballocs we can avoid them by never using
 * libdl functions in any code that might be called from a malloc handler.
 *
 * BUT WAIT. That's not enough, for two reasons. One, we need libdl for
 * phdr access. So, at least some libdl calls in our own init code are
 * unavoidable. Two, lazy binding: in effect, *any* interposable call in 
 * our own .so can call into ld.so, which can malloc, which can call our 
 * code, which can call back into ld.so (for the same reason), which can
 * malloc. So we can't prevent reentrant mallocs coming from ld.so: they're
 * happening during the course of lazy binding during our own malloc handling.
 * That's okay, except that the later free(), also coming from libdl, need
 * *not* be reentrant. So it'll get mapped to the wrong allocator. To solve
 * this, all mallocs and frees coming from ld.so must use the private malloc.
 * (In case you're wondering: GNU/glibc ld.so use malloc for errstring.)
 * 
 * AND WAIT again. Even the above isn't enough, because of callchains like
 * the following.
 * #15 0x00002aaaaad4d631 in hook_malloc (size=size@entry=100, ..
 * #16 0x00002aaaaad62414 in malloc (size=size@entry=100)
 * #17 0x00002aaaab7f5062 in _IO_vasprintf (result_ptr=0x7fff56838cf0, ...            <-- in libc.so!
 * #18 0x00002aaaab7d6907 in ___asprintf (string_ptr=string_ptr@entry=0x7fff56838cf0, <-- in libdl
 * #19 0x00002aaaab57f54d in __dlerror () at dlerror.c:99
 * #20 0x00002aaaaad5363a in (callback)
 * #21 0x00002aaaab8b8aac in __GI___dl_iterate_phdr (...
 * (user code)
 * 
 * ... i.e. where libdl calls into us *via* libc. So we need to use a global
 * flag that says "avoid libdl calls" and let the client code figure it out.
 * In liballocs's case it will set the flag in the preload wrappers.
 */
void *__private_malloc(size_t size) __attribute__((visibility("protected")));
void *__private_calloc(size_t nmemb, size_t size) __attribute__((visibility("protected")));
void __private_free(void *ptr) __attribute__((visibility("protected")));
void *__private_realloc(void *ptr, size_t size) __attribute__((visibility("protected")));
void *__private_memalign(size_t boundary, size_t size) __attribute__((visibility("protected")));
int __private_posix_memalign(void **memptr, size_t alignment, size_t size) __attribute__((visibility("protected")));
size_t __private_malloc_usable_size(void *userptr) __attribute__((visibility("protected")));

extern const char __ldso_name[] __attribute__((weak));
extern _Bool      __avoid_libdl_calls __attribute__((weak));

/* These are our pointers to the dlsym-returned RTLD_NEXT malloc and friends. */
static void *(*__underlying_malloc)(size_t size);
static void *(*__underlying_calloc)(size_t nmemb, size_t size);
static void (*__underlying_free)(void *ptr);
static void *(*__underlying_realloc)(void *ptr, size_t size);
static void *(*__underlying_memalign)(size_t boundary, size_t size);
static int (*__underlying_posix_memalign)(void **memptr, size_t alignment, size_t size);
static size_t (*__underlying_malloc_usable_size)(void *userptr);

static _Bool tried_to_initialize;
static _Bool failed_to_initialize;
static void initialize_underlying_malloc()
{
	assert(!(tried_to_initialize && failed_to_initialize));
	if (tried_to_initialize && !failed_to_initialize)
	{
		// we should be okay (shouldn't really have been called though)
		assert(__underlying_malloc && __underlying_free && 
			__underlying_memalign && __underlying_realloc && 
			__underlying_calloc && __underlying_posix_memalign &&
			__underlying_malloc_usable_size);
		return;
	}
	else
	{
#define fail(symname) do { \
fprintf(stderr, "dlsym(" #symname ") error: %s\n", dlerror()); \
failed_to_initialize = 1; \
 } while(0)
		tried_to_initialize = 1;
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
		__underlying_malloc_usable_size = (size_t(*)(void*)) dlsym(RTLD_NEXT, "malloc_usable_size");
		if (!__underlying_malloc_usable_size) fail(malloc_usable_size);
#undef fail
	}
}

/* Now the "real" functions. These will rely on private_malloc early on, 
 * when it's not safe to call dlsym(), then switch to underlying_malloc et al. */
void __terminal_hook_init(void) {}

void * __terminal_hook_malloc(size_t size, const void *caller)
{
	if (!__underlying_malloc) initialize_underlying_malloc();
	if (__underlying_malloc) return __underlying_malloc(size);
	else return __private_malloc(size);
}
void __terminal_hook_free(void *ptr, const void *caller)
{
	if (!__underlying_free) initialize_underlying_malloc();
	if (__underlying_free) __underlying_free(ptr);
}
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	if (!__underlying_realloc) initialize_underlying_malloc();
	if (__underlying_realloc) return __underlying_realloc(ptr, size);
	else return NULL;
}
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	if (!__underlying_memalign) initialize_underlying_malloc();
	assert(__underlying_memalign);
	return __underlying_memalign(boundary, size);
}

/* FIXME: also override malloc_usable_size s.t. we divert queries about the
 * private buffer into early_malloc_usable_size. */
size_t __mallochooks_malloc_usable_size(void *userptr);
size_t malloc_usable_size(void *userptr) __attribute__((weak,alias("__mallochooks_malloc_usable_size")));
size_t __mallochooks_malloc_usable_size(void *userptr)
{
	size_t ret;

	// this might silently return if we're in the middle of an early dlsym...
	if (!__underlying_malloc_usable_size) initialize_underlying_malloc();
	// ... in which case this test should succeed
	assert(__underlying_malloc_usable_size);
	ret = __underlying_malloc_usable_size(userptr);

	return ret;
}

/* Stolen from relf.h, but pasted here to stay self-contained. */
extern struct r_debug _r_debug;
extern int _etext; /* NOTE: to resolve to *this object*'s _etext, we *must* be linked -Bsymbolic. */
static inline
struct link_map*
get_highest_loaded_object_below(void *ptr)
{
	/* Walk all the loaded objects' load addresses. 
	 * The load address we want is the next-lower one. */
	struct link_map *highest_seen = NULL;
	for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
	{
		if (!highest_seen || 
				((char*) l->l_addr > (char*) highest_seen->l_addr
					&& (char*) l->l_addr <= (char*) ptr))
		{
			highest_seen = l;
		}
	}
	return highest_seen;
}

static 
_Bool
is_self_call(const void *caller)
{
	static char *our_load_addr;
	if (!our_load_addr) our_load_addr = (char*) get_highest_loaded_object_below(&is_self_call)->l_addr;
	if (!our_load_addr) abort(); /* we're supposed to be preloaded, not executable */
	static char *text_segment_end;
	if (!text_segment_end) text_segment_end = our_load_addr + (unsigned long) &_etext; /* HACK: ABS symbol, so not relocated. */
	return ((char*) caller >= our_load_addr && (char*) caller < text_segment_end);
}

static 
_Bool
is_libdl_or_ldso_call(const void *caller)
{
	static char *ldso_load_addr = NULL;
	static char *ldso_text_segment_end;
	if (!ldso_load_addr) 
	{
		for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
		{
			if (&__ldso_name && 0 == strcmp(l->l_name, __ldso_name))
			{
				ldso_load_addr = (char*) l->l_addr;
				break;
			}
		}
	}
	static char *libdl_load_addr = NULL;
	static char *libdl_text_segment_end;
	if (!libdl_load_addr)
	{
		for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
		{
			// HACK to test for files named 'libdl*'
			const char *found = strstr(l->l_name, "/libdl");
			if (found && !strchr(found + 1, '/'))
			{
				libdl_load_addr = (char*) l->l_addr;
				break;
			}
		}
	}
	
	/* How do we get the text segment size of the ld.so? HACK: just assume the
	 * phdrs are mapped. Ideally use relf.h's symbol lookup funcs, though... hmm,
	 * actually ld.so probably doesn't export its _etext dynamically, so no good. */
	if (ldso_load_addr && !ldso_text_segment_end)
	{
		ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) ldso_load_addr;
		ElfW(Phdr) *phdrs = (ElfW(Phdr) *)((char*) ehdr + ehdr->e_phoff);
		ldso_text_segment_end = ldso_load_addr + phdrs[0].p_memsz; // another monster HACK
	}
	_Bool is_in_ldso = ldso_load_addr &&
			((char*) caller >= ldso_load_addr && (char*) caller < ldso_text_segment_end);
	/* Similar for libdl. */
	if (libdl_load_addr && !libdl_text_segment_end)
	{
		ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) libdl_load_addr;
		ElfW(Phdr) *phdrs = (ElfW(Phdr) *)((char*) ehdr + ehdr->e_phoff);
		libdl_text_segment_end = libdl_load_addr + phdrs[0].p_memsz; // another monster HACK
	}
	_Bool is_in_libdl = libdl_load_addr && 
			((char*) caller >= libdl_load_addr && (char*) caller < libdl_text_segment_end);
	
	return (&__avoid_libdl_calls && __avoid_libdl_calls)
			|| is_in_ldso 
			|| is_in_libdl;
}

/* These are our actual hook stubs. */
void *malloc(size_t size)
{
	static __thread _Bool malloc_active;
	_Bool is_reentrant_call = malloc_active;
	if (!is_reentrant_call) malloc_active = 1;
	void *ret;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		ret = hook_malloc(size, __builtin_return_address(0));
	} else ret = __private_malloc(size);
	if (!is_reentrant_call) malloc_active = 0;
	return ret;
}
void *calloc(size_t nmemb, size_t size)
{
	static __thread _Bool calloc_active;
	_Bool is_reentrant_call = calloc_active;
	if (!is_reentrant_call) calloc_active = 1;
	void *ret;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		ret = hook_malloc(nmemb * size, __builtin_return_address(0));
	} else ret = __private_calloc(nmemb, size);
	if (ret) bzero(ret, nmemb * size);
	if (!is_reentrant_call) calloc_active = 0;
	return ret;
}
void free(void *ptr)
{
	static __thread _Bool free_active;
	_Bool is_reentrant_call = free_active;
	if (!is_reentrant_call) free_active = 1;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		hook_free(ptr, __builtin_return_address(0));
	} else __private_free(ptr);
	if (!is_reentrant_call) free_active = 0;
}
void *realloc(void *ptr, size_t size)
{
	static __thread _Bool realloc_active;
	_Bool is_reentrant_call = realloc_active;
	void *ret;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		ret = hook_realloc(ptr, size, __builtin_return_address(0));
	} else ret = __private_realloc(ptr, size);
	if (!is_reentrant_call) realloc_active = 0;
	return ret;
}
void *memalign(size_t boundary, size_t size)
{
	static __thread _Bool memalign_active;
	_Bool is_reentrant_call = memalign_active;
	void *ret;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		ret = hook_memalign(boundary, size, __builtin_return_address(0));
	} else ret = __private_memalign(boundary, size);
	if (!is_reentrant_call) memalign_active = 0;
	return ret;
}
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	static __thread _Bool posix_memalign_active;
	_Bool is_reentrant_call = posix_memalign_active;
	void *retptr;
	int retval;
	if (!is_reentrant_call
			 && !is_self_call(__builtin_return_address(0))
			 && !is_libdl_or_ldso_call(__builtin_return_address(0)))
	{
		retptr = hook_memalign(alignment, size, __builtin_return_address(0));

		if (!retptr) retval = EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
		else
		{
			*memptr = retptr;
			retval = 0;
		}
	}
	else retval = __private_posix_memalign(memptr, alignment, size);
	if (!is_reentrant_call) posix_memalign_active = 0;
	return retval;
}
