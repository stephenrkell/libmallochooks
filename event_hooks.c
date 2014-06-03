#include <strings.h>  /* for bzero */
#include <errno.h>    /* for EINVAL */
#include <stdio.h>    /* for stderr */
#include <assert.h>

#undef HOOK_PREFIX
#include "hook_protos.h"

#define HOOK_PREFIX(i) __next_ ## i
#include "hook_protos.h"
#undef HOOK_PREFIX

#include "alloc_events.h"

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
hook_calloc(size_t nmemb, size_t size, const void *caller)
{
	void *result = hook_malloc(size * nmemb, caller);
	bzero(result, size * nmemb);
	return result;
}

void *
hook_malloc(size_t size, const void *caller)
{
	void *result;
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "calling malloc(%zu)\n", size);
	#endif
	size_t modified_size = size;
	size_t modified_alignment = sizeof (void *);
	pre_alloc(&modified_size, &modified_alignment, caller);
	assert(modified_alignment == sizeof (void *));
	
	result = __next_hook_malloc(size, caller);
	
	if (result) post_successful_alloc(result, modified_size, modified_alignment, 
			size, sizeof (void*), caller);
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "malloc(%zu) returned chunk at %p (modified size: %zu, userptr: %p)\n", 
		size, result, modified_size, ALLOCPTR_TO_USERPTR(result)); 
	#endif
	return ALLOCPTR_TO_USERPTR(result);
}

void
hook_free(void *userptr, const void *caller)
{
	void *allocptr = USERPTR_TO_ALLOCPTR(userptr);
	#ifdef TRACE_MALLOC_HOOKS
	if (userptr != NULL) fprintf(stderr, "freeing chunk at %p (userptr %p)\n", allocptr, userptr);
	#endif 
	if (userptr != NULL) pre_nonnull_free(userptr, malloc_usable_size(allocptr));
	
	__next_hook_free(allocptr, caller);
	
	if (userptr != NULL) post_nonnull_free(userptr);
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "freed chunk at %p\n", allocptr);
	#endif
}

int
hook_posix_memalign(void **memptr, size_t alignment, size_t size, const void *caller)
{
	void *ret = hook_memalign(alignment, size, caller);
	if (!ret) return EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
	else
	{
		*memptr = ret;
		return 0;
	}
}

void *
hook_memalign(size_t alignment, size_t size, const void *caller)
{
	void *result;
	size_t modified_size = size;
	size_t modified_alignment = alignment;
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "calling memalign(%zu, %zu)\n", alignment, size);
	#endif
	pre_alloc(&modified_size, &modified_alignment, caller);
	
	result = __next_hook_memalign(modified_alignment, modified_size, caller);
	
	if (result) post_successful_alloc(result, modified_size, modified_alignment, size, alignment, caller);
	#ifdef TRACE_MALLOC_HOOKS
	printf ("memalign(%zu, %zu) returned %p\n", alignment, size, result);
	#endif
	return ALLOCPTR_TO_USERPTR(result);
}


void *
hook_realloc(void *userptr, size_t size, const void *caller)
{
	void *result_allocptr;
	void *allocptr = USERPTR_TO_ALLOCPTR(userptr);
	size_t alignment = sizeof (void*);
	size_t old_usable_size;
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "realigning user pointer %p (allocptr: %p) to requested size %zu\n", userptr, 
			allocptr, size);
	#endif
	/* Split cases. First we eliminate the cases where
	 * realloc() degenerates into either malloc or free. */
	if (userptr == NULL)
	{
		/* We behave like malloc(). */
		pre_alloc(&size, &alignment, caller);
	}
	else if (size == 0)
	{
		/* We behave like free(). */
		pre_nonnull_free(userptr, malloc_usable_size(allocptr));
	}
	else
	{
		/* We are doing a bone fide realloc. This might fail, leaving the
		 * original block untouched. 
		 * If it changes, we'll need to know the old usable size to access
		 * the old trailer. */
		old_usable_size = malloc_usable_size(allocptr);
		pre_nonnull_nonzero_realloc(userptr, size, caller);
	}
	
	/* Modify the size, as usual, *only if* size != 0 */
	size_t modified_size = size;
	size_t modified_alignment = sizeof (void *);
	if (size != 0)
	{
		pre_alloc(&modified_size, &modified_alignment, caller);
		assert(modified_alignment == sizeof (void *));
	}

	result_allocptr = __next_hook_realloc(allocptr, modified_size, caller);
	
	if (userptr == NULL)
	{
		/* like malloc() */
		if (result_allocptr) post_successful_alloc(result_allocptr, modified_size, modified_alignment, 
				size, sizeof (void*), caller);
	}
	else if (size == 0)
	{
		/* like free */
		post_nonnull_free(userptr);
	}
	else
	{
		/* bona fide realloc */
		post_nonnull_nonzero_realloc(userptr, modified_size, old_usable_size, caller, result_allocptr);
	}

	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "reallocated user chunk at %p, new user chunk at %p (requested size %zu, modified size %zu)\n", 
			userptr, ALLOCPTR_TO_USERPTR(result_allocptr), size, modified_size);
	#endif
	return ALLOCPTR_TO_USERPTR(result_allocptr);
}
