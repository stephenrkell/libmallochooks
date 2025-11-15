#include <strings.h>  /* for bzero */
#include <errno.h>    /* for EINVAL */
#include <stdio.h>    /* for stderr */
#include <assert.h>

#include "mallochooks/userapi.h"

/* Our hooks default to hook_*.
 * FIXME: we used to tell clients to compile with -Dhook_malloc=xxx here
 * to change our hook names. Is any client still doing this? Check liballocs. */
#ifndef OUR_HOOK
#define OUR_HOOK(m) hook_ ## m
#endif

#ifndef NEXT_HOOK
#define NEXT_HOOK(m) HOOK_PREFIX(m)
#endif

/* We want to declare the next-called hooks. But
 * this is a problem if the callee is a function pointer
 * not a direct-called function. We will blithely declare a
 * plain function here. */
#if !defined(HOOK_PREFIX) && defined(NEXT_HOOK)
#define HOOK_PREFIX(m) NEXT_HOOK(m)
#endif
#include "mallochooks/hookapi.h"

/* By default, event handler function definitions are hidden */
#define HIDDEN __attribute__((visibility("hidden")))
#ifndef ALLOC_EVENT_ATTRIBUTES
#define ALLOC_EVENT_ATTRIBUTES HIDDEN
#endif
#include "mallochooks/eventapi.h"

/* We can translate between 'alloc' and 'user' pointers,
 * if instrumentation is adding a header. However, in
 * practice trailers are more robust. */
#ifndef ALLOCPTR_TO_USERPTR
#define ALLOCPTR_TO_USERPTR(a) (a)
#else
#warning "alloc <-> user translation is not robust"
#endif

#ifndef USERPTR_TO_ALLOCPTR
#define USERPTR_TO_ALLOCPTR(u) (u)
#else
#warning "alloc <-> user translation is not robust"
#endif

void OUR_HOOK(init)(void)
{
	// chain here
	ALLOC_EVENT(post_init)();
	NEXT_HOOK(init)();
}

void *OUR_HOOK(malloc)(size_t size, const void *caller)
{
	void *result;
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "called malloc(%zu)\n", size);
	#endif
	size_t modified_size = size;
	size_t modified_alignment = sizeof (void *);
	ALLOC_EVENT(pre_alloc)(&modified_size, &modified_alignment, caller);
	assert(modified_alignment == sizeof (void *));
	
	result = NEXT_HOOK(malloc)(modified_size, caller);
	
	if (result) ALLOC_EVENT(post_successful_alloc)(result, modified_size, modified_alignment, 
			size, sizeof (void*), caller);
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "malloc(%zu) returned chunk at %p (modified size: %zu, userptr: %p)\n", 
		size, result, modified_size, ALLOCPTR_TO_USERPTR(result)); 
	#endif
	return ALLOCPTR_TO_USERPTR(result);
}

void OUR_HOOK(free)(void *userptr, const void *caller)
{
	void *allocptr = USERPTR_TO_ALLOCPTR(userptr);
	#ifdef TRACE_MALLOC_HOOKS
	if (userptr != NULL) fprintf(stderr, "freeing chunk at %p (userptr %p)\n", allocptr, userptr);
	#endif
	/* FIXME: which malloc_usable_size should we use here? */
	if (userptr != NULL)
	{
		size_t size = NEXT_HOOK(malloc_usable_size)(allocptr);
		if (ALLOC_EVENT(pre_nonnull_free)(userptr, size))
		{
			/* the pre-hook can 'cancel' the free by returning nonzero */
			return;
		}
	}
	
	NEXT_HOOK(free)(allocptr, caller);
	
	if (userptr != NULL) ALLOC_EVENT(post_nonnull_free)(userptr);
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "freed chunk at %p\n", allocptr);
	#endif
}

void *OUR_HOOK(memalign)(size_t alignment, size_t size, const void *caller)
{
	void *result;
	size_t modified_size = size;
	size_t modified_alignment = alignment;
	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "calling memalign(%zu, %zu)\n", alignment, size);
	#endif
	ALLOC_EVENT(pre_alloc)(&modified_size, &modified_alignment, caller);
	
	result = NEXT_HOOK(memalign)(modified_alignment, modified_size, caller);
	
	if (result) ALLOC_EVENT(post_successful_alloc)(result, modified_size, modified_alignment, size, alignment, caller);
	#ifdef TRACE_MALLOC_HOOKS
	printf ("memalign(%zu, %zu) returned %p\n", alignment, size, result);
	#endif
	return ALLOCPTR_TO_USERPTR(result);
}


void *OUR_HOOK(realloc)(void *userptr, size_t size, const void *caller)
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
		ALLOC_EVENT(pre_alloc)(&size, &alignment, caller);
	}
	else if (size == 0)
	{
		/* We behave like free(). */
		old_usable_size = NEXT_HOOK(malloc_usable_size)(allocptr);
		/* The free hook can 'cancel' the free by returning non-zero. */
		if (ALLOC_EVENT(pre_nonnull_free)(userptr, old_usable_size)) return NULL;
	}
	else
	{
		/* We are doing a bone fide realloc. This might fail, leaving the
		 * original block untouched. 
		 * If it changes, we'll need to know the old usable size to access
		 * the old trailer. */
		old_usable_size = NEXT_HOOK(malloc_usable_size)(allocptr);
		ALLOC_EVENT(pre_nonnull_nonzero_realloc)(userptr, size, caller);
	}
	
	/* Modify the size, as usual, *only if* size != 0 */
	size_t modified_size = size;
	size_t modified_alignment = sizeof (void *);
	if (size != 0)
	{
		ALLOC_EVENT(pre_alloc)(&modified_size, &modified_alignment, caller);
		assert(modified_alignment == sizeof (void *));
	}

	result_allocptr = NEXT_HOOK(realloc)(allocptr, modified_size, caller);
	
	if (userptr == NULL)
	{
		/* like malloc() */
		if (result_allocptr) ALLOC_EVENT(post_successful_alloc)(result_allocptr, modified_size, modified_alignment, 
				size, sizeof (void*), caller);
	}
	else if (size == 0)
	{
		/* like free */
		ALLOC_EVENT(post_nonnull_free)(userptr);
	}
	else
	{
		/* bona fide realloc */
		ALLOC_EVENT(post_nonnull_nonzero_realloc)(userptr, modified_size, old_usable_size, caller, result_allocptr);
	}

	#ifdef TRACE_MALLOC_HOOKS
	fprintf(stderr, "reallocated user chunk at %p, new user chunk at %p (requested size %zu, modified size %zu)\n", 
			userptr, ALLOCPTR_TO_USERPTR(result_allocptr), size, modified_size);
	#endif
	return ALLOCPTR_TO_USERPTR(result_allocptr);
}

size_t OUR_HOOK(malloc_usable_size)(void *ptr)
{
	return NEXT_HOOK(malloc_usable_size)(ptr);
}
