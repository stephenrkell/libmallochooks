/* Prototypes for the generic library-level hooks.
 * These are based on the glibc hooks. */
static void generic_initialize_hook(void);
static void *generic_malloc_hook(size_t size, const void *caller);
static void generic_free_hook(void *ptr, const void *caller);
static void *generic_memalign_hook(size_t alignment, size_t size, const void *caller);
static void *generic_realloc_hook(void *ptr, size_t size, const void *caller);

/* The next-in-chain hooks. */
extern void __next_initialize_hook(void) __attribute__((weak));
extern void *__next_malloc_hook(size_t size, const void *caller)__attribute__((weak));
extern void __next_free_hook(void *ptr, const void *caller) __attribute__((weak));
extern void *__next_memalign_hook(size_t alignment, size_t size, const void *caller) __attribute__((weak));
extern void *__next_realloc_hook(void *ptr, size_t size, const void *caller) __attribute__((weak));

static void
generic_initialize_hook(void)
{
	// chain here
	if (__next_initialize_hook) __next_initialize_hook();
	initialize_hook();
}

static void *
generic_malloc_hook(size_t size, const void *caller)
{
	void *result;
	#ifdef TRACE_MALLOC_HOOKS
	printf ("calling malloc(%zu)\n", size);
	#endif
	size_t modified_size = size;
	pre_alloc(&modified_size, caller);
	
	if (__next_malloc_hook) result = __next_malloc_hook(size, caller);
	else result = __real_malloc(modified_size);
	
	if (result) post_successful_alloc(result, modified_size, caller);
	#ifdef TRACE_MALLOC_HOOKS
	printf ("malloc(%zu) returned chunk at %p (modified size: %zu)\n", 
		size, result, modified_size); 
	#endif
	return result;
}

static void
generic_free_hook(void *ptr, const void *caller)
{
	#ifdef TRACE_MALLOC_HOOKS
	if (ptr != NULL) printf ("freeing chunk at %p\n", ptr);
	#endif 
	if (ptr != NULL) pre_nonnull_free(ptr, malloc_usable_size(ptr));
	
	if (__next_free_hook) __next_free_hook(ptr, caller);
	else __real_free(ptr);
	
	if (ptr != NULL) post_nonnull_free(ptr);
	#ifdef TRACE_MALLOC_HOOKS
	printf ("freed chunk at %p\n", ptr);
	#endif
}

static void *
generic_memalign_hook (size_t alignment, size_t size, const void *caller)
{
	void *result;
	size_t modified_size = size;
	#ifdef TRACE_MALLOC_HOOKS
	printf ("calling memalign(%zu, %zu)\n", alignment, size);
	#endif
	pre_alloc(&modified_size, caller);
	
	if (__next_memalign_hook) result = __next_memalign_hook(alignment, modified_size, caller);
	else result = __real_memalign(alignment, modified_size);
	
	if (result) post_successful_alloc(result, modified_size, caller);
	#ifdef TRACE_MALLOC_HOOKS
	printf ("memalign(%zu, %zu) returned %p\n", alignment, size, result);
	#endif
	return result;
}


static void *
generic_realloc_hook(void *ptr, size_t size, const void *caller)
{
	void *result;
	size_t old_usable_size;
	#ifdef TRACE_MALLOC_HOOKS
	printf ("realigning pointer %p to requested size %zu\n", ptr, size);
	#endif
	/* Split cases. First we eliminate the cases where
	 * realloc() degenerates into either malloc or free. */
	if (ptr == NULL)
	{
		/* We behave like malloc(). */
		pre_alloc(&size, caller);
	}
	else if (size == 0)
	{
		/* We behave like free(). */
		pre_nonnull_free(ptr, malloc_usable_size(ptr));
	}
	else
	{
		/* We are doing a bone fide realloc. This might fail, leaving the
		 * original block untouched. 
		 * If it changes, we'll need to know the old usable size to access
		 * the old trailer. */
		old_usable_size = malloc_usable_size(ptr);
		pre_nonnull_nonzero_realloc(ptr, size, caller, result);
	}
	
	/* Modify the size, as usual, *only if* size != 0 */
	size_t modified_size = size;
	if (size != 0)
	{
		pre_alloc(&modified_size, caller);
	}

	if (__next_realloc_hook) result = __next_realloc_hook(ptr, modified_size, caller);
	else result = __real_realloc(ptr, modified_size);
	
	if (ptr == NULL)
	{
		/* like malloc() */
		if (result) post_successful_alloc(result, modified_size, caller);
	}
	else if (size == 0)
	{
		/* like free */
		post_nonnull_free(ptr);
	}
	else
	{
		/* bona fide realloc */
		post_nonnull_nonzero_realloc(ptr, modified_size, old_usable_size, caller, result);
	}

	#ifdef TRACE_MALLOC_HOOKS
	printf ("reallocated chunk at %p, new chunk at %p (requested size %zu, modified size %zu)\n", ptr, result,  
	  size, modified_size);
	#endif
	return result;
}
