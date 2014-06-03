/* Prototypes for the high-level user hooks. */
static void initialize_hook(void);
static void pre_alloc(size_t *p_size, size_t *p_alignment, const void *caller);
static void post_successful_alloc(void *allocated, size_t modified_size, size_t modified_alignment, 
	size_t requested_size, size_t requested_alignment, const void *caller);
static void *allocptr_to_userptr(void *allocptr);
static void *userptr_to_allocptr(void *allocptr);
static void pre_nonnull_free(void *userptr, size_t freed_usable_size);
static void post_nonnull_free(void *userptr);
static void pre_nonnull_nonzero_realloc(void *userptr, size_t size, const void *caller);
static void post_nonnull_nonzero_realloc(void *userptr, 
	size_t modified_size, 
	size_t old_usable_size, 
	const void *caller, void *__new);

/* Prototypes for the generic library-level hooks.
 * These are based on the glibc hooks. */
static void generic_initialize_hook(void);
static void *generic_malloc_hook(size_t size, const void *caller);
static void generic_free_hook(void *ptr, const void *caller);
static void *generic_memalign_hook(size_t alignment, size_t size, const void *caller);
static void *generic_realloc_hook(void *ptr, size_t size, const void *caller);
