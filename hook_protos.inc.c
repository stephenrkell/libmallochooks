/* Prototypes for the high-level user hooks. */
static void initialize_hook(void);
static void pre_alloc(size_t *p_size, const void *caller);
static void post_successful_alloc(void *begin, size_t modified_size, const void *caller);
static void pre_nonnull_free(void *ptr, size_t freed_usable_size);
static void post_nonnull_free(void *ptr);
static void pre_nonnull_nonzero_realloc(void *ptr, size_t size, const void *caller, void *__new);
static void post_nonnull_nonzero_realloc(void *ptr, 
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
