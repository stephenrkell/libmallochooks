#ifndef ALLOC_EVENTS_H_
#define ALLOC_EVENTS_H_

/* Prototypes for the event callbacks (formerly "high-level hooks"). */
void post_init(void);
void pre_alloc(size_t *p_size, size_t *p_alignment, const void *caller);
void post_successful_alloc(void *allocated, size_t modified_size, size_t modified_alignment, 
	size_t requested_size, size_t requested_alignment, const void *caller);
void pre_nonnull_free(void *userptr, size_t freed_usable_size);
void post_nonnull_free(void *userptr);
void pre_nonnull_nonzero_realloc(void *userptr, size_t size, const void *caller);
void post_nonnull_nonzero_realloc(void *userptr, 
	size_t modified_size, 
	size_t old_usable_size, 
	const void *caller, void *__new);

#endif
