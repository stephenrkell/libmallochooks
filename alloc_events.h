#ifndef ALLOC_EVENTS_H_
#define ALLOC_EVENTS_H_

/* By default, event handlers are assumed to be in the same 
 * dynamic object, so that link-time optimisation can take
 * effect by assuming they're never overridden. */
#ifndef ALLOC_EVENT_ATTRIBUTES
#define ALLOC_EVENT_ATTRIBUTES __attribute__((visibility("hidden")))
#endif

/* Prototypes for the event callbacks (formerly "high-level hooks"). */
void post_init(void) ALLOC_EVENT_ATTRIBUTES;
void pre_alloc(size_t *p_size, size_t *p_alignment, const void *caller) ALLOC_EVENT_ATTRIBUTES;
void post_successful_alloc(void *allocated, size_t modified_size, size_t modified_alignment, 
	size_t requested_size, size_t requested_alignment, const void *caller) ALLOC_EVENT_ATTRIBUTES;
void pre_nonnull_free(void *userptr, size_t freed_usable_size) ALLOC_EVENT_ATTRIBUTES;
void post_nonnull_free(void *userptr) ALLOC_EVENT_ATTRIBUTES;
void pre_nonnull_nonzero_realloc(void *userptr, size_t size, const void *caller) ALLOC_EVENT_ATTRIBUTES;
void post_nonnull_nonzero_realloc(void *userptr, 
	size_t modified_size, 
	size_t old_usable_size, 
	const void *caller, void *__new) ALLOC_EVENT_ATTRIBUTES;

#endif
