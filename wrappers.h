#define DEFINE_WRAPPERS(extraprefix, visibility) \
/* These are our actual hook stubs. */ \
void *MALLOC_PREFIX(extraprefix, malloc)(size_t size) __attribute__((visibility( #visibility ))); \
void *MALLOC_PREFIX(extraprefix, malloc)(size_t size) \
{ \
	void *ret; \
	ret = hook_malloc(size, __builtin_return_address(0)); \
	return ret; \
} \
void *MALLOC_PREFIX(extraprefix, calloc)(size_t nmemb, size_t size) __attribute__((visibility( #visibility ))); \
void *MALLOC_PREFIX(extraprefix, calloc)(size_t nmemb, size_t size) \
{ \
	void *ret; \
	ret = hook_malloc(nmemb * size, __builtin_return_address(0)); \
	if (ret) bzero(ret, nmemb * size); \
	return ret; \
} \
void MALLOC_PREFIX(extraprefix, free)(void *ptr) __attribute__((visibility( #visibility ))); \
void MALLOC_PREFIX(extraprefix, free)(void *ptr) \
{ \
	hook_free(ptr, __builtin_return_address(0)); \
} \
void *MALLOC_PREFIX(extraprefix, realloc)(void *ptr, size_t size) __attribute__((visibility( #visibility ))); \
void *MALLOC_PREFIX(extraprefix, realloc)(void *ptr, size_t size) \
{ \
	void *ret; \
	ret = hook_realloc(ptr, size, __builtin_return_address(0)); \
	return ret; \
} \
void *MALLOC_PREFIX(extraprefix, memalign)(size_t boundary, size_t size) __attribute__((visibility( #visibility ))); \
void *MALLOC_PREFIX(extraprefix, memalign)(size_t boundary, size_t size) \
{ \
	void *ret; \
	ret = hook_memalign(boundary, size, __builtin_return_address(0)); \
	return ret; \
} \
int MALLOC_PREFIX(extraprefix, posix_memalign)(void **memptr, size_t alignment, size_t size) __attribute__((visibility( #visibility ))); \
int MALLOC_PREFIX(extraprefix, posix_memalign)(void **memptr, size_t alignment, size_t size) \
{ \
	void *ret; \
	ret = hook_memalign(alignment, size, __builtin_return_address(0)); \
	 \
	if (!ret) return EINVAL; /* FIXME: check alignment, return ENOMEM/EINVAL as appropriate */ \
	else \
	{ \
		*memptr = ret; \
		return 0; \
	} \
}
