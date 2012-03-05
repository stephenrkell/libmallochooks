/* We want to build some non-glibc preloadable malloc wrappers. */

#include "hook_protos.inc.c"
void *__real_malloc(size_t size);
void __real_free(void *ptr);
void *__real_realloc(void *ptr, size_t size);
void *__real_memalign(size_t boundary, size_t size);
#include "generic.inc.c"

/* Init will be done by toplevel_init(). */

/* We changed the name of init_hook. */
static void init_hook(void); 
static void initialize_hook(void) { init_hook(); }

/* Alias __first_blah to */
void __first_initialize_hook(void) //__attribute__((weakref("initialize_hook")));
{ initialize_hook(); }

/* HACK: Our first hooks are the generic hooks dispatching to whatever high-level hooks
 * are defined by our includer.
 * We should really define this by linker arguments, but the generic hooks don't have
 * public linkage names. */

void *__first_malloc_hook(size_t size, const void *caller) 
{ return generic_malloc_hook(size, caller); }
void __first_free_hook(void *ptr, const void *caller) 
{ generic_free_hook(ptr, caller); }
void *__first_realloc_hook(void *ptr, size_t size, const void *caller) 
{ return generic_realloc_hook(ptr, size, caller); }
void *__first_memalign_hook(size_t align, size_t size, const void *caller) 
{ return generic_memalign_hook(align, size, caller); }
