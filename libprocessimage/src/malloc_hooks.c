#define _GNU_SOURCE
#include <stdio.h>
/* Prototypes for __malloc_hook, __free_hook */
#include <malloc.h>
#include <assert.h>
#include <dlfcn.h>

#include "objdiscover.h"

/* Prototypes for our hooks.  */
static void my_init_hook (void);
static void *my_malloc_hook (size_t, const void *);
static void my_free_hook (void*, const void *);
static void *my_memalign_hook (size_t alignment, size_t size, const void *caller);
static void *my_realloc_hook(void *ptr, size_t size, const void *caller);

/* Local variables to hold the next-in-chain hooks. */
static void *(*old_malloc_hook) (size_t, const void *);
static void (*old_free_hook) (void*, const void *);
static void *(*old_memalign_hook) (size_t alignment, size_t size, const void *caller);
static void *(*old_realloc_hook)(void *ptr, size_t size, const void *caller);

        
/* Override initializing hook from the C library. */
void (*__malloc_initialize_hook) (void) = my_init_hook;

/* The trick here is that we keep our own malloc bookkeeping info,
 * to remember the extents of blocks that were actually issued to
 * malloc callers. This is because I don't know of any way to 
 * discover the extents of an issued block given a pointer to some
 * arbitrary location in the block. It may not even be knowable
 * without guesswork.... */

struct __cake_alloc *__cake_alloc_list_head;
unsigned long recs_allocated;
double average_alloc_size;
        
static void
my_init_hook (void)
{
    /* save old hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* install our hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
	/* Sanity check: can we find the list head using the link map? 
     * Separate-process tools like ltrace (with our patches) rely on this. */
    assert(&__cake_alloc_list_head == dlsym(RTLD_DEFAULT, "__cake_alloc_list_head"));
}

void print_head_alloc(void)
{
	fprintf(stderr, "Head alloc is at %p, has begin %p, size %d bytes, next %p\n",
            __cake_alloc_list_head, __cake_alloc_list_head->begin,
            __cake_alloc_list_head->size, __cake_alloc_list_head->next);
}

static void
add_region_rec(void *begin, size_t size)
{
	struct __cake_alloc *new_cake_alloc = malloc(sizeof(new_cake_alloc));
    new_cake_alloc->begin = begin;
    new_cake_alloc->size = size;
    // FIXME: locking
    new_cake_alloc->next = __cake_alloc_list_head;
    __cake_alloc_list_head = new_cake_alloc;
    recs_allocated++;
    average_alloc_size = (average_alloc_size * (recs_allocated - 1) + size) / recs_allocated;
}

static void *
my_malloc_hook (size_t size, const void *caller)
{
    void *result;
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __memalign_hook = old_memalign_hook;
    __realloc_hook = old_realloc_hook;
    /* Call recursively */
    /*printf ("calling malloc (%u)\n", (unsigned int) size);*/
    result = malloc (size);
    if (result) add_region_rec(result, size);
    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* printf might call malloc, so protect it too. */
    /*printf ("malloc (%u) returns %p\n", (unsigned int) size, result);*/
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
    return result;
}

static void delete_region_rec_for(void *ptr)
{
/*    if (__cake_alloc_list_head->begin == ptr)
    {
    	void *old = __cake_alloc_list_head;
        __cake_alloc_list_head = __cake_alloc_list_head->next;
        free_func(old);   
    }    
    else
    {*/
	    int found = 0;
	    size_t saved_size;
        struct __cake_alloc *prev_node = NULL;
        for (struct __cake_alloc *n = __cake_alloc_list_head;
            	    n != NULL;
                    prev_node = n, n = n->next)
        {
            if (n->begin == ptr)
            {
        	    found = 1;
                if (prev_node != NULL) prev_node->next = n->next;
                else __cake_alloc_list_head = n->next;
                saved_size = n->size;
                free(n);
                break;   
            }
        }
	    assert(found);
	    average_alloc_size = (average_alloc_size * recs_allocated - saved_size) / (recs_allocated - 1);
        recs_allocated--;
/*    }*/
}

static void
my_free_hook (void *ptr, const void *caller)
{
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __memalign_hook = old_memalign_hook;
    __realloc_hook = old_realloc_hook;
    /* Call recursively */
    /*if (ptr != NULL) printf ("freeing pointer %p\n", ptr);*/
    free (ptr);
    if (ptr != NULL) delete_region_rec_for(ptr);
    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* printf might call free, so protect it too. */
    /*printf ("freed pointer %p\n", ptr);*/
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
}

static void *
my_memalign_hook (size_t alignment, size_t size, const void *caller)
{
    void *result;
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __memalign_hook = old_memalign_hook;
    __realloc_hook = old_realloc_hook;
    /* Call recursively */
    result = memalign(alignment, size);
    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* printf might call free, so protect it too. */
    /*printf ("memalign (%u, %u) returns %p\n", (unsigned) alignment, (unsigned) size, result);*/
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
    return result;
}

static void *
my_realloc_hook(void *ptr, size_t size, const void *caller)
{
    void *result;
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __memalign_hook = old_memalign_hook;
    __realloc_hook = old_realloc_hook;
    /* Call recursively */
    result = realloc(ptr, size);
    if (ptr != NULL) delete_region_rec_for(ptr);
    if (result != NULL) add_region_rec(result, size);
    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* printf might call free, so protect it too. */
    /* printf ("realigned pointer %p to %p (size %u)\n", ptr, result, (unsigned) size); */
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
    return result;
}

/*int
main (void)
{
	return 0;
}*/
