#include <stdlib.h>

#ifndef EARLY_MALLOC_LIMIT
#define EARLY_MALLOC_LIMIT (10*1024*1024)
#endif

char early_malloc_buf[EARLY_MALLOC_LIMIT]; /* 10MB should suffice */
char *early_malloc_pos;
#define EARLY_MALLOC_END (&early_malloc_buf[EARLY_MALLOC_LIMIT])

void *early_malloc(size_t size)
{
	if (early_malloc_pos + size < EARLY_MALLOC_END)
	{
		void *allocated = early_malloc_pos;
		early_malloc_pos += size;
		return allocated;
	}
	else return NULL;
}

void early_free(void *ptr) {}

/* FIXME: early_realloc, etc.. */

/* HMM: do we also want to expose stuff like malloc_usable_size 
 * here, so that it works with early-alloc'd chunks? 
 * There's probably no need, because 
 * - early malloc is mainly for use by the dynamic linker, whose
 *   allocations shouldn't escape to much other code; 
 * - early malloc'd objects show up as static allocations in the
 *   memory map, so libpmirror et al won't treat them as heap. */
