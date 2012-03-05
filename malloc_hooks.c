/* Replicate the original glibc hooks. */

#include "glibc_glue.inc.c"
#include "hook_protos.inc.c"
#include "generic.inc.c"

/* We are the toplevel hook. */
void (*__malloc_initialize_hook)(void) = glibc_initialize_hook;

/* This hook was not provided previously. */
static void initialize_hook(void) {}
