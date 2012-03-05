/* Replicate the original glibc hooks. */

#include "glibc_glue.inc.c"
#include "hook_protos.inc.c"
#include "generic.inc.c"

/* We are the toplevel hook. */
void (*__malloc_initialize_hook)(void) = glibc_initialize_hook;

/* We changed the name of init_hook. */
static void init_hook(void); 
static void initialize_hook(void) { init_hook(); }
