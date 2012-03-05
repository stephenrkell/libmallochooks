/* We link this file in if we're using a method (preload or wrap) 
 * that doesn't automatically call the first init hook. */
 
extern void first_initialize_hook(void);

static void do_initialize(void) __attribute__((constructor));
static void do_initialize(void)
{
	first_initialize_hook();
}
