/* We link this file in if we're using a method (preload or wrap) 
 * that doesn't automatically call the first init hook. */
 
extern void __first_initialize_hook(void) __attribute__((weak));

static void do_initialize(void) __attribute__((constructor));
static void do_initialize(void)
{
	if (__first_initialize_hook) __first_initialize_hook();
}
