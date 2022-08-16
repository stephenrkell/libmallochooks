#include <stdlib.h>

int *libcall_doing_malloc(int arg)
{
	return malloc(42 + arg);
}

void libcall_doing_free(int *p)
{
	free(p);
}
