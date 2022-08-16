#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int *libcall_doing_malloc(int);
void libcall_doing_free(int*);

int main(void)
{
	// run some stuff in the library
	int *is = libcall_doing_malloc(42);

    // run some stuff that might be in the exe, or not
    int *js = malloc(42 * sizeof (int));
	free(is);
	libcall_doing_free(js);

	// use the libc
	char *chars = strdup("Hello, world!\n");
	char *found = strchr(chars, 'H');
	free(found);
	
	return 0;
}
