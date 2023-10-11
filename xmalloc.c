#include <stddef.h>
#include <stdlib.h>

void *xmalloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr == NULL)
	{
		abort();
	}

	return ptr;
}

void xfree(void *ptr)
{
	free(ptr);
}

