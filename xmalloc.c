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

void *xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);

	if (size != 0 && ptr == NULL)
	{
		abort();
	}

	return ptr;
}

void xfree(void *ptr)
{
	free(ptr);
}

