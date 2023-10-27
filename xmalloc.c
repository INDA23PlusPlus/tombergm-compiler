#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void *xmalloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr == NULL)
	{
		fprintf(stderr, "error: out of memory, aborting\n");

		abort();
	}

	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);

	if (size != 0 && ptr == NULL)
	{
		fprintf(stderr, "error: out of memory, aborting\n");

		abort();
	}

	return ptr;
}

void xfree(void *ptr)
{
	free(ptr);
}

