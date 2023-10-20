#ifndef WHERE_H
#define WHERE_H

#include <stddef.h>

typedef struct
{
	const char *	file;
	const char *	src;
	long		beg;
	long		end;
} where_t;

typedef struct
{
	long		line;
	long		col;
	const char *	line_beg;
	const char *	line_end;
} where_ctx_t;

static inline where_t nowhere(void)
{
	where_t where;

	where.file = NULL;
	where.src = NULL;
	where.beg = -1;
	where.end = -1;

	return where;
}

void where_join(where_t *a, const where_t *b);
void where_get_ctx(const where_t *where, where_ctx_t *ctx);

#endif
