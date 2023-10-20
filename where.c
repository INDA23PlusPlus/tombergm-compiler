#include "where.h"

void where_join(where_t *a, const where_t *b)
{
	if (a->file == NULL)
	{
		a->file = b->file;
	}

	if (a->src == NULL)
	{
		a->src = b->src;
	}

	if (a->beg == -1 || b->beg < a->beg)
	{
		a->beg = b->beg;
	}

	if (a->beg == -1 || b->end > a->end)
	{
		a->end = b->end;
	}
}

void where_get_ctx(const where_t *where, where_ctx_t *ctx)
{
	const char *s = where->src;
	const char *p = where->src + where->beg;

	ctx->line = 0;
	ctx->col = 0;
	ctx->line_beg = s;

	while (s != p)
	{
		if (s[0] == '\n')
		{
			ctx->line++;
			ctx->col = 0;
			ctx->line_beg = s + 1;
		}
		else if (s[0] == '\t')
		{
			ctx->col += 8 - (ctx->col % 8);
		}
		else
		{
			ctx->col++;
		}

		s++;
	}

	while (s[0] != '\n' && s[0] != '\0')
	{
		s++;
	}

	ctx->line_end = s;
}
