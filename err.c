#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "err.h"
#include "tok.h"
#include "where.h"
#include "xmalloc.h"

err_t *err_dup(const err_t *err)
{
	if (err == NULL)
	{
		return NULL;
	}

	size_t size;

	switch (err->var)
	{
		case ERR_EXP	: size = sizeof(err_exp_t);	break;
		case ERR_OTH	: size = sizeof(err_oth_t);	break;
		default		: size = sizeof(err_t);		break;
	}

	err_t *err_d = xmalloc(size);

	memcpy(err_d, err, size);
	err_d->next = NULL;

	return err_d;
}

void err_del(err_t *err)
{
	xfree(err);
}

void err_set(err_t **err_list, const err_t *err)
{
	err_t *top = *err_list;

	if (top != NULL && top->where.beg > err->where.beg)
	{
		return;
	}

	err_t *err_d = err_dup(err);

	err_t *next = *err_list;
	*err_list = err_d;
	err_d->next = next;
}

err_t *err_save(err_t **err_list)
{
	return *err_list;
}

void err_rstor(err_t **err_list, const err_t *err_st)
{
	err_t *err = *err_list;

	while (err != err_st)
	{
		err_t *next = err->next;

		err_del(err);

		err = next;
	}

	*err_list = err;
}

void err_rstor_to(err_t **err_list, const err_t *err_st, const where_t *to)
{
	err_t *err = *err_list;

	while (err != err_st && err->where.beg <= to->beg)
	{
		err_t *next = err->next;

		err_del(err);

		err = next;
	}

	*err_list = err;
}

static void print_err_ctx(const where_t *where, const where_ctx_t *ctx)
{
	long range_l = where->end - where->beg;
	long line_l = ctx->line_end - ctx->line_beg;

	if (where->src + where->end > ctx->line_end)
	{
		range_l = ctx->line_end - (where->src + where->beg);
	}

	fprintf(stderr, "%5li | ", ctx->line + 1);
	for (int i = 0; i < line_l; i++)
	{
		if (ctx->line_beg[i] == '\t')
		{
			int n = 8 - i % 8;
			for (int j = 0; j < n; j++)
			{
				fprintf(stderr, " ");
			}
		}
		else
		{
			fprintf(stderr, "%c", ctx->line_beg[i]);
		}
	}
	fprintf(stderr, "\n      | ");

	for (long i = 0; i < ctx->col; i++)
	{
		fprintf(stderr, " ");
	}

	for (long i = 0; i < range_l; i++)
	{
		if (i == 0)
		{
			fprintf(stderr, "^");
		}
		else
		{
			fprintf(stderr, "~");
		}
	}

	fprintf(stderr, "\n");
}

static void print_exp_opt(const err_exp_t *err)
{
	if (err->what != NULL)
	{
		fprintf(stderr, "%s", err->what);
	}
	else if (err->tok_var == TOK_INT)
	{
		fprintf(stderr, "integer");
	}
	else if (err->tok_var == TOK_ID)
	{
		fprintf(stderr, "identifier");
	}
	else if (err->tok_var == TOK_CALL)
	{
		fprintf(stderr, "function call");
	}
	else if (err->tok_var == TOK_END)
	{
		fprintf(stderr, "end of file");
	}
	else
	{
		tok_t tok;

		tok.var = err->tok_var;

		fprintf(stderr, "'");
		tok_print(&tok);
		fprintf(stderr, "'");
	}
}

static void print_exp_list(const err_t *err)
{
	where_t where = err->where;
	where_ctx_t ctx;

	where_get_ctx(&where, &ctx);
	fprintf(stderr, "%s:%li:%li: error: expected ",
		where.file, ctx.line + 1, ctx.col + 1);

	int nopt = 0;
	const err_exp_t *opt = NULL;

	while (err != NULL)
	{
		if (err->where.beg != where.beg)
		{
			break;
		}

		if (err->var == ERR_EXP)
		{
			if (opt != NULL)
			{
				if (nopt > 1)
				{
					fprintf(stderr, ", ");
				}

				print_exp_opt(opt);
			}

			opt = err_as_exp(err);
			nopt++;

			where_join(&where, &opt->err.where);
		}

		err = err->next;
	}

	if (opt != NULL)
	{
		if (nopt > 1)
		{
			fprintf(stderr, " or ");
		}

		print_exp_opt(opt);
	}

	fprintf(stderr, "\n");

	where_get_ctx(&where, &ctx);

	print_err_ctx(&where, &ctx);
}

static void print_oth(const err_oth_t *err)
{
	where_t where = err->err.where;
	where_ctx_t ctx;

	where_get_ctx(&where, &ctx);

	fprintf(stderr, "%s:%li:%li: error: %s\n",
		where.file, ctx.line + 1, ctx.col + 1, err->what);

	print_err_ctx(&where, &ctx);
}

void err_print(err_t *err)
{
	if (err == NULL)
	{
		return;
	}

	switch (err->var)
	{
		case ERR_EXP	:
		{
			return print_exp_list(err);
		}
		case ERR_OTH	:
		{
			return print_oth(err_as_oth(err));
		}
	}
}

