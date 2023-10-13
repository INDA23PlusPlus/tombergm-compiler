#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "tok.h"
#include "xmalloc.h"

void tok_print(const tok_t *tok)
{
	switch (tok->var)
	{
		case TOK_INT	:
		{
			fprintf(stderr, "%i", tok_as_int(tok)->val);
		}						break;
		case TOK_ID	:
		{
			fprintf(stderr, "%s", tok_as_id(tok)->id);
		}						break;
		case TOK_CALL	:
		{
			fprintf(stderr, "(%i)", tok_as_call(tok)->narg);
		}						break;
		case TOK_EQ	: fprintf(stderr, "=");		break;
		case TOK_LT	: fprintf(stderr, "<");		break;
		case TOK_GT	: fprintf(stderr, ">");		break;
		case TOK_2EQ	: fprintf(stderr, "==");	break;
		case TOK_PLUS	: fprintf(stderr, "+");		break;
		case TOK_MINUS	: fprintf(stderr, "-");		break;
		case TOK_ASTER	: fprintf(stderr, "*");		break;
		case TOK_SLASH	: fprintf(stderr, "/");		break;
		case TOK_PRCENT	: fprintf(stderr, "%%");	break;
		case TOK_COMMA	: fprintf(stderr, ",");		break;
		case TOK_SEMICO	: fprintf(stderr, ";");		break;
		case TOK_LPAREN	: fprintf(stderr, "(");		break;
		case TOK_RPAREN	: fprintf(stderr, ")");		break;
		case TOK_LBRACE	: fprintf(stderr, "{");		break;
		case TOK_RBRACE	: fprintf(stderr, "}");		break;
		case TOK_LET	: fprintf(stderr, "let");	break;
		case TOK_IF	: fprintf(stderr, "if");	break;
		case TOK_ELSE	: fprintf(stderr, "else");	break;
		case TOK_WHILE	: fprintf(stderr, "while");	break;
		case TOK_RET	: fprintf(stderr, "return");	break;
		case TOK_FN	: fprintf(stderr, "fn");	break;
	}
}

tok_t *tok_new(tok_var_t var)
{
	size_t size;

	switch (var)
	{
		case TOK_ID	: size = sizeof(tok_id_t);	break;
		case TOK_INT	: size = sizeof(tok_int_t);	break;
		case TOK_CALL	: size = sizeof(tok_call_t);	break;
		default		: size = sizeof(tok_t);		break;
	}

	tok_t *tok = xmalloc(size);

	tok->var = var;
	tok->next = NULL;

	return tok;
}

tok_int_t *tok_new_int(int val)
{
	tok_int_t *tok = tok_as_int(tok_new(TOK_INT));

	tok->val = val;

	return tok;
}

tok_id_t *tok_new_id(const char *s, int l)
{
	tok_id_t *tok = tok_as_id(tok_new(TOK_ID));

	tok->id = xmalloc(l + 1);
	memcpy(tok->id, s, l);
	tok->id[l] = '\0';

	return tok;
}

tok_call_t *tok_new_call(int narg)
{
	tok_call_t *tok = tok_as_call(tok_new(TOK_CALL));

	tok->narg = narg;

	return tok;
}

tok_int_t *tok_dup_int(const tok_int_t *tok)
{
	return tok_new_int(tok->val);
}

tok_id_t *tok_dup_id(const tok_id_t *tok)
{
	return tok_new_id(tok->id, strlen(tok->id));
}

tok_call_t *tok_dup_call(const tok_call_t *tok)
{
	return tok_new_call(tok->narg);
}

tok_t *tok_dup(const tok_t *tok)
{
	if (tok == NULL)
	{
		return NULL;
	}

	switch (tok->var)
	{
		case TOK_INT	: return &tok_dup_int(tok_as_int(tok))->tok;
		case TOK_ID	: return &tok_dup_id(tok_as_id(tok))->tok;
		case TOK_CALL	: return &tok_dup_call(tok_as_call(tok))->tok;
		default		: return tok_new(tok->var);
	}
}

void tok_dstr_id(tok_id_t *tok)
{
	if (tok->id != NULL)
	{
		xfree(tok->id);
	}
}

void tok_dstr(tok_t *tok)
{
	switch (tok->var)
	{
		case TOK_ID	: return tok_dstr_id(tok_as_id(tok));
		default		: return;
	}
}

tok_t *tok_del(tok_t *tok)
{
	if (tok != NULL)
	{
		tok_dstr(tok);

		xfree(tok);
	}

	return NULL;
}

tok_t *tok_del_list(tok_t *tok)
{
	while (tok != NULL)
	{
		tok_t *next = tok->next;

		tok_del(tok);

		tok = next;
	}

	return NULL;
}
