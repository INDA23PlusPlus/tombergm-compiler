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
			printf("%i", tok_as_int(tok)->val);
		}					break;
		case TOK_ID	:
		{
			printf("%s", tok_as_id(tok)->id);
		}					break;
		case TOK_CALL	:
		{
			printf("(%i)", tok_as_call(tok)->narg);
		}					break;
		case TOK_EQ	: printf("=");		break;
		case TOK_PLUS	: printf("+");		break;
		case TOK_MINUS	: printf("-");		break;
		case TOK_ASTER	: printf("*");		break;
		case TOK_SLASH	: printf("/");		break;
		case TOK_COMMA	: printf(",");		break;
		case TOK_SEMICO	: printf(";");		break;
		case TOK_LPAREN	: printf("(");		break;
		case TOK_RPAREN	: printf(")");		break;
		case TOK_LBRACE	: printf("{");		break;
		case TOK_RBRACE	: printf("}");		break;
		case TOK_IF	: printf("if");		break;
		case TOK_ELSE	: printf("else");	break;
		case TOK_WHILE	: printf("while");	break;
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

void tok_del(tok_t *tok)
{
	tok_dstr(tok);

	xfree(tok);
}


