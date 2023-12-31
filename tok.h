#ifndef TOK_H
#define TOK_H

#include <stddef.h>
#include <stdint.h>
#include "where.h"

typedef enum
{
	TOK_INT,
	TOK_ID,
	TOK_EX,
	TOK_AMP,
	TOK_PIPE,
	TOK_CARET,
	TOK_TILDE,
	TOK_EQ,
	TOK_LT,
	TOK_GT,
	TOK_LTEQ,
	TOK_GTEQ,
	TOK_2EQ,
	TOK_EXEQ,
	TOK_2AMP,
	TOK_2PIPE,
	TOK_2LT,
	TOK_2GT,
	TOK_PLUS,
	TOK_MINUS,
	TOK_ASTER,
	TOK_SLASH,
	TOK_PRCENT,
	TOK_COMMA,
	TOK_SEMICO,
	TOK_LPAREN,
	TOK_RPAREN,
	TOK_LBRACE,
	TOK_RBRACE,
	TOK_LET,
	TOK_IF,
	TOK_ELSE,
	TOK_WHILE,
	TOK_CONT,
	TOK_BREAK,
	TOK_RET,
	TOK_FN,
	/* Pseudo-tokens for parsing */
	TOK_CALL,
	TOK_NEG,
	TOK_POS,
	TOK_END,
} tok_var_t;

typedef struct tok tok_t;

struct tok
{
	tok_var_t	var;
	where_t		where;
	tok_t *		next;
};

typedef struct
{
	tok_t		tok;
	int64_t		val;
} tok_int_t;

typedef struct
{
	tok_t		tok;
	char *		id;
} tok_id_t;

typedef struct
{
	tok_t		tok;
	int		narg;
} tok_call_t;

#define tok_as(var, v) \
( \
	_Generic \
	( \
		(v), \
		tok_t *		: (tok_ ## var ## _t *) v, \
		const tok_t *	: (const tok_ ## var ## _t *) v \
	) \
)
#define tok_as_int(v) tok_as(int, v)
#define tok_as_id(v) tok_as(id, v)
#define tok_as_call(v) tok_as(call, v)

static inline tok_t *tok_push(tok_t **tokp, tok_t *tok)
{
	if (tok != NULL)
	{
		tok_t *next = *tokp;
		*tokp = tok;

		tok->next = next;
	}

	return tok;
}

static inline tok_t *tok_push_back(tok_t ***head, tok_t *tok)
{
	if (tok != NULL)
	{
		**head = tok;
		*head = &tok->next;
	}

	return tok;
}

static inline tok_t *tok_pop(tok_t **tokp)
{
	tok_t *tok = *tokp;

	if (tok != NULL)
	{
		*tokp = tok->next;
	}

	return tok;
}

void		tok_print(const tok_t *tok);
tok_t *		tok_new(tok_var_t var);
tok_int_t *	tok_new_int(int64_t val);
tok_id_t *	tok_new_id(const char *s, int l);
tok_call_t *	tok_new_call(int narg);
tok_int_t *	tok_dup_int(const tok_int_t *tok);
tok_id_t *	tok_dup_id(const tok_id_t *tok);
tok_call_t *	tok_dup_call(const tok_call_t *tok);
tok_t *		tok_dup(const tok_t *tok);
void		tok_dstr_id(tok_id_t *tok);
void		tok_dstr(tok_t *tok);
tok_t *		tok_del(tok_t *tok);
tok_t *		tok_del_list(tok_t *tok);

#endif
