#ifndef TOK_H
#define TOK_H

typedef enum
{
	TOK_INT,
	TOK_ID,
	TOK_EQ,
	TOK_PLUS,
	TOK_MINUS,
	TOK_ASTER,
	TOK_SLASH,
	TOK_SEMICO,
	TOK_LPAREN,
	TOK_RPAREN,
	TOK_LBRACE,
	TOK_RBRACE,
	TOK_IF,
	TOK_ELSE,
	TOK_WHILE,
} tok_var_t;

typedef struct tok tok_t;

struct tok
{
	tok_var_t	var;
	tok_t *		next;
};

typedef struct
{
	tok_t		tok;
	int		val;
} tok_int_t;

typedef struct
{
	tok_t		tok;
	char *		id;
} tok_id_t;

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

void		tok_print(const tok_t *tok);
tok_t *		tok_new(tok_var_t var);
tok_int_t *	tok_new_int(int val);
tok_id_t *	tok_new_id(const char *s, int l);
tok_int_t *	tok_dup_int(const tok_int_t *tok);
tok_id_t *	tok_dup_id(const tok_id_t *tok);
tok_t *		tok_dup(const tok_t *tok);
void		tok_dstr_id(tok_id_t *tok);
void		tok_dstr(tok_t *tok);
void		tok_del(tok_t *tok);

#endif

