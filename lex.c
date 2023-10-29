#include <stddef.h>
#include <string.h>
#include "err.h"
#include "misc.h"
#include "tok.h"
#include "where.h"

static inline int is_alpha(char c)
{
	return
		(c >= 'a' && c <= 'z')	||
		(c >= 'A' && c <= 'Z')	;
}

static inline int is_digit(char c)
{
	return c >= '0' && c <= '9';
}

static inline int is_idsym(char c)
{
	return c == '_';
}

static inline int is_id(char c)
{
	return is_alpha(c) || is_digit(c) || is_idsym(c);
}

static tok_t *lex_sym(const char **sp)
{
	const char *s = *sp;

	tok_var_t var;
	switch (s++[0])
	{
		case '!'	:
		{
			var = TOK_EX;

			switch (s++[0])
			{
				case '='	: var = TOK_EXEQ;	break;
				default		: s--;
			}
		}					break;
		case '='	:
		{
			var = TOK_EQ;

			switch (s++[0])
			{
				case '='	: var = TOK_2EQ;	break;
				default		: s--;			break;
			}
		}					break;
		case '&'	:
		{
			var = TOK_AMP;

			switch (s++[0])
			{
				case '&'	: var = TOK_2AMP;	break;
				default		: s--;			break;
			}
		}					break;
		case '|'	:
		{
			var = TOK_PIPE;

			switch (s++[0])
			{
				case '|'	: var = TOK_2PIPE;	break;
				default		: s--;			break;
			}
		}					break;
		case '^'	: var = TOK_CARET;	break;
		case '~'	: var = TOK_TILDE;	break;
		case '<'	:
		{
			var = TOK_LT;

			switch (s++[0])
			{
				case '='	: var = TOK_LTEQ;	break;
				case '<'	: var = TOK_2LT;	break;
				default		: s--;			break;
			}
		}					break;
		case '>'	:
		{
			var = TOK_GT;

			switch (s++[0])
			{
				case '='	: var = TOK_GTEQ;	break;
				case '>'	: var = TOK_2GT;	break;
				default		: s--;
			}
		}					break;
		case '+'	: var = TOK_PLUS;	break;
		case '-'	: var = TOK_MINUS;	break;
		case '*'	: var = TOK_ASTER;	break;
		case '/'	: var = TOK_SLASH;	break;
		case '%'	: var = TOK_PRCENT;	break;
		case ','	: var = TOK_COMMA;	break;
		case ';'	: var = TOK_SEMICO;	break;
		case '('	: var = TOK_LPAREN;	break;
		case ')'	: var = TOK_RPAREN;	break;
		case '{'	: var = TOK_LBRACE;	break;
		case '}'	: var = TOK_RBRACE;	break;
		default		: return NULL;
	}

	*sp = s;

	return tok_new(var);
}

static tok_t *lex_int(const char **sp)
{
	const char *s = *sp;

	if (!is_digit(s[0]))
	{
		return NULL;
	}

	uint64_t val = 0;
	while (is_digit(s[0]))
	{
		val = val * 10 + (s[0] - '0');
		s++;
	}

	*sp = s;

	return &tok_new_int(val)->tok;
}

static tok_t *lex_kw(const char **sp)
{
	const char *s = *sp;

	if (is_digit(s[0]) || !is_id(s[0]))
	{
		return NULL;
	}

	int sl = 0;

	while (is_id(s[sl]))
	{
		sl++;
	}

	tok_var_t var;

	if (sl == 3 && strncmp(s, "let", sl) == 0)
	{
		var = TOK_LET;
	}
	else if (sl == 2 && strncmp(s, "if", sl) == 0)
	{
		var = TOK_IF;
	}
	else if (sl == 4 && strncmp(s, "else", sl) == 0)
	{
		var = TOK_ELSE;
	}
	else if (sl == 5 && strncmp(s, "while", sl) == 0)
	{
		var = TOK_WHILE;
	}
	else if (sl == 8 && strncmp(s, "continue", sl) == 0)
	{
		var = TOK_CONT;
	}
	else if (sl == 5 && strncmp(s, "break", sl) == 0)
	{
		var = TOK_BREAK;
	}
	else if(sl == 6 && strncmp(s, "return", sl) == 0)
	{
		var = TOK_RET;
	}
	else if (sl == 2 && strncmp(s, "fn", sl) == 0)
	{
		var = TOK_FN;
	}
	else
	{
		return NULL;
	}

	s += sl;

	*sp = s;

	return tok_new(var);
}

static tok_t *lex_id(const char **sp)
{
	const char *s = *sp;

	if (is_digit(s[0]) || !is_id(s[0]))
	{
		return NULL;
	}

	const char *ss = s;
	int sl = 0;

	while (is_id(s[0]))
	{
		s++;
		sl++;
	}

	*sp = s;

	return &tok_new_id(ss, sl)->tok;
}

tok_t *lex(const char *src, const char *file, err_t **err_list)
{
	const char *s = src;

	tok_t *(*lex_fns[])(const char **sp) =
	{
		lex_sym,
		lex_int,
		lex_kw,
		lex_id,
	};

	tok_t *tok_list = NULL;
	tok_t **tok_head = &tok_list;

	where_t where_tmpl = nowhere();
	where_tmpl.file = file;
	where_tmpl.src = src;

	for (;;)
	{
		while (s[0] == ' ' || s[0] == '\t' || s[0] == '\n')
		{
			s++;
		}

		if (strncmp(s, "/*", 2) == 0)
		{
			s += 2;

			while (s[0] != '\0')
			{
				if (strncmp(s, "*/", 2) == 0)
				{
					s += 2;

					break;
				}
				else
				{
					s++;
				}
			}

			continue;
		}

		where_t where = where_tmpl;
		where.beg = s - src;

		tok_t *tok = NULL;

		for (int i = 0; i < ARRAY_SIZE(lex_fns); i++)
		{
			tok = lex_fns[i](&s);

			if (tok != NULL)
			{
				break;
			}
		}

		if (tok == NULL)
		{
			if (s[0] != '\0')
			{
				where.end = s + 1 - src;
				err_set_m
				(
					err_list,
					where,
					oth,
					"unexpected character"
				);

				goto err;
			}

			break;
		}

		where.end = s - src;
		tok->where = where;

		tok_push_back(&tok_head, tok);
	}

	{
		tok_t *tok = tok_new(TOK_END);

		tok->where = where_tmpl;
		tok->where.beg = s - src;
		tok->where.end = s - src;

		tok_push_back(&tok_head, tok);
	}

	return tok_list;

err:
	tok_del_list(tok_list);

	return NULL;
}
