#include <stddef.h>
#include <string.h>
#include "misc.h"
#include "tok.h"

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

static tok_t *lex_int(const char **sp)
{
	const char *s = *sp;

	if (!is_digit(s[0]))
	{
		return NULL;
	}

	int val = 0;
	while (is_digit(s[0]))
	{
		val = val * 10 + (s[0] - '0');
		s++;
	}

	*sp = s;

	return &tok_new_int(val)->tok;
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

static tok_t *lex_sym(const char **sp)
{
	const char *s = *sp;

	tok_var_t var;
	switch (s++[0])
	{
		case '='	:
		{
			var = TOK_EQ;

			switch (s++[0])
			{
				case '='	: var = TOK_2EQ;	break;
				default		: s--;			break;
			}
		}					break;
		case '<'	: var = TOK_LT;		break;
		case '>'	: var = TOK_GT;		break;
		case '+'	: var = TOK_PLUS;	break;
		case '-'	: var = TOK_MINUS;	break;
		case '*'	: var = TOK_ASTER;	break;
		case '/'	: var = TOK_SLASH;	break;
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

static tok_t *lex_kw(const char **sp)
{
	const char *s = *sp;

	tok_var_t var;

	if (strncmp(s, "let", 3) == 0)
	{
		var = TOK_LET;
		s += 3;
	}
	else if (strncmp(s, "if", 2) == 0)
	{
		var = TOK_IF;
		s += 2;
	}
	else if (strncmp(s, "else", 4) == 0)
	{
		var = TOK_ELSE;
		s += 4;
	}
	else if (strncmp(s, "while", 5) == 0)
	{
		var = TOK_WHILE;
		s += 5;
	}
	else if(strncmp(s, "return", 6) == 0)
	{
		var = TOK_RET;
		s += 6;
	}
	else if (strncmp(s, "fn", 2) == 0)
	{
		var = TOK_FN;
		s += 2;
	}
	else
	{
		return NULL;
	}

	*sp = s;

	return tok_new(var);
}

tok_t *lex(const char *s)
{
	tok_t *(*lex_fns[])(const char **sp) =
	{
		lex_kw,
		lex_int,
		lex_id,
		lex_sym,
	};

	tok_t *tok_list = NULL;
	tok_t **tok_head = &tok_list;

	for (;;)
	{
		while (s[0] == ' ' || s[0] == '\t' || s[0] == '\n')
		{
			s++;
		}

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
			break;
		}

		tok_push_back(&tok_head, tok);
	}

	return tok_list;
}
