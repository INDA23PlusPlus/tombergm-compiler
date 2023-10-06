#include <stddef.h>
#include "ast.h"
#include "tok.h"

static inline int op_left(const tok_t *tok)
{
	return
		tok->var == TOK_PLUS	||
		tok->var == TOK_MINUS	||
		tok->var == TOK_ASTER	||
		tok->var == TOK_SLASH	;
}

static inline int op_prec(const tok_t *tok)
{
	if (tok == NULL)
	{
		return -1;
	}

	switch (tok->var)
	{
		case TOK_EQ	: return 0;
		case TOK_PLUS	: return 1;
		case TOK_MINUS	: return 1;
		case TOK_ASTER	: return 2;
		case TOK_SLASH	: return 2;
		default		: return -1;
	}
}

static void tok_push(tok_t **tokp, tok_t *tok)
{
	tok_t *next = *tokp;
	*tokp = tok;

	tok->next = next;
}

static tok_t *tok_pop(tok_t **tokp)
{
	tok_t *tok = *tokp;

	if (tok != NULL)
	{
		*tokp = tok->next;
	}

	return tok;
}

static inline int is_val(const tok_t *tok)
{
	return
		tok != NULL			&&
		(
			tok->var == TOK_INT	||
			tok->var == TOK_ID
		);
}

static inline int is_op(const tok_t *tok)
{
	return
		tok != NULL			&&
		(
			tok->var == TOK_EQ	||
			tok->var == TOK_PLUS	||
			tok->var == TOK_MINUS	||
			tok->var == TOK_ASTER	||
			tok->var == TOK_SLASH
		);
}

static inline int is_lparen(const tok_t *tok)
{
	return
		tok != NULL		&&
		tok->var == TOK_LPAREN	;
}

static inline int is_rparen(const tok_t *tok)
{
	return
		tok != NULL		&&
		tok->var == TOK_RPAREN	;
}

static int should_pop(tok_t **opstk, const tok_t *tok)
{
	tok_t *op = *opstk;

	if (op == NULL || op->var == TOK_LPAREN)
	{
		return 0;
	}
	else
	{
		return
			op_prec(op) > op_prec(tok)		||
			(
				op_prec(op) == op_prec(tok)	&&
				op_left(tok)
			);
	}
}

static void do_op(tok_t **opstk, tok_t **outpt, const tok_t *tok)
{
	while (should_pop(opstk, tok))
	{
		tok_push(outpt, tok_pop(opstk));
	}

	tok_push(opstk, tok_dup(tok));
}

static int do_rparen(tok_t **opstk, tok_t **outpt)
{
	if (is_lparen(*opstk))
	{
		return -1;
	}

	while (*opstk != NULL)
	{
		if (is_lparen(*opstk))
		{
			tok_del(tok_pop(opstk));

			return 0;
		}

		tok_push(outpt, tok_pop(opstk));
	}

	return -1;
}

static inline ast_var_t tok_to_bin(tok_var_t var)
{
	switch (var)
	{
		case TOK_EQ	: return AST_SET;
		case TOK_PLUS	: return AST_SUM;
		case TOK_MINUS	: return AST_DIFF;
		case TOK_ASTER	: return AST_PROD;
		case TOK_SLASH	: return AST_QUOT;
		default		: return 0;
	}
}

static ast_t *parse_expr_pn(tok_t **tokp)
{
	tok_t *tok = tok_pop(tokp);

	if (tok == NULL)
	{
		return NULL;
	}

	switch (tok->var)
	{
		case TOK_INT	:
		{
			return &ast_new_const(tok_as_int(tok)->val)->ast;
		}
		case TOK_ID	:
		{
			return &ast_new_id(tok_as_id(tok)->id)->ast;
		}
		case TOK_EQ	:
		case TOK_PLUS	:
		case TOK_MINUS	:
		case TOK_ASTER	:
		case TOK_SLASH	:
		{
			ast_var_t var = tok_to_bin(tok->var);

			ast_t *r = parse_expr_pn(tokp);
			ast_t *l = parse_expr_pn(tokp);

			if (l != NULL && r != NULL)
			{
				ast_bin_t *ast = ast_as_bin(ast_new(var));

				ast->l = l;
				ast->r = r;

				return &ast->ast;
			}
			else
			{
				if (l != NULL)
				{
					ast_del(l);
				}

				if (r != NULL)
				{
					ast_del(r);
				}

				return NULL;
			}
		}
		default		: return NULL;
	}
}

static ast_t *parse_expr(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_t *ast = NULL;

	tok_t *opstk = NULL;
	tok_t *outpt = NULL;

	for (;;)
	{
		if (is_val(tok))
		{
			tok_push(&outpt, tok_dup(tok));
		}
		else if (is_op(tok))
		{
			do_op(&opstk, &outpt, tok);
		}
		else if (is_lparen(tok))
		{
			tok_push(&opstk, tok_dup(tok));
		}
		else if (is_rparen(tok))
		{
			if (opstk == NULL)
			{
				break;
			}

			if (do_rparen(&opstk, &outpt) != 0)
			{
				goto exit;
			}
		}
		else
		{
			break;
		}

		tok = tok->next;
	}

	while (opstk != NULL)
	{
		if (is_lparen(opstk))
		{
			goto exit;
		}

		tok_push(&outpt, tok_pop(&opstk));
	}

	{
		tok_t *outpt_p = outpt;

		ast = parse_expr_pn(&outpt_p);

		if (outpt_p != NULL)
		{
			if (ast != NULL)
			{
				ast_del(ast);
				ast = NULL;
			}

			goto exit;
		}
	}

	*tokp = tok;
exit:
	while (opstk != NULL)
	{
		tok_del(tok_pop(&opstk));
	}
	while (outpt != NULL)
	{
		tok_del(tok_pop(&outpt));
	}

	return ast;
}

#define expect(tok_var) \
	if (tok != NULL && tok->var == TOK_ ## tok_var) \
	{ \
		tok = tok->next; \
	} \
	else \
	{ \
		goto err; \
	}

#define expect_maybe(tok_var) \
	if (tok != NULL && tok->var == TOK_ ## tok_var \
		&& (tok = tok->next, 1)) \

#define try_parse(where, what) \
{ \
	(where) = parse_ ## what (&tok); \
	if ((where) == NULL) \
	{ \
		goto err; \
	} \
}

static ast_t *parse_fullexpr(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_t *ast = NULL;

	try_parse(ast, expr);
	expect(SEMICO);

	*tokp = tok;

	return ast;

err:
	if (ast != NULL)
	{
		ast_del(ast);
	}

	return NULL;
}

static ast_t *parse_stmt(const tok_t **tokp);

static ast_t *parse_block(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_block_t *ast = NULL;

	expect(LBRACE);

	ast = ast_new_block();

	ast_t **stmt_head = &ast->stmt;

	for (;;)
	{
		ast_t *stmt = parse_stmt(&tok);

		if (stmt == NULL)
		{
			break;
		}

		*stmt_head = stmt;
		stmt_head = &stmt->next;
	}

	expect(RBRACE);

	*tokp = tok;

	return &ast->ast;

err:
	if (ast != NULL)
	{
		ast_del(&ast->ast);
	}

	return NULL;
}

static ast_t *parse_if(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_if_t *ast = NULL;

	expect(IF);
	expect(LPAREN);

	ast = ast_new_if();

	try_parse(ast->expr, expr);
	expect(RPAREN);
	try_parse(ast->t_stmt, stmt);

	expect_maybe(ELSE)
	{
		try_parse(ast->f_stmt, stmt);
	}

	*tokp = tok;

	return &ast->ast;

err:
	if (ast != NULL)
	{
		ast_del(&ast->ast);
	}

	return NULL;
}

static ast_t *parse_while(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_while_t *ast = NULL;

	expect(WHILE);
	expect(LPAREN);

	ast = ast_new_while();

	try_parse(ast->expr, expr);
	expect(RPAREN);
	try_parse(ast->stmt, stmt);

	*tokp = tok;

	return &ast->ast;

err:
	if (ast != NULL)
	{
		ast_del(&ast->ast);
	}

	return NULL;
}

static ast_t *parse_stmt(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_t *ast;

	ast = parse_block(&tok);
	if (ast != NULL)
	{
		*tokp = tok;

		return ast;
	}

	ast = parse_fullexpr(&tok);
	if (ast != NULL)
	{
		*tokp = tok;

		return ast;
	}

	ast = parse_if(&tok);
	if (ast != NULL)
	{
		*tokp = tok;

		return ast;
	}

	ast = parse_while(&tok);
	if (ast != NULL)
	{
		*tokp = tok;

		return ast;
	}

	return NULL;
}

ast_t *parse(const tok_t *tok)
{
	ast_t *ast_list = NULL;
	ast_t **ast_head = &ast_list;

	for (;;)
	{
		ast_t *ast = parse_stmt(&tok);

		if (ast == NULL)
		{
			break;
		}

		*ast_head = ast;
		ast_head = &ast->next;
	}

	return ast_list;
}

