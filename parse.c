#include <stddef.h>
#include "ast.h"
#include "misc.h"
#include "tok.h"

#define expect(tok_var) \
({ \
	__typeof__(tok) __expect_tok = tok; \
	if (tok != NULL && tok->var == TOK_ ## tok_var) \
	{ \
		tok = tok->next; \
	} \
	else \
	{ \
		goto err; \
	} \
	__expect_tok; \
})

#define expect_maybe(tok_var) \
({ \
	__typeof__(tok) __expect_maybe_tok; \
	if (tok != NULL && tok->var == TOK_ ## tok_var) \
	{ \
		__expect_maybe_tok = tok; \
		tok = tok->next; \
	} \
	else \
	{ \
		__expect_maybe_tok = NULL; \
	} \
	__expect_maybe_tok; \
})

#define try_parse(what) \
({ \
	ast_t *__try_parse_ast = parse_ ## what(&tok); \
	if (__try_parse_ast == NULL) \
	{ \
		goto err; \
	} \
	__try_parse_ast; \
})

static ast_t *parse_stmt(const tok_t **tokp);

static inline int op_left(const tok_t *tok)
{
	return
		tok->var == TOK_2EQ	||
		tok->var == TOK_LT	||
		tok->var == TOK_GT	||
		tok->var == TOK_PLUS	||
		tok->var == TOK_MINUS	||
		tok->var == TOK_ASTER	||
		tok->var == TOK_SLASH	||
		tok->var == TOK_COMMA	;
}

static inline int op_prec(const tok_t *tok)
{
	if (tok == NULL)
	{
		return -1;
	}

	switch (tok->var)
	{
		default		: return -1;
		case TOK_EQ	: return 0;
		case TOK_2EQ	: return 1;
		case TOK_LT	:
		case TOK_GT	: return 2;
		case TOK_PLUS	:
		case TOK_MINUS	: return 3;
		case TOK_ASTER	:
		case TOK_SLASH	: return 4;
	}
}

static inline int is_comma(const tok_t *tok)
{
	return
		tok != NULL		&&
		tok->var == TOK_COMMA	;
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
			tok->var == TOK_2EQ	||
			tok->var == TOK_LT	||
			tok->var == TOK_GT	||
			tok->var == TOK_PLUS	||
			tok->var == TOK_MINUS	||
			tok->var == TOK_ASTER	||
			tok->var == TOK_SLASH	||
			tok->var == TOK_COMMA
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

static inline int is_call(const tok_t *tok)
{
	return
		tok != NULL		&&
		tok->var == TOK_CALL	;
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
		case TOK_2EQ	: return AST_EQ;
		case TOK_LT	: return AST_LT;
		case TOK_GT	: return AST_GT;
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
		case TOK_CALL	:
		{
			int narg = tok_as_call(tok)->narg;

			ast_call_t *ast = ast_new_call();

			while (ast->narg < tok_as_call(tok)->narg)
			{
				ast_t *arg = parse_expr_pn(tokp);

				if (arg == NULL)
				{
					break;
				}

				ast_push(&ast->arg, arg);

				ast->narg++;
			}

			ast->fn = parse_expr_pn(tokp);

			if (ast->narg != narg || ast->fn == NULL)
			{
				ast_del(&ast->ast);

				return NULL;
			}

			return &ast->ast;
		}
		case TOK_EQ	:
		case TOK_2EQ	:
		case TOK_LT	:
		case TOK_GT	:
		case TOK_PLUS	:
		case TOK_MINUS	:
		case TOK_ASTER	:
		case TOK_SLASH	:
		{
			ast_var_t var = tok_to_bin(tok->var);
			ast_bin_t *ast = ast_as_bin(ast_new(var));

			ast->r = parse_expr_pn(tokp);
			ast->l = parse_expr_pn(tokp);

			if (ast->l == NULL || ast->r == NULL)
			{
				ast_del(&ast->ast);

				return NULL;
			}

			return &ast->ast;
		}
		default		: return NULL;
	}
}

static ast_t *parse_expr(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	const tok_t *pre = NULL;
	ast_t *ast = NULL;

	tok_t *opstk = NULL;
	tok_t *outpt = NULL;
	tok_t *fnstk = NULL;

	for (;;)
	{
		if (is_call(fnstk) && is_comma(tok))
		{
			while (opstk != NULL && !is_lparen(opstk))
			{
				tok_push(&outpt, tok_pop(&opstk));
			}

			tok_as_call(fnstk)->narg++;
		}
		else if (is_val(tok))
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

			if (pre != NULL && !is_op(pre) && !is_lparen(pre))
			{
				tok_push(&fnstk, &tok_new_call(0)->tok);
			}
			else
			{
				tok_push(&fnstk, tok_dup(tok));
			}
		}
		else if (is_rparen(tok))
		{
			if (do_rparen(&opstk, &outpt) != 0)
			{
				break;
			}

			if (is_call(fnstk))
			{
				if (!is_lparen(pre))
				{
					tok_as_call(fnstk)->narg++;
				}

				tok_push(&outpt, tok_pop(&fnstk));
			}
			else
			{
				if (is_lparen(pre))
				{
					goto exit;
				}

				tok_del(tok_pop(&fnstk));
			}
		}
		else
		{
			break;
		}

		pre = tok;
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
			ast = ast_del(ast);

			goto exit;
		}
	}

	*tokp = tok;
exit:
	tok_del_list(opstk);
	tok_del_list(outpt);
	tok_del_list(fnstk);

	return ast;
}

static ast_t *parse_fullexpr(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_t *ast = NULL;

	ast = try_parse(expr);
	expect(SEMICO);

	*tokp = tok;

	return ast;

err:
	ast_del(ast);

	return NULL;
}

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

		ast_push_back(&stmt_head, stmt);
	}

	expect(RBRACE);

	*tokp = tok;

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

static ast_t *parse_let(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_let_t *ast = NULL;

	expect(LET);

	ast = ast_new_let();

	ast->id = &ast_new_id(tok_as_id(expect(ID))->id)->ast;

	if (expect_maybe(EQ) != NULL)
	{
		ast->expr = try_parse(expr);
	}

	expect(SEMICO);

	*tokp = tok;

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

static ast_t *parse_if(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_if_t *ast = NULL;

	expect(IF);
	expect(LPAREN);

	ast = ast_new_if();

	ast->expr = try_parse(expr);
	expect(RPAREN);
	ast->t_stmt = try_parse(stmt);

	if (expect_maybe(ELSE) != NULL)
	{
		ast->f_stmt = try_parse(stmt);
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

	ast->expr = try_parse(expr);
	expect(RPAREN);
	ast->stmt = try_parse(stmt);

	*tokp = tok;

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

static ast_t *parse_ret(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_ret_t *ast = NULL;

	expect(RET);

	ast = ast_new_ret();

	ast->expr = parse_expr(&tok);

	expect(SEMICO);

	*tokp = tok;

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

static ast_t *parse_stmt(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_t *ast;

	ast_t *(*parse_fns[])(const tok_t **tokp) =
	{
		parse_block,
		parse_fullexpr,
		parse_let,
		parse_if,
		parse_while,
		parse_ret,
	};

	for (int i = 0; i < ARRAY_SIZE(parse_fns); i++)
	{
		ast = parse_fns[i](&tok);

		if (ast != NULL)
		{
			*tokp = tok;

			return ast;
		}
	}

	return NULL;
}

static ast_t *parse_arglist(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_t *arg_list = NULL;
	ast_t **arg_head = &arg_list;

	expect(LPAREN);

	for (;;)
	{
		ast_id_t *arg = ast_new_id(tok_as_id(expect(ID))->id);
		ast_push_back(&arg_head, &arg->ast);

		if (expect_maybe(COMMA) == NULL)
		{
			break;
		}
	}

	expect(RPAREN);

	*tokp = tok;

	return arg_list;

err:
	ast_del_list(arg_list);

	return NULL;
}

static ast_t *parse_fn(const tok_t **tokp)
{
	const tok_t *tok = *tokp;
	ast_fn_t *ast = NULL;

	expect(FN);

	ast = ast_new_fn();

	ast->id = &ast_new_id(tok_as_id(expect(ID))->id)->ast;

	ast->arg = parse_arglist(&tok);
	if (ast->arg == NULL)
	{
		expect(LPAREN);
		expect(RPAREN);
	}

	ast->body = try_parse(block);

	ast_t *arg = ast->arg;
	while (arg != NULL)
	{
		ast->narg++;

		arg = arg->next;
	}

	*tokp = tok;

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

ast_t *parse(const tok_t *tok)
{
	ast_t *ast_list = NULL;
	ast_t **ast_head = &ast_list;

	for (;;)
	{
		ast_t *ast = parse_fn(&tok);

		if (ast == NULL)
		{
			break;
		}

		ast_push_back(&ast_head, ast);
	}

	return ast_list;
}

