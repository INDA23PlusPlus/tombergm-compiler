#include <stddef.h>
#include "ast.h"
#include "err.h"
#include "misc.h"
#include "tok.h"
#include "where.h"
#include "xmalloc.h"

#define par_str_op	"operator"
#define par_str_expr	"expression"
#define par_str_stmt	"statement"
#define par_str_block	"block"
#define par_str_fn	"function definition"

#define expect(tok_var) \
({ \
	__typeof__(tok) __expect_tok = tok; \
	if (tok != NULL && tok->var == TOK_ ## tok_var) \
	{ \
		where_join(&where, &tok->where); \
		tok = tok->next; \
	} \
	else \
	{ \
		err_set_m(err_list, tok->where, exp_tok, TOK_ ## tok_var); \
		goto err; \
	} \
	__expect_tok; \
})

#define expect_maybe(tok_var) \
({ \
	__typeof__(tok) __expect_maybe_tok; \
	if (tok != NULL && tok->var == TOK_ ## tok_var) \
	{ \
		where_join(&where, &tok->where); \
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
	ast_t *__try_parse_ast = parse_ ## what(&tok, err_list); \
	if (__try_parse_ast != NULL) \
	{ \
		where_join(&where, &__try_parse_ast->where); \
	} \
	else \
	{ \
		err_rstor_to(err_list, err_st, &tok->where); \
		err_set_m(err_list, tok->where, exp_some, par_str_ ## what); \
		goto err; \
	} \
	__try_parse_ast; \
})

static ast_t *parse_stmt(const tok_t **tokp, err_t **err_list);

static inline int op_left(const tok_t *tok)
{
	return
		tok->var == TOK_2EQ	||
		tok->var == TOK_EXEQ	||
		tok->var == TOK_LT	||
		tok->var == TOK_LTEQ	||
		tok->var == TOK_GT	||
		tok->var == TOK_GTEQ	||
		tok->var == TOK_2AMP	||
		tok->var == TOK_2PIPE	||
		tok->var == TOK_PLUS	||
		tok->var == TOK_MINUS	||
		tok->var == TOK_ASTER	||
		tok->var == TOK_SLASH	||
		tok->var == TOK_PRCENT	||
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
		case TOK_2PIPE	: return 1;
		case TOK_2AMP	: return 2;
		case TOK_2EQ	:
		case TOK_EXEQ	: return 3;
		case TOK_LT	:
		case TOK_LTEQ	:
		case TOK_GT	:
		case TOK_GTEQ	: return 4;
		case TOK_PLUS	:
		case TOK_MINUS	: return 5;
		case TOK_ASTER	:
		case TOK_SLASH	:
		case TOK_PRCENT	: return 6;
		case TOK_EX	: return 7;
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
			tok->var == TOK_EX	||
			tok->var == TOK_EQ	||
			tok->var == TOK_2EQ	||
			tok->var == TOK_EXEQ	||
			tok->var == TOK_LT	||
			tok->var == TOK_LTEQ	||
			tok->var == TOK_GT	||
			tok->var == TOK_GTEQ	||
			tok->var == TOK_2AMP	||
			tok->var == TOK_2PIPE	||
			tok->var == TOK_PLUS	||
			tok->var == TOK_MINUS	||
			tok->var == TOK_ASTER	||
			tok->var == TOK_SLASH	||
			tok->var == TOK_PRCENT	||
			tok->var == TOK_COMMA
		);
}

static inline int is_un(const tok_t *tok)
{
	return
		tok != NULL			&&
		(
			tok->var == TOK_EX
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

static inline ast_var_t tok_to_un(tok_var_t var)
{
	switch (var)
	{
		case TOK_EX	: return AST_NOT;
		default		: return 0;
	}
}

static inline ast_var_t tok_to_bin(tok_var_t var)
{
	switch (var)
	{
		case TOK_EQ	: return AST_SET;
		case TOK_2EQ	: return AST_EQ;
		case TOK_EXEQ	: return AST_NE;
		case TOK_LT	: return AST_LT;
		case TOK_LTEQ	: return AST_LE;
		case TOK_GT	: return AST_GT;
		case TOK_GTEQ	: return AST_GE;
		case TOK_2AMP	: return AST_LAND;
		case TOK_2PIPE	: return AST_LOR;
		case TOK_PLUS	: return AST_SUM;
		case TOK_MINUS	: return AST_DIFF;
		case TOK_ASTER	: return AST_PROD;
		case TOK_SLASH	: return AST_QUOT;
		case TOK_PRCENT	: return AST_REM;
		default		: return 0;
	}
}

static ast_t *parse_expr_pn(tok_t **tokp, err_t **err_list)
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
			ast_const_t *ast = ast_new_const(tok_as_int(tok)->val);

			where_join(&ast->ast.where, &tok->where);

			return &ast->ast;
		}
		case TOK_ID	:
		{
			ast_id_t *ast = ast_new_id(tok_as_id(tok)->id);

			where_join(&ast->ast.where, &tok->where);

			return &ast->ast;
		}
		case TOK_CALL	:
		{
			int narg = tok_as_call(tok)->narg;

			ast_call_t *ast = ast_new_call();

			where_join(&ast->ast.where, &tok->where);

			while (ast->narg < tok_as_call(tok)->narg)
			{
				ast_t *arg = parse_expr_pn(tokp, err_list);

				if (arg == NULL)
				{
					break;
				}

				ast_push(&ast->arg, arg);

				where_join(&ast->ast.where, &arg->where);

				ast->narg++;
			}

			ast->fn = parse_expr_pn(tokp, err_list);

			if (ast->narg != narg || ast->fn == NULL)
			{
				ast_del(&ast->ast);

				return NULL;
			}

			where_join(&ast->ast.where, &ast->fn->where);

			return &ast->ast;
		}
		case TOK_EX	:
		{
			ast_var_t var = tok_to_un(tok->var);
			ast_un_t *ast = ast_as_un(ast_new(var));

			where_join(&ast->ast.where, &tok->where);

			ast->expr = parse_expr_pn(tokp, err_list);

			if (ast->expr == NULL)
			{
				ast_del(&ast->ast);

				return NULL;
			}

			where_join(&ast->ast.where, &ast->expr->where);

			return &ast->ast;
		}
		case TOK_EQ	:
		case TOK_2EQ	:
		case TOK_EXEQ	:
		case TOK_LT	:
		case TOK_LTEQ	:
		case TOK_GT	:
		case TOK_GTEQ	:
		case TOK_2AMP	:
		case TOK_2PIPE	:
		case TOK_PLUS	:
		case TOK_MINUS	:
		case TOK_ASTER	:
		case TOK_SLASH	:
		case TOK_PRCENT	:
		{
			ast_var_t var = tok_to_bin(tok->var);
			ast_bin_t *ast = ast_as_bin(ast_new(var));

			where_join(&ast->ast.where, &tok->where);

			ast->r = parse_expr_pn(tokp, err_list);
			ast->l = parse_expr_pn(tokp, err_list);

			if (ast->l == NULL || ast->r == NULL)
			{
				ast_del(&ast->ast);

				return NULL;
			}

			where_join(&ast->ast.where, &ast->l->where);
			where_join(&ast->ast.where, &ast->r->where);

			return &ast->ast;
		}
		default		: return NULL;
	}
}

static ast_t *parse_expr(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
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
			if (is_un(tok))
			{
				tok_push(&opstk, tok_dup(tok));
			}
			else
			{
				do_op(&opstk, &outpt, tok);
			}
		}
		else if (is_lparen(tok))
		{
			tok_push(&opstk, tok_dup(tok));

			if (pre != NULL && !is_op(pre) && !is_lparen(pre))
			{
				tok_call_t *tok_call = tok_new_call(0);
				where_join(&tok_call->tok.where, &tok->where);
				tok_push(&fnstk, &tok_call->tok);
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

				where_join(&fnstk->where, &tok->where);
				tok_push(&outpt, tok_pop(&fnstk));
			}
			else
			{
				if (is_lparen(pre))
				{
					err_set_m
					(
						err_list,
						tok->where,
						exp_some,
						par_str_expr
					);

					goto exit;
				}

				tok_del(tok_pop(&fnstk));
			}
		}
		else
		{
			break;
		}

		where_join(&where, &tok->where);

		pre = tok;
		tok = tok->next;
	}

	while (opstk != NULL)
	{
		if (is_lparen(opstk))
		{
			err_set_m
			(
				err_list,
				opstk->where,
				oth,
				"mismatched parenthesis"
			);

			goto exit;
		}

		tok_push(&outpt, tok_pop(&opstk));
	}

	{
		tok_t *outpt_p = outpt;

		ast = parse_expr_pn(&outpt_p, err_list);

		if (outpt_p != NULL)
		{
			err_set_m(err_list, ast->where, exp_some, par_str_op);

			ast = ast_del(ast);

			goto exit;
		}
	}

	*tokp = tok;
	if (ast != NULL)
	{
		ast->where = where;
		err_rstor(err_list, err_st);
	}

exit:
	tok_del_list(opstk);
	tok_del_list(outpt);
	tok_del_list(fnstk);

	return ast;
}

static ast_t *parse_fullexpr(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
	const tok_t *tok = *tokp;
	ast_t *ast = NULL;

	ast = try_parse(expr);
	expect(SEMICO);

	*tokp = tok;
	ast->where = where;
	err_rstor(err_list, err_st);

	return ast;

err:
	ast_del(ast);

	return NULL;
}

static ast_t *parse_block(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
	const tok_t *tok = *tokp;
	ast_block_t *ast = NULL;

	expect(LBRACE);

	ast = ast_new_block();

	ast_t **stmt_head = &ast->stmt;

	for (;;)
	{
		if (expect_maybe(RBRACE) != NULL)
		{
			break;
		}

		ast_push_back(&stmt_head, try_parse(stmt));
	}

	*tokp = tok;
	ast->ast.where = where;
	err_rstor(err_list, err_st);

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

static ast_t *parse_let(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
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
	ast->ast.where = where;
	err_rstor(err_list, err_st);

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

static ast_t *parse_if(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
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
	ast->ast.where = where;
	err_rstor(err_list, err_st);

	return &ast->ast;

err:
	if (ast != NULL)
	{
		ast_del(&ast->ast);
	}

	return NULL;
}

static ast_t *parse_while(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
	const tok_t *tok = *tokp;
	ast_while_t *ast = NULL;

	expect(WHILE);
	expect(LPAREN);

	ast = ast_new_while();

	ast->expr = try_parse(expr);
	expect(RPAREN);
	ast->stmt = try_parse(stmt);

	*tokp = tok;
	ast->ast.where = where;
	err_rstor(err_list, err_st);

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

static ast_t *parse_ret(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
	const tok_t *tok = *tokp;
	ast_ret_t *ast = NULL;

	expect(RET);

	ast = ast_new_ret();

	if (expect_maybe(SEMICO) == NULL)
	{
		ast->expr = try_parse(expr);

		expect(SEMICO);
	}

	*tokp = tok;
	ast->ast.where = where;
	err_rstor(err_list, err_st);

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

static ast_t *parse_stmt(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	const tok_t *tok = *tokp;
	ast_t *ast;

	ast_t *(*parse_fns[])(const tok_t **tokp, err_t **err_list) =
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
		ast = parse_fns[i](&tok, err_list);

		if (ast != NULL)
		{
			*tokp = tok;
			err_rstor(err_list, err_st);

			return ast;
		}
	}

	return NULL;
}

static ast_t *parse_arglist(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
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
	err_rstor(err_list, err_st);

	return arg_list;

err:
	ast_del_list(arg_list);

	return NULL;
}

static ast_t *parse_fn(const tok_t **tokp, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
	const tok_t *tok = *tokp;
	ast_fn_t *ast = NULL;

	expect(FN);

	ast = ast_new_fn();

	ast->id = &ast_new_id(tok_as_id(expect(ID))->id)->ast;

	ast->arg = parse_arglist(&tok, err_list);
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
	ast->ast.where = where;
	err_rstor(err_list, err_st);

	return &ast->ast;

err:
	ast_del(&ast->ast);

	return NULL;
}

ast_t *parse(const tok_t *tok, err_t **err_list)
{
	err_t *err_st = err_save(err_list);
	where_t where = nowhere();
	ast_t *ast_list = NULL;
	ast_t **ast_head = &ast_list;

	for (;;)
	{
		const tok_t *tok_end = expect_maybe(END);

		if (tok_end != NULL)
		{
			ast_t *ast_end = ast_new(AST_END);
			ast_end->where = tok_end->where;

			ast_push_back(&ast_head, ast_end);

			break;
		}

		ast_push_back(&ast_head, try_parse(fn));
	}

	err_rstor(err_list, err_st);

	return ast_list;

err:
	ast_del_list(ast_list);

	return NULL;
}
