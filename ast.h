#ifndef AST_H
#define AST_H

#include <stddef.h>
#include <stdint.h>
#include "where.h"

typedef enum
{
	AST_VOID,
	AST_CONST,
	AST_ID,
	AST_CALL,
	AST_NOT,
	AST_SET,
	AST_EQ,
	AST_NE,
	AST_LT,
	AST_LE,
	AST_GT,
	AST_GE,
	AST_LAND,
	AST_LOR,
	AST_SUM,
	AST_DIFF,
	AST_PROD,
	AST_QUOT,
	AST_REM,
	AST_BLOCK,
	AST_LET,
	AST_IF,
	AST_WHILE,
	AST_FN,
	AST_RET,
	AST_END,
} ast_var_t;

typedef struct ast ast_t;

struct ast
{
	ast_var_t	var;
	where_t		where;
	ast_t *		next;
};

typedef struct
{
	ast_t		ast;
	int64_t		val;
} ast_const_t;

typedef struct
{
	ast_t		ast;
	char *		id;
} ast_id_t;

typedef struct
{
	ast_t		ast;
	ast_t *		fn;
	ast_t *		arg;
	int		narg;
} ast_call_t;

typedef struct
{
	ast_t		ast;
	ast_t *		expr;
} ast_un_t;

typedef struct
{
	ast_t		ast;
	ast_t *		l;
	ast_t *		r;
} ast_bin_t;

typedef struct
{
	ast_t		ast;
	ast_t *		stmt;
} ast_block_t;

typedef struct
{
	ast_t		ast;
	ast_t *		id;
	ast_t *		expr;
} ast_let_t;

typedef struct
{
	ast_t		ast;
	ast_t *		expr;
	ast_t *		t_stmt;
	ast_t *		f_stmt;
} ast_if_t;

typedef struct
{
	ast_t		ast;
	ast_t *		expr;
	ast_t *		stmt;
} ast_while_t;

typedef struct
{
	ast_t		ast;
	ast_t *		expr;
} ast_ret_t;

typedef struct
{
	ast_t		ast;
	ast_t *		id;
	ast_t *		arg;
	ast_t *		body;
	int		narg;
} ast_fn_t;

#define ast_as(var, v) \
( \
	_Generic \
	( \
		(v), \
		ast_t *		: (ast_ ## var ## _t *) v, \
		const ast_t *	: (const ast_ ## var ## _t *) v \
	) \
)
#define ast_as_const(v) ast_as(const, v)
#define ast_as_id(v) ast_as(id, v)
#define ast_as_call(v) ast_as(call, v)
#define ast_as_un(v) ast_as(un, v)
#define ast_as_bin(v) ast_as(bin, v)
#define ast_as_block(v) ast_as(block, v)
#define ast_as_let(v) ast_as(let, v)
#define ast_as_if(v) ast_as(if, v)
#define ast_as_while(v) ast_as(while, v)
#define ast_as_ret(v) ast_as(ret, v)
#define ast_as_fn(v) ast_as(fn, v)

static inline ast_t *ast_push(ast_t **astp, ast_t *ast)
{
	if (ast != NULL)
	{
		ast_t *next = *astp;
		*astp = ast;

		ast->next = next;
	}

	return ast;
}

static inline ast_t *ast_push_back(ast_t ***head, ast_t *ast)
{
	if (ast != NULL)
	{
		**head = ast;
		*head = &ast->next;
	}

	return ast;
}

static inline ast_t *ast_pop(ast_t **astp)
{
	ast_t *ast = *astp;

	if (ast != NULL)
	{
		*astp = ast->next;
	}

	return ast;
}

void		ast_print(const ast_t *ast);
ast_t *		ast_new(ast_var_t var);
ast_const_t *	ast_new_const(int val);
ast_id_t *	ast_new_id(const char *id);
ast_call_t *	ast_new_call(void);
ast_block_t *	ast_new_block(void);
ast_let_t *	ast_new_let(void);
ast_if_t *	ast_new_if(void);
ast_while_t *	ast_new_while(void);
ast_ret_t *	ast_new_ret(void);
ast_fn_t *	ast_new_fn(void);
void		ast_dstr_id(ast_id_t *ast);
void		ast_dstr_call(ast_call_t *ast);
void		ast_dstr_block(ast_block_t *ast);
void		ast_dstr_let(ast_let_t *ast);
void		ast_dstr_if(ast_if_t *ast);
void		ast_dstr_while(ast_while_t *ast);
void		ast_dstr_ret(ast_ret_t *ast);
void		ast_dstr_fn(ast_fn_t *ast);
void		ast_dstr(ast_t *ast);
ast_t *		ast_del(ast_t *ast);
ast_t *		ast_del_list(ast_t *ast);

#endif
