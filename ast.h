#ifndef AST_H
#define AST_H

typedef enum
{
	AST_CONST,
	AST_ID,
	AST_CALL,
	AST_SET,
	AST_SUM,
	AST_DIFF,
	AST_PROD,
	AST_QUOT,
	AST_BLOCK,
	AST_IF,
	AST_WHILE,
} ast_var_t;

typedef struct ast ast_t;

struct ast
{
	ast_var_t	var;
	ast_t *		next;
};

typedef struct
{
	ast_t		ast;
	int		val;
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
#define ast_as_bin(v) ast_as(bin, v)
#define ast_as_block(v) ast_as(block, v)
#define ast_as_if(v) ast_as(if, v)
#define ast_as_while(v) ast_as(while, v)

void		ast_print(const ast_t *ast);
ast_t *		ast_new(ast_var_t var);
ast_const_t *	ast_new_const(int val);
ast_id_t *	ast_new_id(const char *id);
ast_call_t *	ast_new_call(void);
ast_block_t *	ast_new_block(void);
ast_if_t *	ast_new_if(void);
ast_while_t *	ast_new_while(void);
void		ast_dstr_id(ast_id_t *ast);
void		ast_dstr_call(ast_call_t *ast);
void		ast_dstr_block(ast_block_t *ast);
void		ast_dstr_if(ast_if_t *ast);
void		ast_dstr_while(ast_while_t *ast);
void		ast_dstr(ast_t *ast);
void		ast_del(ast_t *ast);

#endif

