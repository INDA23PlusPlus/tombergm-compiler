#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "ast.h"
#include "xmalloc.h"

static const char *op_sym(ast_var_t var)
{
	switch (var)
	{
		case AST_SET	: return "=";
		case AST_EQ	: return "==";
		case AST_LT	: return "<";
		case AST_GT	: return ">";
		case AST_SUM	: return "+";
		case AST_DIFF	: return "-";
		case AST_PROD	: return "*";
		case AST_QUOT	: return "/";
		default		: return "";
	}
}

void ast_print(const ast_t *ast)
{
	switch (ast->var)
	{
		case AST_CONST	:
		{
			printf("%i", ast_as_const(ast)->val);
		}			break;
		case AST_ID	:
		{
			printf("%s", ast_as_id(ast)->id);
		}			break;
		case AST_CALL	:
		{
			ast_print(ast_as_call(ast)->fn);

			printf("(");

			ast_t *arg = ast_as_call(ast)->arg;
			while (arg != NULL)
			{
				ast_print(arg);

				arg = arg->next;

				if (arg != NULL)
				{
					printf(", ");
				}
			}

			printf(")");
		}			break;
		case AST_SET	:
		case AST_EQ	:
		case AST_LT	:
		case AST_GT	:
		case AST_SUM	:
		case AST_DIFF	:
		case AST_PROD	:
		case AST_QUOT	:
		{
			printf("(");
			ast_print(ast_as_bin(ast)->l);
			printf(" %s ", op_sym(ast->var));
			ast_print(ast_as_bin(ast)->r);
			printf(")");
		}			break;
		case AST_BLOCK	:
		{
			printf("{");

			ast_t *stmt = ast_as_block(ast)->stmt;
			while (stmt != NULL)
			{
				printf(" ");
				ast_print(stmt);
				if
				(
					stmt->var != AST_IF	&&
					stmt->var != AST_WHILE
				)
				{
					printf(";");
				}
				stmt = stmt->next;
			}

			printf(" }");
		}			break;
		case AST_LET	:
		{
			printf("let ");
			ast_print(ast_as_let(ast)->id);

			if (ast_as_let(ast)->expr != NULL)
			{
				printf(" = ");
				ast_print(ast_as_let(ast)->expr);
			}
		}			break;
		case AST_IF	:
		{
			printf("if (");
			ast_print(ast_as_if(ast)->expr);
			printf(") ");
			ast_print(ast_as_if(ast)->t_stmt);

			ast_t *f_stmt = ast_as_if(ast)->f_stmt;
			if (f_stmt != NULL)
			{
				printf(" else ");
				ast_print(f_stmt);
			}
		}			break;
		case AST_WHILE	:
		{
			printf("while (");
			ast_print(ast_as_while(ast)->expr);
			printf(") ");
			ast_print(ast_as_while(ast)->stmt);
		}			break;
		case AST_RET	:
		{
			printf("return");
			if (ast_as_ret(ast)->expr != NULL)
			{
				printf(" ");
				ast_print(ast_as_ret(ast)->expr);
			}
		}			break;
		case AST_FN	:
		{
			printf("fn ");
			ast_print(ast_as_fn(ast)->id);
			printf("(");

			ast_t *arg = ast_as_fn(ast)->arg;
			while (arg != NULL)
			{
				ast_print(arg);

				arg = arg->next;

				if (arg != NULL)
				{
					printf(", ");
				}
			}

			printf(") ");
			ast_print(ast_as_fn(ast)->body);
		}			break;
		default		:	break;
	}
}

ast_t *ast_new(ast_var_t var)
{
	size_t size;

	switch (var)
	{
		case AST_CONST	: size = sizeof(ast_const_t);	break;
		case AST_ID	: size = sizeof(ast_id_t);	break;
		case AST_CALL	: size = sizeof(ast_call_t);	break;
		case AST_SET	:
		case AST_EQ	:
		case AST_LT	:
		case AST_GT	:
		case AST_SUM	:
		case AST_DIFF	:
		case AST_PROD	:
		case AST_QUOT	: size = sizeof(ast_bin_t);	break;
		case AST_BLOCK	: size = sizeof(ast_block_t);	break;
		case AST_LET	: size = sizeof(ast_let_t);	break;
		case AST_IF	: size = sizeof(ast_if_t);	break;
		case AST_WHILE	: size = sizeof(ast_while_t);	break;
		case AST_RET	: size = sizeof(ast_ret_t);	break;
		case AST_FN	: size = sizeof(ast_fn_t);	break;
		default		: size = sizeof(ast_t);		break;
	}

	ast_t *ast = xmalloc(size);

	ast->var = var;
	ast->next = NULL;

	return ast;
}

ast_const_t *ast_new_const(int val)
{
	ast_const_t *ast = ast_as_const(ast_new(AST_CONST));

	ast->val = val;

	return ast;
}

ast_id_t *ast_new_id(const char *id)
{
	ast_id_t *ast = ast_as_id(ast_new(AST_ID));

	int l = strlen(id);
	ast->id = xmalloc(l + 1);
	memcpy(ast->id, id, l);
	ast->id[l] = '\0';

	return ast;
}

ast_call_t *ast_new_call(void)
{
	ast_call_t *ast = ast_as_call(ast_new(AST_CALL));

	ast->fn = NULL;
	ast->arg = NULL;
	ast->narg = 0;

	return ast;
}

ast_block_t *ast_new_block(void)
{
	ast_block_t *ast = ast_as_block(ast_new(AST_BLOCK));

	ast->stmt = NULL;

	return ast;
}

ast_let_t *ast_new_let(void)
{
	ast_let_t *ast = ast_as_let(ast_new(AST_LET));

	ast->id = NULL;
	ast->expr = NULL;

	return ast;
}

ast_if_t *ast_new_if(void)
{
	ast_if_t *ast = ast_as_if(ast_new(AST_IF));

	ast->expr = NULL;
	ast->t_stmt = NULL;
	ast->f_stmt = NULL;

	return ast;
}

ast_while_t *ast_new_while(void)
{
	ast_while_t *ast = ast_as_while(ast_new(AST_WHILE));

	ast->expr = NULL;
	ast->stmt = NULL;

	return ast;
}

ast_ret_t *ast_new_ret(void)
{
	ast_ret_t *ast = ast_as_ret(ast_new(AST_RET));

	ast->expr = NULL;

	return ast;
}

ast_fn_t *ast_new_fn(void)
{
	ast_fn_t *ast = ast_as_fn(ast_new(AST_FN));

	ast->id = NULL;
	ast->arg = NULL;
	ast->body = NULL;
	ast->narg = 0;

	return ast;
}

void ast_dstr_id(ast_id_t *ast)
{
	if (ast->id != NULL)
	{
		xfree(ast->id);
	}
}

void ast_dstr_call(ast_call_t *ast)
{
	ast_del(ast->fn);
	ast_del_list(ast->arg);
}

void ast_dstr_block(ast_block_t *ast)
{
	ast_del_list(ast->stmt);
}

void ast_dstr_let(ast_let_t *ast)
{
	ast_del(ast->id);
	ast_del(ast->expr);
}

void ast_dstr_if(ast_if_t *ast)
{
	ast_del(ast->expr);
	ast_del(ast->t_stmt);
	ast_del(ast->f_stmt);
}

void ast_dstr_while(ast_while_t *ast)
{
	ast_del(ast->expr);
	ast_del(ast->stmt);
}

void ast_dstr_ret(ast_ret_t *ast)
{
	ast_del(ast->expr);
}

void ast_dstr_fn(ast_fn_t *ast)
{
	ast_del(ast->id);
	ast_del(ast->arg);
	ast_del(ast->body);
}

void ast_dstr(ast_t *ast)
{
	switch (ast->var)
	{
		case AST_ID	: return ast_dstr_id(ast_as_id(ast));
		case AST_BLOCK	: return ast_dstr_block(ast_as_block(ast));
		case AST_CALL	: return ast_dstr_call(ast_as_call(ast));
		case AST_LET	: return ast_dstr_let(ast_as_let(ast));
		case AST_IF	: return ast_dstr_if(ast_as_if(ast));
		case AST_WHILE	: return ast_dstr_while(ast_as_while(ast));
		case AST_RET	: return ast_dstr_ret(ast_as_ret(ast));
		case AST_FN	: return ast_dstr_fn(ast_as_fn(ast));
		default		: return;
	}
}

ast_t *ast_del(ast_t *ast)
{
	if (ast != NULL)
	{
		ast_dstr(ast);

		xfree(ast);
	}

	return NULL;
}

ast_t *ast_del_list(ast_t *ast)
{
	while (ast != NULL)
	{
		ast_t *next = ast->next;

		ast_del(ast);

		ast = next;
	}

	return NULL;
}

