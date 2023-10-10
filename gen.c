#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ast.h"
#include "xmalloc.h"

typedef enum
{
	REG_RAX,
	REG_RBX,
	REG_RCX,
	REG_RDX,
	REG_RBP,
	REG_RSP,
	REG_RSI,
	REG_RDI,
	REG_R8,
	REG_R9,
	REG_R10,
	REG_R11,
	REG_R12,
	REG_R13,
	REG_R14,
	REG_R15,
	REG_MAX,
	REG_INV = -1,
} reg_t;

#define RESERV	1
#define ALLOCD	2

static const char *reg_names[] =
{
	"%rax",
	"%rbx",
	"%rcx",
	"%rdx",
	"%rbp",
	"%rsp",
	"%rsi",
	"%rdi",
	"%r8",
	"%r9",
	"%r10",
	"%r11",
	"%r12",
	"%r13",
	"%r14",
	"%r15",
};

reg_t call_regs[] =
{
	REG_RDI,
	REG_RSI,
	REG_RDX,
	REG_RCX,
	REG_R8,
	REG_R9,
};

typedef struct def def_t;

struct def
{
	def_t *		next;
	const char *	id;
	int		reg;
};

typedef struct
{
	def_t *	defs;
	int	regs[REG_MAX];
	int	lbl;
} state_t;

static int labl(const char *fmt, ...)
{
	int ret = 0;
	va_list arg;

	va_start(arg, fmt);
	ret += vprintf(fmt, arg);
	va_end(arg);

	ret += printf(":\n");

	return ret;
}

static int insn(const char *fmt, ...)
{
	int ret = 0;
	va_list arg;

	ret += printf("\t");

	va_start(arg, fmt);
	ret += vprintf(fmt, arg);
	va_end(arg);

	ret += printf("\n");

	return ret;
}

static int endl(void)
{
	return printf("\n");
}

void state_init(state_t *st)
{
	st->defs = NULL;

	for (int i = 0; i < REG_MAX; i++)
	{
		st->regs[i] = 0;
	}

	st->regs[REG_RAX] = RESERV;
	st->regs[REG_RCX] = RESERV;
	st->regs[REG_RDX] = RESERV;
	st->regs[REG_RSP] = RESERV;
	st->regs[REG_RSI] = RESERV;
	st->regs[REG_RDI] = RESERV;
	st->regs[REG_R8] = RESERV;
	st->regs[REG_R9] = RESERV;

	st->lbl = 0;
}

void state_dstr(state_t *st)
{
	while (st->defs != NULL)
	{
		def_t *next = st->defs->next;

		xfree(st->defs);

		st->defs = next;
	}
}

void def_add(state_t *st, const char *id, int r)
{
	def_t *def = xmalloc(sizeof(def_t));

	def->id = id;
	def->reg = r;

	def->next = st->defs;
	st->defs = def;
}

def_t *def_lookup(const state_t *st, const char *id)
{
	def_t *def = st->defs;

	while (def != NULL)
	{
		if (strcmp(def->id, id) == 0)
		{
			return def;
		}

		def = def->next;
	}

	return NULL;
}

static const char *reg_name(int r)
{
	if (r < 0 || r >= REG_MAX)
	{
		abort();
	}

	return reg_names[r];
}

static int reg_alloc(state_t *st)
{
	for (int i = 0; i < REG_MAX; i++)
	{
		if (st->regs[i] == 0)
		{
			st->regs[i] |= ALLOCD;

			return i;
		}
	}

	return -1;
}

static void reg_free(state_t *st, int r)
{
	st->regs[r] &= ~ALLOCD;
}

static int reg_realloc(state_t *st, int *a)
{
	if (!(st->regs[*a] & RESERV))
	{
		return *a;
	}
	else
	{
		int r = reg_alloc(st);
		insn("MOV\t%s, %s", reg_name(*a), reg_name(r));
		reg_free(st, *a);
		return r;
	}
}

static int reg_realloc2(state_t *st, int *a, int *b)
{
	if (!(st->regs[*a] & RESERV))
	{
		return *a;
	}
	else if (!(st->regs[*b] & RESERV))
	{
		int r = *a;
		*a = *b;
		*b = r;
		return *a;
	}
	else
	{
		int r = reg_alloc(st);
		insn("MOV\t%s, %s", reg_name(*a), reg_name(r));
		reg_free(st, *a);
		return r;
	}
}

static const char *lbl_name(int l)
{
	static char s[32];

	sprintf(s, ".L%i", l);

	return s;
}

static int lbl_alloc(state_t *st)
{
	return st->lbl++;
}

static int gen_stmt(const ast_t *ast, state_t *st);
static int gen_expr(const ast_t *ast, state_t *st);

static int gen_const(const ast_const_t *ast, state_t *st)
{
	int r = reg_alloc(st);

	if (ast->val == 0)
	{
		insn("XOR\t%s, %s", reg_name(r), reg_name(r));
	}
	else
	{
		insn("MOV\t$%i, %s", ast->val, reg_name(r));
	}

	return r;
}

static int gen_id(const ast_id_t *ast, state_t *st)
{
	def_t *def = def_lookup(st, ast->id);

	st->regs[def->reg] |= ALLOCD;

	return def->reg;
}

static int gen_call(const ast_call_t *ast, state_t *st)
{
	for (int i = 0; i < REG_MAX; i++)
	{
		if (st->regs[i] & ALLOCD)
		{
			insn("PUSH\t%s", reg_name(i));
		}
	}

	int narg = 0;
	ast_t *arg = ast->arg;
	int moved[ast->narg];
	while (arg != NULL)
	{
		int a = gen_expr(arg, st);
		int b = call_regs[narg];
		insn("PUSH\t%s", reg_name(b));
		if (b != a)
		{
			if (st->regs[b] & ALLOCD)
			{
				b = reg_alloc(st);
			}
			insn("MOV\t%s, %s", reg_name(a), reg_name(b));
		}
		moved[narg] = b;
		reg_free(st, a);

		narg++;
		arg = arg->next;
	}

	for (int i = 0; i < narg; i++)
	{
		int b = call_regs[i];

		if (moved[i] != b)
		{
			insn("MOV\t%s, %s", moved[i], b);
			reg_free(st, moved[i]);
		}
	}

	insn("XOR\t%%rax, %%rax");
	insn("CALL\t%s", ast_as_id(ast->fn)->id);

	while (narg > 0)
	{
		int b = call_regs[--narg];
		insn("POP\t%s", reg_name(b));
	}

	int r = REG_RAX;

	if (st->regs[r] & ALLOCD)
	{
		r = reg_alloc(st);
		insn("MOV\t%s, %s", reg_name(REG_RAX), reg_name(r));
	}
	else
	{
		st->regs[r] |= ALLOCD;
	}

	for (int i = REG_MAX - 1; i >= 0; i--)
	{
		if (i != r && (st->regs[i] & ALLOCD))
		{
			insn("POP\t%s", reg_name(i));
		}
	}

	return r;
}

static int gen_eq(const ast_bin_t *ast, state_t *st)
{
	int a = gen_expr(ast->l, st);
	int b = gen_expr(ast->r, st);
	int r;

	insn("CMP\t%s, %s", reg_name(b), reg_name(a));

	reg_free(st, a);
	reg_free(st, b);

	r = reg_alloc(st);

	if (st->regs[REG_RAX] & ALLOCD)
	{
		insn("PUSH\t%%rax");
	}

	insn("SETE\t%%al");
	insn("MOVZX\t%%al, %s", reg_name(r));

	if (st->regs[REG_RAX] & ALLOCD)
	{
		insn("POP\t%%rax");
	}

	return r;
}

static int gen_lt(const ast_bin_t *ast, state_t *st)
{
	int a = gen_expr(ast->l, st);
	int b = gen_expr(ast->r, st);
	int r;

	insn("CMP\t%s, %s", reg_name(b), reg_name(a));

	reg_free(st, a);
	reg_free(st, b);

	r = reg_alloc(st);

	if (st->regs[REG_RAX] & ALLOCD)
	{
		insn("PUSH\t%%rax");
	}

	insn("SETL\t%%al");
	insn("MOVZX\t%%al, %s", reg_name(r));

	if (st->regs[REG_RAX] & ALLOCD)
	{
		insn("POP\t%%rax");
	}

	return r;
}

static int gen_sum(const ast_bin_t *ast, state_t *st)
{
	int a = gen_expr(ast->l, st);
	int b = gen_expr(ast->r, st);
	int r = reg_realloc2(st, &a, &b);

	insn("ADD\t%s, %s", reg_name(b), reg_name(r));

	reg_free(st, b);

	return r;
}

static int gen_diff(const ast_bin_t *ast, state_t *st)
{
	int a = gen_expr(ast->l, st);
	int b = gen_expr(ast->r, st);
	int r = reg_realloc(st, &a);

	insn("SUB\t%s, %s", reg_name(b), reg_name(r));

	reg_free(st, b);

	return r;
}

static int gen_expr(const ast_t *ast, state_t *st)
{
	switch (ast->var)
	{
		case AST_CONST	: return gen_const(ast_as_const(ast), st);
		case AST_ID	: return gen_id(ast_as_id(ast), st);
		case AST_CALL	: return gen_call(ast_as_call(ast), st);
		case AST_EQ	: return gen_eq(ast_as_bin(ast), st);
		case AST_LT	: return gen_lt(ast_as_bin(ast), st);
		case AST_SUM	: return gen_sum(ast_as_bin(ast), st);
		case AST_DIFF	: return gen_diff(ast_as_bin(ast), st);
		default		: return -1;
	}
}

static int gen_block(const ast_block_t *ast, state_t *st)
{
	const ast_t *stmt = ast->stmt;

	while (stmt != NULL)
	{
		int r = gen_stmt(stmt, st);

		if (r != REG_INV)
		{
			reg_free(st, r);
		}

		stmt = stmt->next;
	}

	return REG_INV;
}

static int gen_if(const ast_if_t *ast, state_t *st)
{
	int a = -1;
	int b = -1;
	int r = gen_expr(ast->expr, st);

	insn("TEST\t%s, %s", reg_name(r), reg_name(r));

	reg_free(st, r);

	a = lbl_alloc(st);

	if (ast->f_stmt != NULL)
	{
		b = lbl_alloc(st);
	}

	insn("JZ\t%s", lbl_name(a));

	gen_stmt(ast->t_stmt, st);
	if (ast->f_stmt != NULL)
	{
		insn("JMP\t%s", lbl_name(b));
	}

	labl("%s", lbl_name(a));
	if (ast->f_stmt != NULL)
	{
		gen_stmt(ast->f_stmt, st);
		labl("%s", lbl_name(b));
	}

	return REG_INV;
}

static int gen_ret(const ast_ret_t *ast, state_t *st)
{
	if (ast->expr != NULL)
	{
		int r = gen_expr(ast->expr, st);

		if (r != REG_RAX)
		{
			insn("MOV\t%s, %%rax", reg_name(r));
		}

		reg_free(st, r);
	}

	insn("RET");

	return REG_RAX;
}

static int gen_stmt(const ast_t *ast, state_t *st)
{
	switch (ast->var)
	{
		case AST_BLOCK	: return gen_block(ast_as_block(ast), st);
		case AST_IF	: return gen_if(ast_as_if(ast), st);
		case AST_RET	: return gen_ret(ast_as_ret(ast), st);
		default		: return gen_expr(ast, st);
	}
}

static int gen_fn(const ast_fn_t *ast, state_t *st)
{
	const char *id = ast_as_id(ast->id)->id;

	insn(".globl\t%s", id);
	insn(".type\t%s, @function", id);
	labl("%s", id);

	state_t fn_st;
	state_init(&fn_st);
	fn_st.lbl = st->lbl;

	int narg = 0;
	ast_t *arg = ast->arg;
	while (arg != NULL)
	{
		def_add(&fn_st, ast_as_id(arg)->id, call_regs[narg++]);

		arg = arg->next;
	}

	gen_stmt(ast->body, &fn_st);

	insn("RET");
	insn(".size\t%s, . - %s", id, id);

	st->lbl = fn_st.lbl;

	state_dstr(&fn_st);

	return -1;
}

void gen(const ast_t *ast)
{
	insn(".section\t.rodata");
	endl();
	labl(".LC0");
	insn(".string\t\"%%lli\\n\"");
	endl();
	insn(".text");
	endl();
	insn(".type\tprint, @function");
	labl("print");
	insn("PUSH\t%%rdi");
	insn("PUSH\t%%rsi");
	insn("MOV\t%%rdi, %%rsi");
	insn("LEA\t.LC0(%%rip), %%rdi");
	insn("CALL\tprintf");
	insn("POP\t%%rsi");
	insn("POP\t%%rdi");
	insn("RET");
	insn(".size\tprint, . - print");
	endl();

	state_t st;
	state_init(&st);

	while (ast != NULL)
	{
		switch (ast->var)
		{
			case AST_FN	: gen_fn(ast_as_fn(ast), &st);	break;
			default		:				break;
		}

		endl();

		ast = ast->next;
	}

	state_dstr(&st);
}

