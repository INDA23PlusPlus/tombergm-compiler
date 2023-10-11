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

static reg_t call_regs[] =
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
	reg_t		reg;
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

static void state_init(state_t *st)
{
	st->defs = NULL;

	for (reg_t i = 0; i < REG_MAX; i++)
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

static void state_dstr(state_t *st)
{
	while (st->defs != NULL)
	{
		def_t *next = st->defs->next;

		xfree(st->defs);

		st->defs = next;
	}
}

static void def_add(state_t *st, const char *id, reg_t r)
{
	def_t *def = xmalloc(sizeof(def_t));

	def->id = id;
	def->reg = r;

	def->next = st->defs;
	st->defs = def;
}

static def_t *def_lookup(const state_t *st, const char *id)
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

static const char *reg_name(reg_t r)
{
	if (r < 0 || r >= REG_MAX)
	{
		abort();
	}

	return reg_names[r];
}

static reg_t reg_alloc(state_t *st)
{
	for (reg_t i = 0; i < REG_MAX; i++)
	{
		if (st->regs[i] == 0)
		{
			st->regs[i] |= ALLOCD;

			return i;
		}
	}

	return REG_INV;
}

static inline int reg_allocd(const state_t *st, reg_t r)
{
	return r != REG_INV && (st->regs[r] & ALLOCD) != 0;
}

static inline int reg_reserv(const state_t *st, reg_t r)
{
	return r != REG_INV && (st->regs[r] & RESERV) != 0;
}

static inline void reg_set_allocd(state_t *st, reg_t r)
{
	if (r != REG_INV)
	{
		st->regs[r] |= ALLOCD;
	}
}

static void reg_free(state_t *st, reg_t r)
{
	if (r != REG_INV)
	{
		st->regs[r] &= ~ALLOCD;
	}
}

static reg_t reg_realloc(state_t *st, reg_t *a)
{
	if (!reg_reserv(st, *a))
	{
		return *a;
	}
	else
	{
		reg_t r = reg_alloc(st);
		insn("MOV\t%s, %s", reg_name(*a), reg_name(r));
		reg_free(st, *a);
		return r;
	}
}

static reg_t reg_realloc2(state_t *st, reg_t *a, reg_t *b)
{
	if (!reg_reserv(st, *a))
	{
		return *a;
	}
	else if (!reg_reserv(st, *b))
	{
		reg_t t = *a;
		*a = *b;
		*b = t;
		return *a;
	}
	else
	{
		reg_t r = reg_alloc(st);
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

static reg_t gen_stmt(const ast_t *ast, state_t *st);
static reg_t gen_expr(const ast_t *ast, state_t *st);

static reg_t gen_const(const ast_const_t *ast, state_t *st)
{
	reg_t r = reg_alloc(st);

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

static reg_t gen_id(const ast_id_t *ast, state_t *st)
{
	def_t *def = def_lookup(st, ast->id);

	reg_set_allocd(st, def->reg);

	return def->reg;
}

static reg_t gen_call(const ast_call_t *ast, state_t *st)
{
	if (ast->fn->var != AST_ID)
	{
		abort();
	}

	for (reg_t i = 0; i < REG_MAX; i++)
	{
		if (reg_allocd(st, i))
		{
			insn("PUSH\t%s", reg_name(i));
		}
	}

	int narg = 0;
	ast_t *arg = ast->arg;
	reg_t moved[ast->narg];
	while (arg != NULL)
	{
		reg_t a = gen_expr(arg, st);
		reg_t b = call_regs[narg];
		insn("PUSH\t%s", reg_name(b));
		if (b != a)
		{
			if (reg_allocd(st, b))
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
		reg_t b = call_regs[i];

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
		reg_t b = call_regs[--narg];
		insn("POP\t%s", reg_name(b));
	}

	reg_t r = REG_RAX;

	if (reg_allocd(st, r))
	{
		r = reg_alloc(st);
		insn("MOV\t%s, %s", reg_name(REG_RAX), reg_name(r));
	}
	else
	{
		reg_set_allocd(st, r);
	}

	for (reg_t i = REG_MAX - 1; i >= 0; i--)
	{
		if (i != r && reg_allocd(st, i))
		{
			insn("POP\t%s", reg_name(i));
		}
	}

	return r;
}

static reg_t gen_set(const ast_bin_t *ast, state_t *st)
{
	reg_t a = gen_expr(ast->l, st);
	reg_t b = gen_expr(ast->r, st);

	insn("MOV\t%s, %s", reg_name(b), reg_name(a));

	reg_free(st, b);

	return a;
}

static reg_t gen_eq(const ast_bin_t *ast, state_t *st)
{
	if (reg_allocd(st, REG_RAX))
	{
		insn("PUSH\t%%rax");
	}

	reg_t a = gen_expr(ast->l, st);
	reg_t b = gen_expr(ast->r, st);
	reg_t r;

	insn("CMP\t%s, %s", reg_name(b), reg_name(a));

	reg_free(st, a);
	reg_free(st, b);

	r = reg_alloc(st);

	insn("SETE\t%%al");
	insn("MOVZX\t%%al, %s", reg_name(r));

	if (reg_allocd(st, REG_RAX))
	{
		insn("POP\t%%rax");
	}

	return r;
}

static reg_t gen_lt(const ast_bin_t *ast, state_t *st)
{
	if (reg_allocd(st, REG_RAX))
	{
		insn("PUSH\t%%rax");
	}

	reg_t a = gen_expr(ast->l, st);
	reg_t b = gen_expr(ast->r, st);
	reg_t r;

	insn("CMP\t%s, %s", reg_name(b), reg_name(a));

	reg_free(st, a);
	reg_free(st, b);

	r = reg_alloc(st);

	insn("SETL\t%%al");
	insn("MOVZX\t%%al, %s", reg_name(r));

	if (reg_allocd(st, REG_RAX))
	{
		insn("POP\t%%rax");
	}

	return r;
}

static reg_t gen_sum(const ast_bin_t *ast, state_t *st)
{
	reg_t a = gen_expr(ast->l, st);
	reg_t b = gen_expr(ast->r, st);
	reg_t r = reg_realloc2(st, &a, &b);

	insn("ADD\t%s, %s", reg_name(b), reg_name(r));

	reg_free(st, b);

	return r;
}

static reg_t gen_diff(const ast_bin_t *ast, state_t *st)
{
	reg_t a = gen_expr(ast->l, st);
	reg_t b = gen_expr(ast->r, st);
	reg_t r = reg_realloc(st, &a);

	insn("SUB\t%s, %s", reg_name(b), reg_name(r));

	reg_free(st, b);

	return r;
}

static reg_t gen_prod(const ast_bin_t *ast, state_t *st)
{
	if (reg_allocd(st, REG_RAX))
	{
		insn("PUSH\t%%rax");
	}
	if (reg_allocd(st, REG_RDX))
	{
		insn("PUSH\t%%rdx");
	}

	reg_t a = gen_expr(ast->l, st);
	reg_t b = gen_expr(ast->r, st);
	reg_t r;

	if (b == REG_RAX)
	{
		reg_t t = a;
		a = b;
		b = t;
	}

	if (a != REG_RAX)
	{
		insn("MOV\t%s, %%rax", reg_name(a));
	}
	reg_free(st, a);

	insn("IMUL\t%s", reg_name(b));
	reg_free(st, b);

	if (reg_allocd(st, REG_RDX))
	{
		insn("POP\t%%rdx");
	}
	if (reg_allocd(st, REG_RAX))
	{
		r = reg_alloc(st);
		insn("MOV\t%%rax, %s", reg_name(r));

		insn("POP\t%%rax");
	}
	else
	{
		r = REG_RAX;
		reg_set_allocd(st, r);
	}

	return r;
}

static reg_t gen_quot(const ast_bin_t *ast, state_t *st)
{
	if (reg_allocd(st, REG_RAX))
	{
		insn("PUSH\t%%rax");
	}
	if (reg_allocd(st, REG_RDX))
	{
		insn("PUSH\t%%rdx");
	}

	reg_t a = gen_expr(ast->l, st);
	reg_t b = gen_expr(ast->r, st);
	reg_t r;

	if (b == REG_RAX)
	{
		b = reg_alloc(st);
		insn("MOV\t%%rax, %s", reg_name(b));
		reg_free(st, REG_RAX);
	}

	if (a != REG_RAX)
	{
		insn("MOV\t%s, %%rax", reg_name(a));
	}
	reg_free(st, a);

	insn("CQO");
	insn("IDIV\t%s", reg_name(b));
	reg_free(st, b);

	if (reg_allocd(st, REG_RDX))
	{
		insn("POP\t%%rdx");
	}
	if (reg_allocd(st, REG_RAX))
	{
		r = reg_alloc(st);
		insn("MOV\t%%rax, %s", reg_name(r));

		insn("POP\t%%rax");
	}
	else
	{
		r = REG_RAX;
		reg_set_allocd(st, r);
	}

	return r;
}

static reg_t gen_expr(const ast_t *ast, state_t *st)
{
	switch (ast->var)
	{
		case AST_CONST	: return gen_const(ast_as_const(ast), st);
		case AST_ID	: return gen_id(ast_as_id(ast), st);
		case AST_CALL	: return gen_call(ast_as_call(ast), st);
		case AST_SET	: return gen_set(ast_as_bin(ast), st);
		case AST_EQ	: return gen_eq(ast_as_bin(ast), st);
		case AST_LT	: return gen_lt(ast_as_bin(ast), st);
		case AST_SUM	: return gen_sum(ast_as_bin(ast), st);
		case AST_DIFF	: return gen_diff(ast_as_bin(ast), st);
		case AST_PROD	: return gen_prod(ast_as_bin(ast), st);
		case AST_QUOT	: return gen_quot(ast_as_bin(ast), st);
		default		: return REG_INV;
	}
}

static reg_t gen_block(const ast_block_t *ast, state_t *st)
{
	const ast_t *stmt = ast->stmt;

	while (stmt != NULL)
	{
		reg_t r = gen_stmt(stmt, st);

		reg_free(st, r);

		stmt = stmt->next;
	}

	return REG_INV;
}

static reg_t gen_if(const ast_if_t *ast, state_t *st)
{
	int lbl_a = -1;
	int lbl_b = -1;
	reg_t r = gen_expr(ast->expr, st);

	insn("TEST\t%s, %s", reg_name(r), reg_name(r));

	reg_free(st, r);

	lbl_a = lbl_alloc(st);

	if (ast->f_stmt != NULL)
	{
		lbl_b = lbl_alloc(st);
	}

	insn("JZ\t%s", lbl_name(lbl_a));

	gen_stmt(ast->t_stmt, st);
	if (ast->f_stmt != NULL)
	{
		insn("JMP\t%s", lbl_name(lbl_b));
	}

	labl("%s", lbl_name(lbl_a));
	if (ast->f_stmt != NULL)
	{
		gen_stmt(ast->f_stmt, st);
		labl("%s", lbl_name(lbl_b));
	}

	return REG_INV;
}

static reg_t gen_while(const ast_while_t *ast, state_t *st)
{
	int lbl_a = lbl_alloc(st);
	int lbl_b = lbl_alloc(st);
	reg_t r;
	reg_t s;

	labl("%s", lbl_name(lbl_a));

	r = gen_expr(ast->expr, st);

	insn("TEST\t%s, %s", reg_name(r), reg_name(r));

	reg_free(st, r);

	insn("JZ\t%s", lbl_name(lbl_b));

	s = gen_stmt(ast->stmt, st);

	reg_free(st, s);

	insn("JMP\t%s", lbl_name(lbl_a));

	labl("%s", lbl_name(lbl_b));

	return REG_INV;
}

static reg_t gen_ret(const ast_ret_t *ast, state_t *st)
{
	if (ast->expr != NULL)
	{
		reg_t r = gen_expr(ast->expr, st);

		if (r != REG_RAX)
		{
			insn("MOV\t%s, %%rax", reg_name(r));
		}

		reg_free(st, r);
	}

	insn("RET");

	return REG_RAX;
}

static reg_t gen_stmt(const ast_t *ast, state_t *st)
{
	switch (ast->var)
	{
		case AST_BLOCK	: return gen_block(ast_as_block(ast), st);
		case AST_IF	: return gen_if(ast_as_if(ast), st);
		case AST_WHILE	: return gen_while(ast_as_while(ast), st);
		case AST_RET	: return gen_ret(ast_as_ret(ast), st);
		default		: return gen_expr(ast, st);
	}
}

static reg_t gen_fn(const ast_fn_t *ast, state_t *st)
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

	return REG_INV;
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

