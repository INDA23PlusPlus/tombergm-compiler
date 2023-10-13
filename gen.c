#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
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

typedef enum
{
	VAL_VOID,
	VAL_CON,
	VAL_REG,
	VAL_MEM,
} val_var_t;

typedef struct
{
	int64_t	val;
} val_con_t;

typedef struct
{
	reg_t	reg;
} val_reg_t;

typedef struct
{
	reg_t	reg;
	int64_t	off;
} val_mem_t;

typedef struct
{
	val_var_t		var;
	union
	{
		val_con_t	con;
		val_reg_t	reg;
		val_mem_t	mem;
	};
} val_t;

static inline val_t val_void(void)
{
	val_t v;

	v.var = VAL_VOID;

	return v;
}

static inline val_t val_con(int val)
{
	val_t v;

	v.var = VAL_CON;
	v.con.val = val;

	return v;
}

static inline val_t val_reg(reg_t reg)
{
	val_t v;

	v.var = VAL_REG;
	v.reg.reg = reg;

	return v;
}

static inline val_t val_mem(reg_t reg, int64_t off)
{
	val_t v;

	v.var = VAL_MEM;
	v.mem.reg = reg;
	v.mem.off = off;

	return v;
}

static int val_eq(const val_t *a, const val_t *b)
{
	if (a->var != b->var)
	{
		return 0;
	}

	switch (a->var)
	{
		case VAL_VOID	: return 1;
		case VAL_CON	: return a->con.val == b->con.val;
		case VAL_REG	: return a->reg.reg == b->reg.reg;
		case VAL_MEM	:
		{
			return
				a->mem.reg == b->mem.reg	&&
				a->mem.off == b->mem.off	;
		}
	}

	return 0;
}

#define RESERV	1	/* Don't allocate for mutable temp */
#define ALLOCD	2	/* Allocated for temp */
#define NOCLOB	4	/* Save across calls, even if not allocd */

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

typedef enum
{
	CND_EQ,
	CND_NE,
	CND_LT,
	CND_LE,
	CND_GT,
	CND_GE,
	CND_INV = -1,
} cnd_t;

static cnd_t cnd_neg(cnd_t c)
{
	switch (c)
	{
		case CND_EQ	: return CND_NE;
		case CND_NE	: return CND_EQ;
		case CND_LT	: return CND_GE;
		case CND_LE	: return CND_GT;
		case CND_GT	: return CND_LE;
		case CND_GE	: return CND_LT;
		default		: return CND_INV;
	}
}

static const char *cnd_mnem[] =
{
	"E",
	"NE",
	"L",
	"LE",
	"G",
	"GE",
};

typedef struct def def_t;

struct def
{
	def_t *		next;
	const char *	id;
	val_t		val;
};

typedef struct state state_t;

struct state
{
	state_t *	next;
	def_t *		defs;
	int		regs[REG_MAX];
	int		lbl;
};

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

static void state_init(state_t *st, state_t *next)
{
	st->next = next;

	st->defs = NULL;

	if (next != NULL)
	{
		for (reg_t i = 0; i < REG_MAX; i++)
		{
			st->regs[i] = next->regs[i];
		}

		st->lbl = next->lbl;
	}
	else
	{
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
}

static void state_pop(state_t *st)
{
	while (st->defs != NULL)
	{
		def_t *next = st->defs->next;

		xfree(st->defs);

		st->defs = next;
	}

	if (st->next != NULL)
	{
		st->next->lbl = st->lbl;
	}
}

static void def_add(state_t *st, const char *id, val_t v)
{
	def_t *def = xmalloc(sizeof(def_t));

	def->id = id;
	def->val = v;

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

	if (st->next != NULL)
	{
		return def_lookup(st->next, id);
	}
	else
	{
		return NULL;
	}
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

static inline int reg_noclob(const state_t *st, reg_t r)
{
	return r != REG_INV && (st->regs[r] & NOCLOB) != 0;
}

static inline void reg_set_reserv(state_t *st, reg_t r)
{
	if (r != REG_INV)
	{
		st->regs[r] |= RESERV;
	}
}

static inline void reg_set_allocd(state_t *st, reg_t r)
{
	if (r != REG_INV)
	{
		st->regs[r] |= ALLOCD;
	}
}

static inline void reg_set_noclob(state_t *st, reg_t r)
{
	if (r != REG_INV)
	{
		st->regs[r] |= NOCLOB;
	}
}

static void reg_free(state_t *st, reg_t r)
{
	if (r != REG_INV)
	{
		st->regs[r] &= ~ALLOCD;
	}
}

static const char *val_asm(const val_t *v)
{
	static char buf[8][32];
	static int n = 0;

	char *s = buf[n];
	n = (n + 1) % 8;

	switch (v->var)
	{
		case VAL_VOID	: abort();
		case VAL_CON	:
		{
			sprintf(s, "$%" PRIi64, v->con.val);
		}			break;
		case VAL_REG	:
		{
			sprintf(s, "%s", reg_name(v->reg.reg));
		}			break;
		case VAL_MEM	:
		{
			if (v->mem.reg != REG_INV)
			{
				sprintf(s, "%" PRIi64 "(%s)", v->mem.off,
					reg_name(v->mem.reg));
			}
			else
			{
				sprintf(s, "%" PRIi64, v->mem.off);
			}
		}			break;
	}

	return s;
}

static void val_free(state_t *st, val_t *val)
{
	switch (val->var)
	{
		case VAL_REG	:
		{
			reg_free(st, val->reg.reg);
		}			break;
		default		:	break;
	}
}

static void gen_mov(const val_t *a, const val_t *b)
{
	val_t zero = val_con(0);

	if (val_eq(a, &zero) && b->var == VAL_REG)
	{
		insn("XOR\t%s, %s", val_asm(b), val_asm(b));
	}
	else
	{
		insn("MOV\t%s, %s", val_asm(a), val_asm(b));
	}
}

static val_t reg_realloc(state_t *st, val_t *a)
{
	if (a->var == VAL_REG && !reg_reserv(st, a->reg.reg))
	{
		return *a;
	}
	else
	{
		val_t v = val_reg(reg_alloc(st));
		gen_mov(a, &v);
		val_free(st, a);
		return v;
	}
}

static val_t reg_realloc2(state_t *st, val_t *a, val_t *b)
{
	if (a->var == VAL_REG && !reg_reserv(st, a->reg.reg))
	{
		return *a;
	}
	else if (b->var == VAL_REG && !reg_reserv(st, b->reg.reg))
	{
		val_t t = *a;
		*a = *b;
		*b = t;
		return *a;
	}
	else
	{
		val_t v = val_reg(reg_alloc(st));
		gen_mov(a, &v);
		val_free(st, a);
		return v;
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

static val_t gen_stmt(const ast_t *ast, state_t *st);
static val_t gen_expr(const ast_t *ast, state_t *st);

static val_t gen_const(const ast_const_t *ast, state_t *st)
{
	return val_con(ast->val);
}

static val_t gen_id(const ast_id_t *ast, state_t *st)
{
	def_t *def = def_lookup(st, ast->id);

	val_t v = def->val;

	if (v.var == VAL_REG)
	{
		reg_set_allocd(st, v.reg.reg);
	}

	return v;
}

static val_t gen_call(const ast_call_t *ast, state_t *st)
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
	val_t moved[ast->narg];
	while (arg != NULL)
	{
		val_t a = gen_expr(arg, st);
		val_t b = val_reg(call_regs[narg]);

		if (reg_noclob(st, b.reg.reg))
		{
			b = reg_realloc(st, &a);
		}
		else
		{
			if (!val_eq(&a, &b))
			{
				gen_mov(&a, &b);
			}

			val_free(st, &a);
		}

		moved[narg] = b;

		narg++;
		arg = arg->next;
	}

	for (reg_t i = 0; i < REG_MAX; i++)
	{
		if (reg_noclob(st, i))
		{
			insn("PUSH\t%s", reg_name(i));
		}
	}

	for (int i = 0; i < narg; i++)
	{
		val_t b = val_reg(call_regs[i]);

		if (!val_eq(&moved[i], &b))
		{
			gen_mov(&moved[i], &b);
			val_free(st, &moved[i]);
		}
	}

	insn("XOR\t%%rax, %%rax");
	insn("CALL\t%s", ast_as_id(ast->fn)->id);

	for (reg_t i = REG_MAX - 1; i >= 0; i--)
	{
		if (reg_noclob(st, i))
		{
			insn("POP\t%s", reg_name(i));
		}
	}

	val_t v = val_reg(REG_RAX);

	if (reg_allocd(st, v.reg.reg))
	{
		val_t t = val_reg(reg_alloc(st));
		gen_mov(&v, &t);
		v = t;
	}
	else
	{
		reg_set_allocd(st, v.reg.reg);
	}

	for (reg_t i = REG_MAX - 1; i >= 0; i--)
	{
		if (i != v.reg.reg && reg_allocd(st, i))
		{
			insn("POP\t%s", reg_name(i));
		}
	}

	return v;
}

static val_t gen_set(const ast_bin_t *ast, state_t *st)
{
	val_t b = gen_expr(ast->r, st);
	val_t a = gen_expr(ast->l, st);

	gen_mov(&b, &a);

	val_free(st, &b);

	return a;
}

static cnd_t gen_cmp_cnd(const ast_t *ast, state_t *st, cnd_t c);

static val_t gen_cmp(const ast_t *ast, state_t *st, cnd_t c)
{
	if (reg_allocd(st, REG_RAX))
	{
		insn("PUSH\t%%rax");
	}

	gen_cmp_cnd(ast, st, c);

	val_t v = val_reg(reg_alloc(st));

	insn("SET%s\t%%al", cnd_mnem[c]);
	insn("MOVZX\t%%al, %s", val_asm(&v));

	if (reg_allocd(st, REG_RAX))
	{
		insn("POP\t%%rax");
	}

	return v;
}

static val_t gen_sum(const ast_bin_t *ast, state_t *st)
{
	val_t a = gen_expr(ast->l, st);
	val_t b = gen_expr(ast->r, st);
	val_t r = reg_realloc2(st, &a, &b);

	insn("ADD\t%s, %s", val_asm(&b), val_asm(&r));

	val_free(st, &b);

	return r;
}

static val_t gen_diff(const ast_bin_t *ast, state_t *st)
{
	val_t a = gen_expr(ast->l, st);
	val_t b = gen_expr(ast->r, st);
	val_t r = reg_realloc(st, &a);

	insn("SUB\t%s, %s", val_asm(&b), val_asm(&r));

	val_free(st, &b);

	return r;
}

static val_t gen_muldiv(const ast_bin_t *ast, state_t *st, int mul, reg_t r)
{
	int rax_allocd = reg_allocd(st, REG_RAX);
	int rdx_allocd = reg_allocd(st, REG_RDX);

	if (rax_allocd)
	{
		insn("PUSH\t%%rax");
	}
	if (rdx_allocd)
	{
		insn("PUSH\t%%rdx");
	}

	val_t rax = val_reg(REG_RAX);
	val_t a = gen_expr(ast->l, st);
	val_t b = gen_expr(ast->r, st);

	if (val_eq(&b, &rax) && !val_eq(&a, &b))
	{
		if (mul)
		{
			val_t t = a;
			a = b;
			b = t;
		}
		else if (a.var != VAL_REG || reg_reserv(st, a.reg.reg))
		{
			val_free(st, &b);
			b = val_reg(reg_alloc(st));
			gen_mov(&rax, &b);
		}
		else
		{
			insn("XCHG\t%%rax, %s", val_asm(&a));
			val_t t = a;
			a = b;
			b = t;
		}
	}

	if (!val_eq(&a, &rax))
	{
		gen_mov(&a, &rax);
	}
	val_free(st, &a);

	if (b.var == VAL_CON)
	{
		val_t t = val_reg(reg_alloc(st));
		gen_mov(&b, &t);
		val_free(st, &b);
		b = t;
	}

	if (mul)
	{
		insn("IMUL\t%s", val_asm(&b));
	}
	else
	{
		insn("CQO");
		insn("IDIV\t%s", val_asm(&b));
	}
	val_free(st, &b);

	val_t v = val_reg(r);

	if (reg_allocd(st, r))
	{
		val_t t = val_reg(reg_alloc(st));
		gen_mov(&v, &t);
		val_free(st, &v);
		v = t;
	}
	else
	{
		reg_set_allocd(st, r);
	}

	if (rdx_allocd)
	{
		insn("POP\t%%rdx");
	}
	if (rax_allocd)
	{
		insn("POP\t%%rax");
	}

	return v;
}

static val_t gen_prod(const ast_bin_t *ast, state_t *st)
{
	return gen_muldiv(ast, st, 1, REG_RAX);
}

static val_t gen_quot(const ast_bin_t *ast, state_t *st)
{
	return gen_muldiv(ast, st, 0, REG_RAX);
}

static val_t gen_rem(const ast_bin_t *ast, state_t *st)
{
	return gen_muldiv(ast, st, 0, REG_RDX);
}

static val_t gen_expr(const ast_t *ast, state_t *st)
{
	switch (ast->var)
	{
		case AST_CONST	: return gen_const(ast_as_const(ast), st);
		case AST_ID	: return gen_id(ast_as_id(ast), st);
		case AST_CALL	: return gen_call(ast_as_call(ast), st);
		case AST_SET	: return gen_set(ast_as_bin(ast), st);
		case AST_EQ	: return gen_cmp(ast, st, CND_EQ);
		case AST_LT	: return gen_cmp(ast, st, CND_LT);
		case AST_SUM	: return gen_sum(ast_as_bin(ast), st);
		case AST_DIFF	: return gen_diff(ast_as_bin(ast), st);
		case AST_PROD	: return gen_prod(ast_as_bin(ast), st);
		case AST_QUOT	: return gen_quot(ast_as_bin(ast), st);
		case AST_REM	: return gen_rem(ast_as_bin(ast), st);
		default		: return val_void();
	}
}

static cnd_t gen_cmp_cnd(const ast_t *ast, state_t *st, cnd_t c)
{
	const ast_bin_t *bin = ast_as_bin(ast);

	val_t zero = val_con(0);
	val_t a = gen_expr(bin->l, st);
	val_t b = gen_expr(bin->r, st);

	int is_eqne = c == CND_EQ || c == CND_NE;
	int a_zero = val_eq(&a, &zero);
	int b_zero = val_eq(&b, &zero);
	if (is_eqne && (a_zero || b_zero))
	{
		val_t v;

		if (a_zero)
		{
			v = b;
		}
		else
		{
			v = a;
		}

		insn("TEST\t%s, %s", val_asm(&v), val_asm(&v));
	}
	else
	{
		insn("CMP\t%s, %s", val_asm(&b), val_asm(&a));
	}

	val_free(st, &a);
	val_free(st, &b);

	return c;
}

static cnd_t gen_expr_cnd(const ast_t *ast, state_t *st)
{
	switch (ast->var)
	{
		case AST_EQ	: return gen_cmp_cnd(ast, st, CND_EQ);
		case AST_LT	: return gen_cmp_cnd(ast, st, CND_LT);
		case AST_GT	: return gen_cmp_cnd(ast, st, CND_GT);
		default		: return CND_INV;
	}
}

static val_t gen_block(const ast_block_t *ast, state_t *st)
{
	const ast_t *stmt = ast->stmt;

	state_t block_st;
	state_init(&block_st, st);

	while (stmt != NULL)
	{
		val_t r = gen_stmt(stmt, &block_st);

		val_free(&block_st, &r);

		stmt = stmt->next;
	}

	state_pop(&block_st);

	return val_void();
}

static val_t gen_let(const ast_let_t *ast, state_t *st)
{
	const ast_id_t *id = ast_as_id(ast->id);
	const ast_t *expr = ast->expr;

	val_t v;

	if (expr != NULL)
	{
		val_t a = gen_expr(expr, st);

		v = reg_realloc(st, &a);
	}
	else
	{
		v = val_reg(reg_alloc(st));
	}

	def_add(st, id->id, v);

	reg_set_reserv(st, v.reg.reg);
	reg_set_noclob(st, v.reg.reg);

	return v;
}

static val_t gen_if(const ast_if_t *ast, state_t *st)
{
	int lbl_a = lbl_alloc(st);
	int lbl_b = -1;

	if (ast->f_stmt != NULL)
	{
		lbl_b = lbl_alloc(st);
	}

	cnd_t c = gen_expr_cnd(ast->expr, st);

	if (c == CND_INV)
	{
		val_t v = gen_expr(ast->expr, st);

		insn("TEST\t%s, %s", val_asm(&v), val_asm(&v));
		insn("JZ\t%s", lbl_name(lbl_a));

		val_free(st, &v);
	}
	else
	{
		insn("J%s\t%s", cnd_mnem[cnd_neg(c)], lbl_name(lbl_a));
	}

	{
		val_t v = gen_stmt(ast->t_stmt, st);
		val_free(st, &v);
	}

	if (ast->f_stmt != NULL)
	{
		insn("JMP\t%s", lbl_name(lbl_b));
	}

	labl("%s", lbl_name(lbl_a));
	if (ast->f_stmt != NULL)
	{
		{
			val_t v = gen_stmt(ast->f_stmt, st);
			val_free(st, &v);
		}
		labl("%s", lbl_name(lbl_b));
	}

	return val_void();
}

static val_t gen_while(const ast_while_t *ast, state_t *st)
{
	int lbl_a = lbl_alloc(st);
	int lbl_b = lbl_alloc(st);

	labl("%s", lbl_name(lbl_a));

	cnd_t c = gen_expr_cnd(ast->expr, st);

	if (c == CND_INV)
	{
		val_t v = gen_expr(ast->expr, st);

		insn("TEST\t%s, %s", val_asm(&v), val_asm(&v));
		insn("JZ\t%s", lbl_name(lbl_b));

		val_free(st, &v);
	}
	else
	{
		insn("J%s\t%s", cnd_mnem[cnd_neg(c)], lbl_name(lbl_b));
	}

	{
		val_t v = gen_stmt(ast->stmt, st);
		val_free(st, &v);
	}

	insn("JMP\t%s", lbl_name(lbl_a));

	labl("%s", lbl_name(lbl_b));

	return val_void();
}

static val_t gen_ret(const ast_ret_t *ast, state_t *st)
{
	val_t r = val_reg(REG_RAX);

	if (ast->expr != NULL)
	{
		val_t v = gen_expr(ast->expr, st);

		if (!val_eq(&v, &r))
		{
			gen_mov(&v, &r);
		}

		val_free(st, &v);
	}

	insn("RET");

	reg_set_allocd(st, r.reg.reg);

	return r;
}

static val_t gen_stmt(const ast_t *ast, state_t *st)
{
	switch (ast->var)
	{
		case AST_BLOCK	: return gen_block(ast_as_block(ast), st);
		case AST_LET	: return gen_let(ast_as_let(ast), st);
		case AST_IF	: return gen_if(ast_as_if(ast), st);
		case AST_WHILE	: return gen_while(ast_as_while(ast), st);
		case AST_RET	: return gen_ret(ast_as_ret(ast), st);
		default		: return gen_expr(ast, st);
	}
}

static val_t gen_fn(const ast_fn_t *ast, state_t *st)
{
	const char *id = ast_as_id(ast->id)->id;

	insn(".globl\t%s", id);
	insn(".type\t%s, @function", id);
	labl("%s", id);

	state_t fn_st;
	state_init(&fn_st, st);

	int narg = 0;
	ast_t *arg = ast->arg;
	while (arg != NULL)
	{
		val_t v = val_reg(call_regs[narg]);

		def_add(&fn_st, ast_as_id(arg)->id, v);

		reg_set_reserv(&fn_st, v.reg.reg);
		reg_set_noclob(&fn_st, v.reg.reg);

		narg++;
		arg = arg->next;
	}

	{
		val_t v = gen_stmt(ast->body, &fn_st);
		val_free(st, &v);
	}

	insn("RET");
	insn(".size\t%s, . - %s", id, id);

	state_pop(&fn_st);

	return val_void();
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
	insn("MOV\t%%rdi, %%rsi");
	insn("LEA\t.LC0(%%rip), %%rdi");
	insn("JMP\tprintf");
	insn(".size\tprint, . - print");

	state_t st;
	state_init(&st, NULL);

	while (ast != NULL)
	{
		endl();

		switch (ast->var)
		{
			case AST_FN	: gen_fn(ast_as_fn(ast), &st);	break;
			default		:				break;
		}

		ast = ast->next;
	}

	state_pop(&st);
}
