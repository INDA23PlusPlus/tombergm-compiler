#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ast.h"
#include "err.h"
#include "misc.h"
#include "xmalloc.h"

#define fatal(where, var, ...) \
({ \
	where_t __fatal_where = (where); \
	__typeof__(err_ ## var(__fatal_where, __VA_ARGS__)) \
	__fatal_err = err_ ## var(__fatal_where, __VA_ARGS__); \
	err_print(&__fatal_err.err); \
	exit(EXIT_FAILURE); \
})

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

static inline val_t val_con(int64_t val)
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

static inline int val_is_void(const val_t *v)
{
	return v !=NULL && v->var == VAL_VOID;
}

static inline int val_is_con(const val_t *v)
{
	return v != NULL && v->var == VAL_CON;
}

static inline int val_is_reg(const val_t *v)
{
	return v != NULL && v->var == VAL_REG;
}

static inline int val_is_mem(const val_t *v)
{
	return v != NULL && v->var == VAL_MEM;
}

static int val_eq(const val_t *a, const val_t *b)
{
	if (a == NULL || b == NULL)
	{
		return 0;
	}

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
	CND_T,
	CND_F,
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
		case CND_T	: return CND_F;
		case CND_F	: return CND_T;
		default		: return CND_INV;
	}
}

static cnd_t cnd_rev(cnd_t c)
{
	switch (c)
	{
		case CND_EQ	: return CND_EQ;
		case CND_NE	: return CND_NE;
		case CND_LT	: return CND_GT;
		case CND_LE	: return CND_GE;
		case CND_GT	: return CND_LT;
		case CND_GE	: return CND_LE;
		case CND_T	: return CND_T;
		case CND_F	: return CND_F;
		default		: return CND_INV;
	}
}

static int cnd_is_con(cnd_t c)
{
	switch (c)
	{
		case CND_T	:
		case CND_F	: return 1;
		default		: return 0;
	}
}

static cnd_t ast_cnd(ast_var_t var)
{
	switch (var)
	{
		case AST_EQ	: return CND_EQ;
		case AST_NE	: return CND_NE;
		case AST_LT	: return CND_LT;
		case AST_LE	: return CND_LE;
		case AST_GT	: return CND_GT;
		case AST_GE	: return CND_GE;
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

	{
		fprintf(stderr, "register allocation failed, aborting\n");
		exit(EXIT_FAILURE);
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

	if (val_eq(a, b))
	{
	}
	else if (val_eq(a, &zero) && val_is_reg(b))
	{
		insn("XORQ\t%s, %s", val_asm(b), val_asm(b));
	}
	else
	{
		insn("MOVQ\t%s, %s", val_asm(a), val_asm(b));
	}
}

static val_t reg_realloc(state_t *st, val_t *a, val_t *d)
{
	if (val_is_reg(a) && val_eq(a, d))
	{
		return *a;
	}
	else if (val_is_reg(a) && !reg_reserv(st, a->reg.reg))
	{
		return *a;
	}
	else
	{
		val_t v = val_reg(reg_alloc(st));
		if (a != NULL)
		{
			gen_mov(a, &v);
			val_free(st, a);
		}
		return v;
	}
}

static val_t reg_realloc2(state_t *st, val_t *a, val_t *b, val_t *d)
{
	if (val_is_reg(a) && val_eq(a, d))
	{
		return *a;
	}
	else if (val_is_reg(b) && val_eq(b, d))
	{
		val_t t = *a;
		*a = *b;
		*b = t;
		return *a;
	}
	else if (val_is_reg(a) && !reg_reserv(st, a->reg.reg))
	{
		return *a;
	}
	else if (val_is_reg(b) && !reg_reserv(st, b->reg.reg))
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
static val_t gen_expr(const ast_t *ast, state_t *st, val_t *d);

static val_t gen_const(const ast_const_t *ast, state_t *st, val_t *d)
{
	return val_con(ast->val);
}

static val_t gen_id(const ast_id_t *ast, state_t *st, val_t *d)
{
	def_t *def = def_lookup(st, ast->id);

	if (def == NULL)
	{
		fatal(ast->ast.where, oth, "use of undeclared identifier");
	}

	val_t v = def->val;

	if (val_is_reg(&v))
	{
		reg_set_allocd(st, v.reg.reg);
	}

	return v;
}

static val_t gen_sqrt(const ast_call_t *ast, state_t *st, val_t *d)
{
	if (ast->narg != 1)
	{
		fatal(ast->ast.where, oth, "sqrt takes exactly one argument");
	}

	ast_t *arg = ast->arg;
	val_t a = gen_expr(arg, st, NULL);
	val_t v = reg_realloc(st, d, d);

	insn("CVTSI2SD\t%s, %%xmm0", val_asm(&a));
	insn("SQRTSD\t%%xmm0, %%xmm0");
	insn("CVTTSD2SI\t%%xmm0, %s", val_asm(&v));

	val_free(st, &a);

	return v;
}

static val_t gen_call(const ast_call_t *ast, state_t *st, val_t *d)
{
	if (ast->fn->var != AST_ID)
	{
		fatal(ast->fn->where, oth, "expression is not callable");
	}

	if (strcmp(ast_as_id(ast->fn)->id, "sqrt") == 0)
	{
		return gen_sqrt(ast, st, d);
	}

	if (ast->narg > 6)
	{
		fatal(ast->ast.where, oth, "too many arguments given");
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
		val_t b = val_reg(call_regs[narg]);

		if (reg_noclob(st, b.reg.reg))
		{
			val_t a = gen_expr(arg, st, NULL);
			b = reg_realloc(st, &a, NULL);
		}
		else
		{
			val_t a = gen_expr(arg, st, &b);
			gen_mov(&a, &b);
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

	insn("XORQ\t%%rax, %%rax");
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

static void pick_lreg(const state_t *st, val_t *r, const char **l, val_t *d)
{
	struct
	{
		reg_t		reg;
		const char *	lreg;
	}
	lregs[] =
	{
		{REG_RAX, "%al"},
		{REG_RBX, "%bl"},
		{REG_RCX, "%cl"},
		{REG_RDX, "%dl"},
	};

	int k = 0;
	for (int i = 0; i < ARRAY_SIZE(lregs); i++)
	{
		val_t r = val_reg(lregs[i].reg);

		if (val_eq(&r, d) || !reg_allocd(st, lregs[i].reg))
		{
			k = i;
			break;
		}
	}

	*r = val_reg(lregs[k].reg);
	*l = lregs[k].lreg;
}

static cnd_t gen_expr_cnd(const ast_t *ast, state_t *st);

static val_t gen_lnot(const ast_t *ast, state_t *st, val_t *d)
{
	cnd_t c = cnd_neg(gen_expr_cnd(ast, st));
	val_t v = reg_realloc(st, d, d);

	if (c == CND_T)
	{
		insn("MOVQ\t$1, %s", val_asm(&v));
	}
	else if (c == CND_F)
	{
		insn("XORQ\t%s, %s", val_asm(&v), val_asm(&v));
	}
	else
	{
		val_t r;
		const char *l;
		pick_lreg(st, &r, &l, &v);

		if (reg_allocd(st, r.reg.reg))
		{
			insn("PUSH\t%s", val_asm(&r));
		}

		insn("SET%s\t%s", cnd_mnem[c], l);
		insn("MOVZX\t%s, %s", l, val_asm(&v));

		if (reg_allocd(st, r.reg.reg))
		{
			insn("POP\t%s", val_asm(&r));
		}
	}

	return v;
}

static val_t gen_bnot(const ast_un_t *ast, state_t *st, val_t *d)
{
	val_t a = gen_expr(ast->expr, st, d);

	if (val_is_con(&a))
	{
		return val_con(~a.con.val);
	}

	val_t v = reg_realloc(st, &a, d);

	insn("NOTQ\t%s", val_asm(&v));

	if (!val_eq(&a, &v))
	{
		val_free(st, &a);
	}

	return v;
}

static val_t gen_set(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a = gen_expr(ast->l, st, d);
	val_t b = gen_expr(ast->r, st, &a);

	if (val_is_con(&a))
	{
		fatal(ast->l->where, oth, "lvalue expected");
	}

	gen_mov(&b, &a);

	if (!val_eq(&a, &b))
	{
		val_free(st, &b);
	}

	return a;
}

static cnd_t gen_cmp_cnd(const ast_t *ast, state_t *st, cnd_t c);

static val_t gen_cmp(const ast_t *ast, state_t *st, cnd_t c, val_t *d)
{
	c = gen_cmp_cnd(ast, st, c);

	val_t v = reg_realloc(st, d, d);

	if (c == CND_T)
	{
		insn("MOVQ\t$1, %s", val_asm(&v));
	}
	else if (c == CND_F)
	{
		insn("XORQ\t%s, %s", val_asm(&v), val_asm(&v));
	}
	else
	{
		val_t r;
		const char *l;
		pick_lreg(st, &r, &l, &v);

		if (reg_allocd(st, r.reg.reg))
		{
			insn("PUSH\t%s", val_asm(&r));
		}

		insn("SET%s\t%s", cnd_mnem[c], l);
		insn("MOVZX\t%s, %s", l, val_asm(&v));

		if (reg_allocd(st, r.reg.reg))
		{
			insn("POP\t%s", val_asm(&r));
		}
	}

	return v;
}

static val_t gen_land(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t v = reg_realloc(st, d, d);
	int lbl = lbl_alloc(st);

	insn("XORQ\t%s, %s", val_asm(&v), val_asm(&v));

	cnd_t a = gen_expr_cnd(ast->l, st);

	if (a == CND_T)
	{
	}
	else if (a == CND_F)
	{
		return v;
	}
	else
	{
		insn("J%s\t%s", cnd_mnem[cnd_neg(a)], lbl_name(lbl));
	}

	cnd_t b = gen_expr_cnd(ast->r, st);

	if (cnd_is_con(b))
	{
		if (b == CND_T)
		{
			insn("INCQ\t%s", val_asm(&v));
		}
	}
	else
	{
		val_t r;
		const char *l;
		pick_lreg(st, &r, &l, &v);

		if (!val_eq(&r, &v) && reg_allocd(st, r.reg.reg))
		{
			insn("PUSH\t%s", val_asm(&r));
		}

		insn("SET%s\t%s", cnd_mnem[b], l);
		insn("MOVZX\t%s, %s", l, val_asm(&v));

		if (!val_eq(&r, &v) && reg_allocd(st, r.reg.reg))
		{
			insn("POP\t%s", val_asm(&r));
		}
	}

	labl("%s", lbl_name(lbl));

	return v;
}

static val_t gen_lor(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t v = reg_realloc(st, d, d);
	int lbl = lbl_alloc(st);

	insn("MOVQ\t$1, %s", val_asm(&v));

	cnd_t a = gen_expr_cnd(ast->l, st);

	if (a == CND_T)
	{
		return v;
	}
	else if (a == CND_F)
	{
	}
	else
	{
		insn("J%s\t%s", cnd_mnem[a], lbl_name(lbl));
	}

	cnd_t b = gen_expr_cnd(ast->r, st);

	if (cnd_is_con(b))
	{
		if (b == CND_F)
		{
			insn("DECQ\t%s", val_asm(&v));
		}
	}
	else
	{
		val_t r;
		const char *l;
		pick_lreg(st, &r, &l, &v);

		if (!val_eq(&r, &v) && reg_allocd(st, r.reg.reg))
		{
			insn("PUSH\t%s", val_asm(&r));
		}

		insn("SET%s\t%s", cnd_mnem[b], l);
		insn("MOVZX\t%s, %s", l, val_asm(&v));

		if (!val_eq(&r, &v) && reg_allocd(st, r.reg.reg))
		{
			insn("POP\t%s", val_asm(&r));
		}
	}

	labl("%s", lbl_name(lbl));

	return v;
}

static val_t gen_sum(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a;
	val_t b;

	a = gen_expr(ast->l, st, d);
	if (!val_eq(&a, d))
	{
		b = gen_expr(ast->r, st, d);
	}
	else
	{
		b = gen_expr(ast->r, st, NULL);
	}

	if (val_is_con(&a) && val_is_con(&b))
	{
		return val_con(a.con.val + b.con.val);
	}

	val_t v = reg_realloc2(st, &a, &b, d);

	insn("ADDQ\t%s, %s", val_asm(&b), val_asm(&v));

	if (!val_eq(&b, &v))
	{
		val_free(st, &b);
	}

	return v;
}

static val_t gen_diff(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a = gen_expr(ast->l, st, d);
	val_t b = gen_expr(ast->r, st, NULL);

	if (val_is_con(&a) && val_is_con(&b))
	{
		return val_con(a.con.val - b.con.val);
	}

	val_t v = reg_realloc(st, &a, d);

	insn("SUBQ\t%s, %s", val_asm(&b), val_asm(&v));

	if (!val_eq(&b, &v))
	{
		val_free(st, &b);
	}

	return v;
}

static val_t gen_muldiv(const ast_bin_t *ast, state_t *st, val_t *d,
			int mul, reg_t r)
{
	int rax_allocd = reg_allocd(st, REG_RAX);
	int rdx_allocd = reg_allocd(st, REG_RDX);

	val_t a = gen_expr(ast->l, st, NULL);
	val_t b = gen_expr(ast->r, st, NULL);

	if (val_is_con(&a) && val_is_con(&b))
	{
		if (mul)
		{
			if (r == REG_RAX)
			{
				return val_con(a.con.val * b.con.val);
			}
		}
		else if (b.con.val != 0)
		{
			if (r == REG_RAX)
			{
				return val_con(a.con.val / b.con.val);
			}
			else if (r == REG_RDX)
			{
				return val_con(a.con.val % b.con.val);
			}
		}
	}

	if (rax_allocd)
	{
		insn("PUSH\t%%rax");
	}
	if (rdx_allocd)
	{
		insn("PUSH\t%%rdx");
	}

	val_t rax = val_reg(REG_RAX);

	if (val_eq(&b, &rax) && !val_eq(&a, &b))
	{
		if (mul)
		{
			val_t t = a;
			a = b;
			b = t;
		}
		else if (!val_is_reg(&a) || reg_reserv(st, a.reg.reg))
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

	gen_mov(&a, &rax);
	val_free(st, &a);

	if (val_is_con(&b))
	{
		val_t t = val_reg(reg_alloc(st));
		gen_mov(&b, &t);
		val_free(st, &b);
		b = t;
	}

	if (mul)
	{
		insn("IMULQ\t%s", val_asm(&b));
	}
	else
	{
		insn("CQO");
		insn("IDIVQ\t%s", val_asm(&b));
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

static val_t gen_prod(const ast_bin_t *ast, state_t *st, val_t *d)
{
	return gen_muldiv(ast, st, d, 1, REG_RAX);
}

static val_t gen_quot(const ast_bin_t *ast, state_t *st, val_t *d)
{
	return gen_muldiv(ast, st, d, 0, REG_RAX);
}

static val_t gen_rem(const ast_bin_t *ast, state_t *st, val_t *d)
{
	return gen_muldiv(ast, st, d, 0, REG_RDX);
}

static val_t gen_band(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a;
	val_t b;

	a = gen_expr(ast->l, st, d);
	if (!val_eq(&a, d))
	{
		b = gen_expr(ast->r, st, d);
	}
	else
	{
		b = gen_expr(ast->r, st, NULL);
	}

	if (val_is_con(&a) && val_is_con(&b))
	{
		return val_con(a.con.val & b.con.val);
	}

	val_t v = reg_realloc2(st, &a, &b, d);

	insn("ANDQ\t%s, %s", val_asm(&b), val_asm(&v));

	if (!val_eq(&b, &v))
	{
		val_free(st, &b);
	}

	return v;
}

static val_t gen_bor(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a;
	val_t b;

	a = gen_expr(ast->l, st, d);
	if (!val_eq(&a, d))
	{
		b = gen_expr(ast->r, st, d);
	}
	else
	{
		b = gen_expr(ast->r, st, NULL);
	}

	if (val_is_con(&a) && val_is_con(&b))
	{
		return val_con(a.con.val | b.con.val);
	}

	val_t v = reg_realloc2(st, &a, &b, d);

	insn("ORQ\t%s, %s", val_asm(&b), val_asm(&v));

	if (!val_eq(&b, &v))
	{
		val_free(st, &b);
	}

	return v;
}

static val_t gen_bxor(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a;
	val_t b;

	a = gen_expr(ast->l, st, d);
	if (!val_eq(&a, d))
	{
		b = gen_expr(ast->r, st, d);
	}
	else
	{
		b = gen_expr(ast->r, st, NULL);
	}

	if (val_is_con(&a) && val_is_con(&b))
	{
		return val_con(a.con.val ^ b.con.val);
	}

	val_t v = reg_realloc2(st, &a, &b, d);

	insn("XORQ\t%s, %s", val_asm(&b), val_asm(&v));

	if (!val_eq(&b, &v))
	{
		val_free(st, &b);
	}

	return v;
}

static val_t gen_expr(const ast_t *ast, state_t *st, val_t *d)
{
	switch (ast->var)
	{
		case AST_CONST	: return gen_const(ast_as_const(ast), st, d);
		case AST_ID	: return gen_id(ast_as_id(ast), st, d);
		case AST_CALL	: return gen_call(ast_as_call(ast), st, d);
		case AST_LNOT	:
		{
			ast_t *expr = ast_as_un(ast)->expr;

			cnd_t c = cnd_neg(ast_cnd(expr->var));

			if (c != CND_INV)
			{
				return gen_cmp(expr, st, c, d);
			}
			else
			{
				return gen_lnot(expr, st, d);
			}
		}
		case AST_BNOT	: return gen_bnot(ast_as_un(ast), st, d);
		case AST_SET	: return gen_set(ast_as_bin(ast), st, d);
		case AST_EQ	:
		case AST_NE	:
		case AST_LT	:
		case AST_LE	:
		case AST_GT	:
		case AST_GE	: return gen_cmp(ast, st, ast_cnd(ast->var), d);
		case AST_LAND	: return gen_land(ast_as_bin(ast), st, d);
		case AST_LOR	: return gen_lor(ast_as_bin(ast), st, d);
		case AST_SUM	: return gen_sum(ast_as_bin(ast), st, d);
		case AST_DIFF	: return gen_diff(ast_as_bin(ast), st, d);
		case AST_PROD	: return gen_prod(ast_as_bin(ast), st, d);
		case AST_QUOT	: return gen_quot(ast_as_bin(ast), st, d);
		case AST_REM	: return gen_rem(ast_as_bin(ast), st, d);
		case AST_BAND	: return gen_band(ast_as_bin(ast), st, d);
		case AST_BOR	: return gen_bor(ast_as_bin(ast), st, d);
		case AST_BXOR	: return gen_bxor(ast_as_bin(ast), st, d);
		default		: return val_void();
	}
}

static cnd_t gen_test_cnd(const ast_t *ast, state_t *st)
{
	if (ast->var == AST_BAND)
	{
		const ast_bin_t *bin = ast_as_bin(ast);

		val_t a = gen_expr(bin->l, st, NULL);
		val_t b = gen_expr(bin->r, st, NULL);

		if (val_is_con(&a) && val_is_con(&b))
		{
			if ((a.con.val & b.con.val) != 0)
			{
				return CND_T;
			}
			else
			{
				return CND_F;
			}
		}
		else if (val_is_con(&a))
		{
			val_t t = a;
			a = b;
			b = t;
		}

		insn("TESTQ\t%s, %s", val_asm(&b), val_asm(&a));

		val_free(st, &a);
		val_free(st, &b);

		return CND_NE;
	}

	cnd_t c;
	val_t v = gen_expr(ast, st, NULL);

	if (val_is_con(&v))
	{
		if (v.con.val == 0)
		{
			c = CND_F;
		}
		else
		{
			c = CND_T;
		}
	}
	else
	{
		switch (ast->var)
		{
			case AST_SUM	:
			case AST_DIFF	:
			case AST_BOR	:
			case AST_BXOR	:	break;
			default		:
			{
				insn("TESTQ\t%s, %s", val_asm(&v), val_asm(&v));
			}			break;
		}

		c = CND_NE;
	}

	val_free(st, &v);

	return c;
}

static int is_cnd_expr(const ast_t *ast)
{
	switch (ast->var)
	{
		case AST_LNOT	:
		case AST_EQ	:
		case AST_NE	:
		case AST_LT	:
		case AST_LE	:
		case AST_GT	:
		case AST_GE	:
		case AST_LAND	:
		case AST_LOR	: return 1;
		default		: return 0;
	}
}

static cnd_t gen_cmp_cnd(const ast_t *ast, state_t *st, cnd_t c)
{
	const ast_bin_t *bin = ast_as_bin(ast);

	if (cnd_is_con(c))
	{
		return c;
	}

	ast_t *l = bin->l;
	ast_t *r = bin->r;

	if (!is_cnd_expr(l) && is_cnd_expr(r))
	{
		ast_t *t = l;
		l = r;
		r = t;
		c = cnd_rev(c);
	}

	val_t a;
	val_t b;

	b = gen_expr(r, st, NULL);

	if (is_cnd_expr(l) && val_is_con(&b))
	{
		cnd_t ac = gen_expr_cnd(l, st);

		switch (c)
		{
			case CND_EQ	:
			{
				if (b.con.val == 0)
				{
					return cnd_neg(ac);
				}
				else if (b.con.val == 1)
				{
					return ac;
				}
				else
				{
					return CND_F;
				}
			}	break;
			case CND_NE	:
			{
				if (b.con.val == 0)
				{
					return ac;
				}
				else if (b.con.val == 1)
				{
					return cnd_neg(ac);
				}
				else
				{
					return CND_T;
				}
			}	break;
			case CND_LT	:
			{
				if (b.con.val < 1)
				{
					return CND_F;
				}
				else if (b.con.val > 1)
				{
					return CND_T;
				}
				else
				{
					return cnd_neg(ac);
				}
			}	break;
			case CND_LE	:
			{
				if (b.con.val < 0)
				{
					return CND_F;
				}
				else if (b.con.val > 0)
				{
					return CND_T;
				}
				else
				{
					return cnd_neg(ac);
				}
			}	break;
			case CND_GT	:
			{
				if (b.con.val > 0)
				{
					return CND_F;
				}
				else if (b.con.val < 0)
				{
					return CND_T;
				}
				else
				{
					return ac;
				}
			}	break;
			case CND_GE	:
			{
				if (b.con.val > 1)
				{
					return CND_F;
				}
				else if (b.con.val < 1)
				{
					return CND_T;
				}
				else
				{
					return ac;
				}
			}	break;
			default		:
				break;
		}
	}

	a = gen_expr(l, st, NULL);

	if (val_is_con(&a) && val_is_con(&b))
	{
		switch (c)
		{
			case CND_EQ	:
			{
				if (a.con.val == b.con.val)
				{
					c = CND_T;
				}
				else
				{
					c = CND_F;
				}
			}	break;
			case CND_NE	:
			{
				if (a.con.val != b.con.val)
				{
					c = CND_T;
				}
				else
				{
					c = CND_F;
				}
			}	break;
			case CND_LT	:
			{
				if (a.con.val < b.con.val)
				{
					c = CND_T;
				}
				else
				{
					c = CND_F;
				}
			}	break;
			case CND_LE	:
			{
				if (a.con.val <= b.con.val)
				{
					c = CND_T;
				}
				else
				{
					c = CND_F;
				}
			}	break;
			case CND_GT	:
			{
				if (a.con.val > b.con.val)
				{
					c = CND_T;
				}
				else
				{
					c = CND_F;
				}
			}	break;
			case CND_GE	:
			{
				if (a.con.val >= b.con.val)
				{
					c = CND_T;
				}
				else
				{
					c = CND_F;
				}
			}	break;
			default		:
				break;
		}
	}
	else
	{
		val_t zero = val_con(0);
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

			insn("TESTQ\t%s, %s", val_asm(&v), val_asm(&v));
		}
		else
		{
			if (val_is_con(&a))
			{
				val_t t = a;
				a = b;
				b = t;
				c = cnd_rev(c);
			}

			insn("CMPQ\t%s, %s", val_asm(&b), val_asm(&a));
		}
	}

	val_free(st, &a);
	val_free(st, &b);

	return c;
}

static void set_cc(cnd_t c, state_t *st)
{
	val_t v = val_reg(reg_alloc(st));

	insn("XORQ\t%s, %s", val_asm(&v), val_asm(&v));

	switch (c)
	{
		case CND_EQ	: insn("CMPQ\t$0, %s", val_asm(&v));	break;
		case CND_NE	: insn("CMPQ\t$1, %s", val_asm(&v));	break;
		case CND_LT	: insn("CMPQ\t$1, %s", val_asm(&v));	break;
		case CND_LE	: insn("CMPQ\t$1, %s", val_asm(&v));	break;
		case CND_GT	: insn("CMPQ\t$-1, %s", val_asm(&v));	break;
		case CND_GE	: insn("CMPQ\t$-1, %s", val_asm(&v));	break;
		default		:					break;
	}

	val_free(st, &v);
}

static void clr_cc(cnd_t c, state_t *st)
{
	val_t v = val_reg(reg_alloc(st));

	insn("XORQ\t%s, %s", val_asm(&v), val_asm(&v));

	switch (c)
	{
		case CND_EQ	: insn("CMPQ\t$1, %s", val_asm(&v));	break;
		case CND_NE	: insn("CMPQ\t$0, %s", val_asm(&v));	break;
		case CND_LT	: insn("CMPQ\t$-1, %s", val_asm(&v));	break;
		case CND_LE	: insn("CMPQ\t$-1, %s", val_asm(&v));	break;
		case CND_GT	: insn("CMPQ\t$1, %s", val_asm(&v));	break;
		case CND_GE	: insn("CMPQ\t$1, %s", val_asm(&v));	break;
		default		:					break;
	}

	val_free(st, &v);
}

static cnd_t gen_land_cnd(const ast_bin_t *ast, state_t *st)
{
	int lbl_a = lbl_alloc(st);

	cnd_t a = gen_expr_cnd(ast->l, st);

	if (a == CND_T)
	{
	}
	else if (a == CND_F)
	{
		return a;
	}
	else
	{
		insn("J%s\t%s", cnd_mnem[cnd_neg(a)], lbl_name(lbl_a));
	}

	cnd_t b = gen_expr_cnd(ast->r, st);

	if (cnd_is_con(b))
	{
	}
	else if (a != b)
	{
		int lbl_b = lbl_alloc(st);

		insn("JMP\t%s", lbl_name(lbl_b));

		labl("%s", lbl_name(lbl_a));
		clr_cc(b, st);

		labl("%s", lbl_name(lbl_b));
	}
	else
	{
		labl("%s", lbl_name(lbl_a));
	}

	return b;
}

static cnd_t gen_lor_cnd(const ast_bin_t *ast, state_t *st)
{
	int lbl_a = lbl_alloc(st);

	cnd_t a = gen_expr_cnd(ast->l, st);

	if (a == CND_T)
	{
		return a;
	}
	else if (a == CND_F)
	{
	}
	else
	{
		insn("J%s\t%s", cnd_mnem[a], lbl_name(lbl_a));
	}

	cnd_t b = gen_expr_cnd(ast->r, st);

	if (cnd_is_con(b))
	{
	}
	else if (a != b)
	{
		int lbl_b = lbl_alloc(st);

		insn("JMP\t%s", lbl_name(lbl_b));

		labl("%s", lbl_name(lbl_a));
		set_cc(b, st);

		labl("%s", lbl_name(lbl_b));
	}
	else
	{
		labl("%s", lbl_name(lbl_a));
	}

	return b;
}

static cnd_t gen_expr_cnd(const ast_t *ast, state_t *st)
{
	switch (ast->var)
	{
		case AST_LNOT	:
		{
			ast_t *expr = ast_as_un(ast)->expr;

			return cnd_neg(gen_expr_cnd(expr, st));
		}
		case AST_EQ	: return gen_cmp_cnd(ast, st, CND_EQ);
		case AST_NE	: return gen_cmp_cnd(ast, st, CND_NE);
		case AST_LT	: return gen_cmp_cnd(ast, st, CND_LT);
		case AST_LE	: return gen_cmp_cnd(ast, st, CND_LE);
		case AST_GT	: return gen_cmp_cnd(ast, st, CND_GT);
		case AST_GE	: return gen_cmp_cnd(ast, st, CND_GE);
		case AST_LAND	: return gen_land_cnd(ast_as_bin(ast), st);
		case AST_LOR	: return gen_lor_cnd(ast_as_bin(ast), st);
		default		: return gen_test_cnd(ast, st);
	}
}

static val_t gen_block(const ast_block_t *ast, state_t *st)
{
	const ast_t *stmt = ast->stmt;

	state_t block_st;
	state_init(&block_st, st);

	while (stmt != NULL)
	{
		val_t v = gen_stmt(stmt, &block_st);

		val_free(&block_st, &v);

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
		val_t a = gen_expr(expr, st, NULL);

		v = reg_realloc(st, &a, NULL);
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

	if (c == CND_T)
	{
		val_t v = gen_stmt(ast->t_stmt, st);
		val_free(st, &v);

		return val_void();
	}
	else if (c == CND_F)
	{
		if (ast->f_stmt != NULL)
		{
			val_t v = gen_stmt(ast->f_stmt, st);
			val_free(st, &v);
		}

		return val_void();
	}

	insn("J%s\t%s", cnd_mnem[cnd_neg(c)], lbl_name(lbl_a));

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

	if (c == CND_T)
	{
		val_t v = gen_stmt(ast->stmt, st);
		val_free(st, &v);

		insn("JMP\t%s", lbl_name(lbl_a));

		return val_void();
	}
	else if (c == CND_F)
	{
		return val_void();
	}

	insn("J%s\t%s", cnd_mnem[cnd_neg(c)], lbl_name(lbl_b));

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
	val_t v = val_reg(REG_RAX);

	if (ast->expr != NULL)
	{
		val_t t = gen_expr(ast->expr, st, &v);

		gen_mov(&t, &v);

		val_free(st, &t);
	}

	insn("RET");

	reg_set_allocd(st, v.reg.reg);

	return v;
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
		default		: return gen_expr(ast, st, NULL);
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
	insn("MOVQ\t%%rdi, %%rsi");
	insn("LEAQ\t.LC0(%%rip), %%rdi");
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
