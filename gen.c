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
	VAL_SYM,
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
	const char *	sym;
	int64_t		off;
} val_sym_t;

typedef struct
{
	val_var_t		var;
	union
	{
		val_con_t	con;
		val_reg_t	reg;
		val_mem_t	mem;
		val_sym_t	sym;
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

static inline val_t val_sym(const char *sym, int64_t off)
{
	val_t v;

	v.var = VAL_SYM;
	v.sym.sym = sym;
	v.sym.off = off;

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

static inline int val_is_sym(const val_t *v)
{
	return v != NULL && v->var == VAL_SYM;
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
		case VAL_SYM	:
		{
			return
				strcmp(a->sym.sym, b->sym.sym) == 0	&&
				a->sym.off == b->sym.off		;
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
	int		cont_lbl;
	int		break_lbl;
	reg_t		stack[REG_MAX];
	int		stack_top;
};

static int check_lvl = 0;

static int labl(const char *fmt, ...)
{
	if (check_lvl != 0)
	{
		return 0;
	}

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
	if (check_lvl != 0)
	{
		return 0;
	}

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
	if (check_lvl != 0)
	{
		return 0;
	}

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

		st->stack_top = next->stack_top;
		for (int i = 0; i < next->stack_top; i++)
		{
			st->stack[i] = next->stack[i];
		}
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

	st->cont_lbl = -1;
	st->break_lbl = -1;

	st->stack_top = 0;
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

		st->next->stack_top = st->stack_top;
		for (int i = 0; i < st->stack_top; i++)
		{
			st->next->stack[i] = st->stack[i];
		}
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

static int get_cont_lbl(const ast_t *ast, const state_t *st)
{
	if (st->cont_lbl != -1)
	{
		return st->cont_lbl;
	}
	else if (st->next != NULL)
	{
		return get_cont_lbl(ast, st->next);
	}
	else
	{
		fatal(ast->where, oth, "continue outside of loop");

		return -1;
	}
}

static int get_break_lbl(const ast_t *ast, const state_t *st)
{
	if (st->break_lbl != -1)
	{
		return st->break_lbl;
	}
	else if (st->next != NULL)
	{
		return get_break_lbl(ast, st->next);
	}
	else
	{
		fatal(ast->where, oth, "break outside of loop");

		return -1;
	}
}

static const char *reg_name(reg_t r)
{
	if (r >= 0 && r < REG_MAX)
	{
		return reg_names[r];
	}
	else
	{
		fprintf(stderr, "internal error: bad register, aborting\n");
		abort();
	}
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
		fprintf(stderr, "compilation error: "
			"out of registers, stopping\n");

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

static const char *val_asm_npop(const val_t *v)
{
	static char buf[8][32];
	static int n = 0;

	char *s = buf[n];
	n = (n + 1) % 8;

	switch (v->var)
	{
		case VAL_VOID	:
		{
			fprintf(stderr, "internal error: "
				"attempt to assemble void value, aborting\n");
			abort();
		}			break;
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
		case VAL_SYM	:
		{
			if (v->sym.off == 0)
			{
				sprintf(s, "%s", v->sym.sym);
			}
			else
			{
				sprintf(s, "%s + %" PRIi64, v->sym.sym,
					v->sym.off);

			}
		}			break;
	}

	return s;
}

static int val_saved(state_t *st, const val_t *v)
{
	for (int i = st->stack_top - 1; i >= 0; i--)
	{
		if (st->stack[i] == v->reg.reg)
		{
			return i;
		}
	}

	return -1;
}

static void val_save(state_t *st, const val_t *v)
{
	if (val_is_reg(v))
	{
		int p = val_saved(st, v);

		if (p == -1)
		{
			insn("PUSH\t%s", val_asm_npop(v));

			st->stack[st->stack_top++] = v->reg.reg;
		}
	}
}

static void val_rstor(state_t *st, const val_t *v)
{
	if (val_is_reg(v))
	{
		int p = val_saved(st, v);

		if (p != -1)
		{
			while (st->stack_top != p)
			{
				st->stack_top--;

				val_t rv = val_reg(st->stack[st->stack_top]);

				insn("POP\t%s", val_asm_npop(&rv));
			}
		}
	}
}

static void stack_reset(state_t *st)
{
	while (st->stack_top != 0)
	{
		st->stack_top--;

		val_t rv = val_reg(st->stack[st->stack_top]);

		insn("POP\t%s", val_asm_npop(&rv));
	}
}

static const char *val_asm(state_t *st, const val_t *v)
{
	val_rstor(st, v);

	return val_asm_npop(v);
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

static void gen_mov(state_t *st, const val_t *a, const val_t *b)
{
	val_t zero = val_con(0);

	if (val_eq(a, b))
	{
	}
	else if (val_eq(a, &zero) && val_is_reg(b))
	{
		insn("XORQ\t%s, %s", val_asm_npop(b), val_asm_npop(b));
	}
	else
	{
		int p = val_saved(st, a);

		if (val_is_reg(a) && !reg_noclob(st, a->reg.reg) && p != -1)
		{
			while (st->stack_top - 1 != p)
			{
				st->stack_top--;

				val_t rv = val_reg(st->stack[st->stack_top]);

				insn("POP\t%s", val_asm_npop(&rv));
			}

			st->stack_top--;

			insn("POP\t%s", val_asm_npop(b));
		}
		else
		{
			insn("MOVQ\t%s, %s", val_asm(st, a), val_asm_npop(b));
		}
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
	else if (val_is_con(a) && val_is_reg(d))
	{
		gen_mov(st, a, d);
		val_free(st, a);
		return *d;
	}
	else if (val_is_reg(d))
	{
		if (a != NULL)
		{
			gen_mov(st, a, d);
			val_free(st, a);
		}
		return *d;
	}
	else
	{
		val_t v = val_reg(reg_alloc(st));
		if (a != NULL)
		{
			gen_mov(st, a, &v);
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
	else if (val_is_con(a) && val_is_reg(d))
	{
		gen_mov(st, a, d);
		val_free(st, a);
		return *d;
	}
	else if (val_is_con(b) && val_is_reg(d))
	{
		val_t t = *a;
		*a = *b;
		*b = t;
		gen_mov(st, a, d);
		val_free(st, a);
		return *d;
	}
	else if (val_is_reg(d))
	{
		gen_mov(st, a, d);
		val_free(st, a);
		return *d;
	}
	else
	{
		val_t v = val_reg(reg_alloc(st));
		gen_mov(st, a, &v);
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

static void check_stmt(const ast_t *ast, state_t *st)
{
	if (ast != NULL)
	{
		state_t c_st = *st;

		check_lvl++;
		gen_stmt(ast, st);
		check_lvl--;

		*st = c_st;
	}
}

static void check_expr(const ast_t *ast, state_t *st)
{
	if (ast != NULL)
	{
		state_t c_st = *st;

		check_lvl++;
		gen_expr(ast, st, NULL);
		check_lvl--;

		*st = c_st;
	}
}

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

	{
		val_t a = gen_expr(ast->arg, st, NULL);

		insn("CVTSI2SD\t%s, %%xmm0", val_asm(st, &a));

		val_free(st, &a);
	}

	val_t v = reg_realloc(st, d, d);

	insn("SQRTSD\t\t%%xmm0, %%xmm0");
	insn("CVTTSD2SI\t%%xmm0, %s", val_asm(st, &v));

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
			gen_mov(st, &a, &b);
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
			val_t r = val_reg(i);
			val_save(st, &r);
		}
	}

	for (int i = 0; i < narg; i++)
	{
		val_t b = val_reg(call_regs[i]);

		if (!val_eq(&moved[i], &b))
		{
			gen_mov(st, &moved[i], &b);
			val_free(st, &moved[i]);
		}
	}

	for (reg_t i = 0; i < REG_MAX; i++)
	{
		if (reg_allocd(st, i) && !reg_noclob(st, i))
		{
			val_t r = val_reg(i);
			val_save(st, &r);
		}
	}

	insn("CALL\t%s", ast_as_id(ast->fn)->id);

	val_t v = val_reg(REG_RAX);

	if (reg_allocd(st, v.reg.reg))
	{
		val_t t = val_reg(reg_alloc(st));
		insn("MOVQ\t%s, %s", val_asm_npop(&v), val_asm(st, &t));
		v = t;
	}
	else
	{
		reg_set_allocd(st, v.reg.reg);
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
		insn("MOVQ\t$1, %s", val_asm(st, &v));
	}
	else if (c == CND_F)
	{
		insn("XORQ\t%s, %s", val_asm(st, &v), val_asm(st, &v));
	}
	else
	{
		val_t r;
		const char *l;
		pick_lreg(st, &r, &l, &v);

		if (reg_allocd(st, r.reg.reg) && !val_eq(&r, &v))
		{
			val_save(st, &r);
		}

		insn("SET%s\t%s", cnd_mnem[c], l);
		insn("MOVZX\t%s, %s", l, val_asm(st, &v));
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

	insn("NOTQ\t%s", val_asm(st, &v));

	if (!val_eq(&a, &v))
	{
		val_free(st, &a);
	}

	return v;
}

static val_t gen_pos(const ast_un_t *ast, state_t *st, val_t *d)
{
	return gen_expr(ast->expr, st, d);
}

static val_t gen_neg(const ast_un_t *ast, state_t *st, val_t *d)
{
	val_t a = gen_expr(ast->expr, st, d);

	if (val_is_con(&a))
	{
		return val_con(-a.con.val);
	}

	val_t v = reg_realloc(st, &a, d);

	insn("NEGQ\t%s", val_asm(st, &v));

	if (!val_eq(&a, &v))
	{
		val_free(st, &a);
	}

	return v;
}

static val_t gen_set(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a = gen_expr(ast->l, st, d);
	val_rstor(st, &a);
	val_t b = gen_expr(ast->r, st, &a);

	if (val_is_con(&a))
	{
		fatal(ast->l->where, oth, "lvalue expected");
	}

	gen_mov(st, &b, &a);

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
		insn("MOVQ\t$1, %s", val_asm(st, &v));
	}
	else if (c == CND_F)
	{
		insn("XORQ\t%s, %s", val_asm(st, &v), val_asm(st, &v));
	}
	else
	{
		val_t r;
		const char *l;
		pick_lreg(st, &r, &l, &v);

		if (reg_allocd(st, r.reg.reg) && !val_eq(&r, &v))
		{
			val_save(st, &r);
		}

		insn("SET%s\t%s", cnd_mnem[c], l);
		insn("MOVZX\t%s, %s", l, val_asm(st, &v));
	}

	return v;
}

static val_t gen_land(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t v = reg_realloc(st, d, d);
	int lbl = lbl_alloc(st);

	insn("XORQ\t%s, %s", val_asm(st, &v), val_asm(st, &v));

	cnd_t a = gen_expr_cnd(ast->l, st);

	if (a == CND_T)
	{
	}
	else if (a == CND_F)
	{
		check_expr(ast->r, st);

		return v;
	}
	else
	{
		stack_reset(st);
		insn("J%s\t%s", cnd_mnem[cnd_neg(a)], lbl_name(lbl));
	}

	cnd_t b = gen_expr_cnd(ast->r, st);

	if (cnd_is_con(b))
	{
		if (b == CND_T)
		{
			insn("INCQ\t%s", val_asm(st, &v));
		}
	}
	else
	{
		val_t r;
		const char *l;
		pick_lreg(st, &r, &l, &v);

		if (reg_allocd(st, r.reg.reg) && !val_eq(&r, &v))
		{
			val_save(st, &r);
		}

		insn("SET%s\t%s", cnd_mnem[b], l);
		insn("MOVZX\t%s, %s", l, val_asm(st, &v));
	}

	stack_reset(st);
	labl("%s", lbl_name(lbl));

	return v;
}

static val_t gen_lor(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t v = reg_realloc(st, d, d);
	int lbl = lbl_alloc(st);

	insn("MOVQ\t$1, %s", val_asm(st, &v));

	cnd_t a = gen_expr_cnd(ast->l, st);

	if (a == CND_T)
	{
		check_expr(ast->r, st);

		return v;
	}
	else if (a == CND_F)
	{
	}
	else
	{
		stack_reset(st);
		insn("J%s\t%s", cnd_mnem[a], lbl_name(lbl));
	}

	cnd_t b = gen_expr_cnd(ast->r, st);

	if (cnd_is_con(b))
	{
		if (b == CND_F)
		{
			insn("DECQ\t%s", val_asm(st, &v));
		}
	}
	else
	{
		val_t r;
		const char *l;
		pick_lreg(st, &r, &l, &v);

		if (reg_allocd(st, r.reg.reg) && !val_eq(&r, &v))
		{
			val_save(st, &r);
		}

		insn("SET%s\t%s", cnd_mnem[b], l);
		insn("MOVZX\t%s, %s", l, val_asm(st, &v));
	}

	stack_reset(st);
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
	else if (val_is_sym(&a) && val_is_con(&b))
	{
		return val_sym(a.sym.sym, a.sym.off + b.con.val);
	}
	else if (val_is_con(&a) && val_is_sym(&b))
	{
		return val_sym(b.sym.sym, b.sym.off + a.con.val);
	}

	val_t v = reg_realloc2(st, &a, &b, d);

	insn("ADDQ\t%s, %s", val_asm(st, &b), val_asm(st, &v));

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
	else if (val_is_sym(&a) && val_is_con(&b))
	{
		return val_sym(a.sym.sym, a.sym.off - b.con.val);
	}

	val_t v = reg_realloc(st, &a, d);

	insn("SUBQ\t%s, %s", val_asm(st, &b), val_asm(st, &v));

	if (!val_eq(&b, &v))
	{
		val_free(st, &b);
	}

	return v;
}

static val_t gen_muldiv(const ast_bin_t *ast, state_t *st, val_t *d,
			int mul, reg_t r)
{
	val_t a = gen_expr(ast->l, st, NULL);
	val_t b = gen_expr(ast->r, st, NULL);

	val_t rax = val_reg(REG_RAX);
	val_t rdx = val_reg(REG_RDX);

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

	if (reg_allocd(st, REG_RAX) && !val_eq(&a, &rax) && !val_eq(&b, &rax))
	{
		val_save(st, &rax);
	}
	if (reg_allocd(st, REG_RDX) && !val_eq(&a, &rdx) && !val_eq(&b, &rdx))
	{
		val_save(st, &rdx);
	}

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
			gen_mov(st, &rax, &b);
		}
		else
		{
			insn("XCHG\t%s, %s", val_asm(st, &b), val_asm(st, &a));
			val_t t = a;
			a = b;
			b = t;
		}
	}

	gen_mov(st, &a, &rax);
	val_free(st, &a);

	if (val_is_con(&b))
	{
		val_t t = val_reg(reg_alloc(st));
		gen_mov(st, &b, &t);
		val_free(st, &b);
		b = t;
	}

	if (mul)
	{
		insn("IMULQ\t%s", val_asm(st, &b));
	}
	else
	{
		insn("CQO");
		insn("IDIVQ\t%s", val_asm(st, &b));
	}
	val_free(st, &b);

	val_t v = val_reg(r);

	if (reg_allocd(st, r))
	{
		val_t t = val_reg(reg_alloc(st));
		insn("MOVQ\t%s, %s", val_asm_npop(&v), val_asm(st, &t));
		v = t;
	}
	else
	{
		reg_set_allocd(st, r);
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

	insn("ANDQ\t%s, %s", val_asm(st, &b), val_asm(st, &v));

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

	insn("ORQ\t%s, %s", val_asm(st, &b), val_asm(st, &v));

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

	insn("XORQ\t%s, %s", val_asm(st, &b), val_asm(st, &v));

	if (!val_eq(&b, &v))
	{
		val_free(st, &b);
	}

	return v;
}

static val_t gen_shl(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a = gen_expr(ast->l, st, d);
	val_t b = gen_expr(ast->r, st, NULL);
	val_t rcx = val_reg(REG_RCX);

	if (val_is_con(&a) && val_is_con(&b))
	{
		return val_con(a.con.val << b.con.val);
	}

	val_t v = reg_realloc(st, &a, d);

	if (val_is_con(&b) || val_eq(&b, &rcx))
	{
		insn("SALQ\t%s, %s", val_asm(st, &b), val_asm(st, &v));
	}
	else
	{
		if (reg_allocd(st, REG_RCX))
		{
			val_save(st, &rcx);
		}

		gen_mov(st, &b, &rcx);
		insn("SALQ\t%s, %s", val_asm_npop(&rcx), val_asm(st, &v));
	}

	val_free(st, &b);

	return v;
}

static val_t gen_shr(const ast_bin_t *ast, state_t *st, val_t *d)
{
	val_t a = gen_expr(ast->l, st, d);
	val_t b = gen_expr(ast->r, st, NULL);
	val_t rcx = val_reg(REG_RCX);

	if (val_is_con(&a) && val_is_con(&b))
	{
		return val_con(a.con.val >> b.con.val);
	}

	val_t v = reg_realloc(st, &a, d);

	if (val_is_con(&b) || val_eq(&b, &rcx))
	{
		insn("SARQ\t%s, %s", val_asm(st, &b), val_asm(st, &v));
	}
	else
	{
		if (reg_allocd(st, REG_RCX))
		{
			val_save(st, &rcx);
		}

		gen_mov(st, &b, &rcx);
		insn("SARQ\t%s, %s", val_asm_npop(&rcx), val_asm(st, &v));
	}

	val_free(st, &b);

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
		case AST_POS	: return gen_pos(ast_as_un(ast), st, d);
		case AST_NEG	: return gen_neg(ast_as_un(ast), st, d);
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
		case AST_SHL	: return gen_shl(ast_as_bin(ast), st, d);
		case AST_SHR	: return gen_shr(ast_as_bin(ast), st, d);
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

		insn("TESTQ\t%s, %s", val_asm(st, &b), val_asm(st, &a));

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
				insn("TESTQ\t%s, %s",
					val_asm(st, &v), val_asm(st, &v));
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
		check_expr(bin->l, st);
		check_expr(bin->r, st);

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
		int a_arit =
			l->var == AST_SUM	||
			l->var == AST_DIFF	||
			l->var == AST_BOR	||
			l->var == AST_BXOR	;
		int b_arit =
			r->var == AST_SUM	||
			r->var == AST_DIFF	||
			r->var == AST_BOR	||
			r->var == AST_BXOR	;
		int is_eqne =
			c == CND_EQ	||
			c == CND_NE	;
		val_t zero = val_con(0);
		int a_zero = val_eq(&a, &zero);
		int b_zero = val_eq(&b, &zero);

		if (a_arit && b_zero)
		{
		}
		else if (a_zero && b_arit)
		{
			c = cnd_rev(c);
		}
		else if (is_eqne && (a_zero || b_zero))
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

			insn("TESTQ\t%s, %s",
				val_asm(st, &v), val_asm(st, &v));
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

			insn("CMPQ\t%s, %s", val_asm(st, &b), val_asm(st, &a));
		}
	}

	val_free(st, &a);
	val_free(st, &b);

	return c;
}

static void set_cc(cnd_t c, state_t *st)
{
	val_t v = val_reg(reg_alloc(st));

	insn("XORQ\t%s, %s", val_asm(st, &v), val_asm(st, &v));

	switch (c)
	{
		case CND_EQ	:
			insn("CMPQ\t$0, %s", val_asm(st, &v));	break;
		case CND_NE	:
			insn("CMPQ\t$1, %s", val_asm(st, &v));	break;
		case CND_LT	:
			insn("CMPQ\t$1, %s", val_asm(st, &v));	break;
		case CND_LE	:
			insn("CMPQ\t$1, %s", val_asm(st, &v));	break;
		case CND_GT	:
			insn("CMPQ\t$-1, %s", val_asm(st, &v));	break;
		case CND_GE	:
			insn("CMPQ\t$-1, %s", val_asm(st, &v));	break;
		default		:				break;
	}

	val_free(st, &v);
}

static void clr_cc(cnd_t c, state_t *st)
{
	val_t v = val_reg(reg_alloc(st));

	insn("XORQ\t%s, %s", val_asm(st, &v), val_asm(st, &v));

	switch (c)
	{
		case CND_EQ	:
			insn("CMPQ\t$1, %s", val_asm(st, &v));	break;
		case CND_NE	:
			insn("CMPQ\t$0, %s", val_asm(st, &v));	break;
		case CND_LT	:
			insn("CMPQ\t$-1, %s", val_asm(st, &v));	break;
		case CND_LE	:
			insn("CMPQ\t$-1, %s", val_asm(st, &v));	break;
		case CND_GT	:
			insn("CMPQ\t$1, %s", val_asm(st, &v));	break;
		case CND_GE	:
			insn("CMPQ\t$1, %s", val_asm(st, &v));	break;
		default		:				break;
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
		check_expr(ast->r, st);

		return a;
	}
	else
	{
		stack_reset(st);
		insn("J%s\t%s", cnd_mnem[cnd_neg(a)], lbl_name(lbl_a));
	}

	cnd_t b = gen_expr_cnd(ast->r, st);

	if (cnd_is_con(b))
	{
	}
	else if (a != b)
	{
		int lbl_b = lbl_alloc(st);

		stack_reset(st);
		insn("JMP\t%s", lbl_name(lbl_b));

		labl("%s", lbl_name(lbl_a));
		clr_cc(b, st);

		labl("%s", lbl_name(lbl_b));
	}
	else
	{
		stack_reset(st);
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
		check_expr(ast->r, st);

		return a;
	}
	else if (a == CND_F)
	{
	}
	else
	{
		stack_reset(st);
		insn("J%s\t%s", cnd_mnem[a], lbl_name(lbl_a));
	}

	cnd_t b = gen_expr_cnd(ast->r, st);

	if (cnd_is_con(b))
	{
	}
	else if (a != b)
	{
		int lbl_b = lbl_alloc(st);

		stack_reset(st);
		insn("JMP\t%s", lbl_name(lbl_b));

		labl("%s", lbl_name(lbl_a));
		set_cc(b, st);

		labl("%s", lbl_name(lbl_b));
	}
	else
	{
		stack_reset(st);
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

	int elim = 0;

	while (stmt != NULL)
	{
		if (elim)
		{
			check_stmt(stmt, &block_st);
		}
		else
		{
			val_t v = gen_stmt(stmt, &block_st);

			val_free(&block_st, &v);

			if (	stmt->var == AST_RET	||
				stmt->var == AST_CONT	||
				stmt->var == AST_BREAK)
			{
				elim = 1;
			}
		}

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

static int is_effective(const ast_t *ast)
{
	if (ast == NULL)
	{
		return 0;
	}

	switch (ast->var)
	{
		case AST_BLOCK	:
		{
			const ast_t *stmt = ast_as_block(ast)->stmt;

			while (stmt != NULL)
			{
				if (is_effective(stmt))
				{
					return 1;
				}

				stmt = stmt->next;
			}

			return 0;
		}
		case AST_VOID	: return 0;
		default		: return 1;
	}
}

static int is_jmp(const ast_t *ast)
{
	if (ast == NULL)
	{
		return 0;
	}

	switch (ast->var)
	{
		case AST_BLOCK	: return is_jmp(ast_as_block(ast)->stmt);
		case AST_CONT	:
		case AST_BREAK	: return 1;
		default		: return 0;
	}
}

static int get_jmp_lbl(const ast_t *ast, const state_t *st)
{
	if (ast == NULL)
	{
		return -1;
	}

	switch (ast->var)
	{
		case AST_BLOCK	:
		{
			return get_jmp_lbl(ast_as_block(ast)->stmt, st);
		}
		case AST_CONT	: return get_cont_lbl(ast, st);
		case AST_BREAK	: return get_break_lbl(ast, st);
		default		: return -1;
	}
}

static val_t gen_if(const ast_if_t *ast, state_t *st)
{
	int else_lbl = lbl_alloc(st);
	int tail_lbl = -1;

	if (is_effective(ast->f_stmt))
	{
		tail_lbl = lbl_alloc(st);
	}

	cnd_t c = gen_expr_cnd(ast->expr, st);

	if (c == CND_T)
	{
		{
			val_t v = gen_stmt(ast->t_stmt, st);
			val_free(st, &v);
		}

		check_stmt(ast->f_stmt, st);

		return val_void();
	}
	else if (c == CND_F)
	{
		check_stmt(ast->t_stmt, st);

		if (is_effective(ast->f_stmt))
		{
			val_t v = gen_stmt(ast->f_stmt, st);
			val_free(st, &v);
		}
		else
		{
			check_stmt(ast->f_stmt, st);
		}

		return val_void();
	}

	if (is_jmp(ast->t_stmt))
	{
		check_stmt(ast->t_stmt, st);

		int jmp_lbl = get_jmp_lbl(ast->t_stmt, st);

		stack_reset(st);
		insn("J%s\t%s", cnd_mnem[c], lbl_name(jmp_lbl));
	}
	else if (is_effective(ast->t_stmt))
	{
		stack_reset(st);
		insn("J%s\t%s", cnd_mnem[cnd_neg(c)], lbl_name(else_lbl));

		{
			val_t v = gen_stmt(ast->t_stmt, st);
			val_free(st, &v);
		}

		if (is_effective(ast->f_stmt))
		{
			stack_reset(st);
			insn("JMP\t%s", lbl_name(tail_lbl));
		}

		stack_reset(st);
		labl("%s", lbl_name(else_lbl));
	}
	else
	{
		check_stmt(ast->t_stmt, st);

		if (is_jmp(ast->f_stmt))
		{
		}
		else if (is_effective(ast->f_stmt))
		{
			stack_reset(st);
			insn("J%s\t%s", cnd_mnem[c], lbl_name(tail_lbl));
		}
	}

	if (!is_jmp(ast->t_stmt) && is_jmp(ast->f_stmt))
	{
		check_stmt(ast->f_stmt, st);

		stack_reset(st);

		int jmp_lbl = get_jmp_lbl(ast->f_stmt, st);

		if (jmp_lbl != tail_lbl)
		{
			insn("J%s\t%s", cnd_mnem[cnd_neg(c)],
				lbl_name(jmp_lbl));
		}

		labl("%s", lbl_name(tail_lbl));
	}
	else if (is_effective(ast->f_stmt))
	{
		{
			val_t v = gen_stmt(ast->f_stmt, st);
			val_free(st, &v);
		}

		stack_reset(st);
		labl("%s", lbl_name(tail_lbl));
	}
	else
	{
		check_stmt(ast->f_stmt, st);
	}

	return val_void();
}

static val_t gen_while(const ast_while_t *ast, state_t *st)
{
	int cont_lbl = lbl_alloc(st);
	int break_lbl = lbl_alloc(st);

	stack_reset(st);
	labl("%s", lbl_name(cont_lbl));

	cnd_t c = gen_expr_cnd(ast->expr, st);

	state_t l_st;
	state_init(&l_st, st);

	l_st.cont_lbl = cont_lbl;
	l_st.break_lbl = break_lbl;

	if (c == CND_T)
	{
		{
			val_t v = gen_stmt(ast->stmt, &l_st);
			val_free(&l_st, &v);
		}

		stack_reset(st);
		insn("JMP\t%s", lbl_name(cont_lbl));

		labl("%s", lbl_name(break_lbl));
	}
	else if (c == CND_F)
	{
		check_stmt(ast->stmt, &l_st);
	}
	else if (is_jmp(ast->stmt))
	{
		check_stmt(ast->stmt, &l_st);

		stack_reset(st);

		int jmp_lbl = get_jmp_lbl(ast->stmt, &l_st);

		if (jmp_lbl != break_lbl)
		{
			insn("J%s\t%s", cnd_mnem[c], lbl_name(jmp_lbl));
		}

		labl("%s", lbl_name(break_lbl));
	}
	else if (is_effective(ast->stmt))
	{
		stack_reset(st);
		insn("J%s\t%s", cnd_mnem[cnd_neg(c)], lbl_name(break_lbl));

		{
			val_t v = gen_stmt(ast->stmt, &l_st);
			val_free(&l_st, &v);
		}

		stack_reset(st);
		insn("JMP\t%s", lbl_name(cont_lbl));

		labl("%s", lbl_name(break_lbl));
	}
	else
	{
		check_stmt(ast->stmt, &l_st);

		stack_reset(st);
		insn("J%s\t%s", cnd_mnem[cnd_neg(c)], lbl_name(break_lbl));

		{
			int jmp_lbl = lbl_alloc(&l_st);
			labl("%s", lbl_name(jmp_lbl));
			insn("JMP\t%s", lbl_name(jmp_lbl));
		}

		labl("%s", lbl_name(break_lbl));
	}

	state_pop(&l_st);

	return val_void();
}

static val_t gen_cont(const ast_t *ast, state_t *st)
{
	stack_reset(st);
	insn("JMP\t%s", lbl_name(get_cont_lbl(ast, st)));

	return val_void();
}

static val_t gen_break(const ast_t *ast, state_t *st)
{
	stack_reset(st);
	insn("JMP\t%s", lbl_name(get_break_lbl(ast, st)));

	return val_void();
}

static val_t gen_ret(const ast_ret_t *ast, state_t *st)
{
	val_t v = val_reg(REG_RAX);

	if (ast->expr != NULL)
	{
		val_t t = gen_expr(ast->expr, st, &v);

		gen_mov(st, &t, &v);

		val_free(st, &t);
	}

	stack_reset(st);
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
		case AST_CONT	: return gen_cont(ast, st);
		case AST_BREAK	: return gen_break(ast, st);
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

	stack_reset(st);
	insn("RET");
	insn(".size\t%s, . - %s", id, id);

	state_pop(&fn_st);

	return val_void();
}

static void gen_lib(void)
{
	insn(".text");
	endl();
	insn(".globl\t_start");
	insn(".type\t_start, @function");
	labl("_start");
	insn("CALL\tmain");
	insn("MOV\t%%rax, %%rdi");
	insn("MOV\t$60, %%rax");
	insn("SYSCALL");
	insn(".size\t_start, . - _start");
	endl();
	insn(".type\t__print_itoa, @function");
	labl("__print_itoa");
	insn("MOV\t%%rdi, %%rax");
	insn("NEG\t%%rax");
	insn("CMOVL\t%%rdi, %%rax");
	insn("MOV\t$10, %%rbx");
	labl(".div");
	insn("XOR\t%%rdx, %%rdx");
	insn("DIV\t%%rbx");
	insn("ADD\t$'0', %%rdx");
	insn("DEC\t%%rsi");
	insn("MOVB\t%%dl, (%%rsi)");
	insn("TEST\t%%rax, %%rax");
	insn("JNZ\t.div");
	insn("LEA\t-1(%%rsi), %%rbx");
	insn("MOVB\t$'-', (%%rbx)");
	insn("TEST\t%%rdi, %%rdi");
	insn("CMOVL\t%%rbx, %%rsi");
	insn("RET");
	insn(".size\t__print_itoa, . - __print_itoa");
	endl();
	insn(".globl\tprint");
	insn(".type\tprint, @function");
	labl("print");
	insn("LEA\t-1(%%rsp), %%rsi");
	insn("MOVB\t$'\\n', (%%rsi)");
	insn("SUB\t$32, %%rsp");
	insn("CALL\t__print_itoa");
	insn("ADD\t$32, %%rsp");
	insn("MOV\t%%rsp, %%rdx");
	insn("SUB\t%%rsi, %%rdx");
	insn("MOV\t$1, %%rdi");
	insn("MOV\t%%rdi, %%rax");
	insn("SYSCALL");
	insn("RET");
	insn(".size\tprint, . - print");
	endl();
	insn(".globl\tputd");
	insn(".type\tputd, @function");
	labl("putd");
	insn("MOV\t%%rsp, %%rsi");
	insn("SUB\t$32, %%rsp");
	insn("CALL\t__print_itoa");
	insn("ADD\t$32, %%rsp");
	insn("MOV\t%%rsp, %%rdx");
	insn("SUB\t%%rsi, %%rdx");
	insn("MOV\t$1, %%rdi");
	insn("MOV\t%%rdi, %%rax");
	insn("SYSCALL");
	insn("RET");
	insn(".size\tputd, . - putd");
	endl();
	insn(".globl\tputc");
	insn(".type\tputc, @function");
	labl("putc");
	insn("LEA\t-8(%%rsp), %%rsi");
	insn("MOVQ\t%%rdi, (%%rsi)");
	insn("MOV\t$1, %%rdi");
	insn("MOV\t%%rdi, %%rdx");
	insn("MOV\t%%rdx, %%rax");
	insn("SYSCALL");
	insn("RET");
	insn(".size\tputc, . - putc");
	endl();
	insn(".globl\tputmc");
	insn(".type\tputmc, @function");
	labl("putmc");
	insn("LZCNT\t%%rdi, %%rdx");
	insn("BSWAP\t%%rdi");
	insn("MOVQ\t%%rdi, -8(%%rsp)");
	insn("NEG\t%%rdx");
	insn("ADD\t$71, %%rdx");
	insn("SHR\t$3, %%rdx");
	insn("MOV\t%%rsp, %rsi");
	insn("SUB\t%%rdx, %%rsi");
	insn("MOV\t$1, %%rdi");
	insn("MOV\t%%rdi, %%rax");
	insn("SYSCALL");
	insn("RET");
	insn(".size\tputmc, . - putmc");
	endl();
	insn(".global\tscan");
	insn(".type\tscan, @function");
	labl("scan");
	insn("XOR\t%%rbx, %%rbx");
	insn("XOR\t%%rbp, %%rbp");
	insn("XOR\t%%rdi, %%rdi");
	insn("LEA\t-1(%%rsp), %%rsi");
	labl(".read");
	insn("MOV\t$1, %%rdx");
	insn("XOR\t%%rax, %%rax");
	insn("SYSCALL");
	insn("TEST\t%%rax, %%rax");
	insn("JZ\t.end");
	insn("MOVZXB\t(%%rsi), %%rcx");
	insn("CMP\t$'\\n', %%rcx");
	insn("JE\t.end");
	insn("TEST\t%%rbp, %%rbp");
	insn("JNZ\t.nosign");
	insn("CMP\t$' ', %%rcx");
	insn("JE\t.read");
	insn("CMP\t$'\\t', %%rcx");
	insn("JE\t.read");
	insn("MOV\t$1, %%rbp");
	insn("CMP\t$'-', %%rcx");
	insn("JNE\t.nosign");
	insn("MOV\t$-1, %%rbp");
	insn("JMP\t.read");
	labl(".nosign");
	insn("SUB\t$'0', %%rcx");
	insn("JL\t.line");
	insn("CMP\t$10, %%rcx");
	insn("JGE\t.line");
	insn("MOV\t$10, %%rax");
	insn("MUL\t%%rbx");
	insn("MOV\t%%rax, %%rbx");
	insn("ADD\t%%rcx, %%rbx");
	insn("JMP\t.read");
	labl(".line");
	insn("XOR\t%%rax, %%rax");
	insn("SYSCALL");
	insn("TEST\t%%rax, %%rax");
	insn("JZ\t.end");
	insn("CMPB\t$'\\n', (%%rsi)");
	insn("JNE\t.line");
	labl(".end");
	insn("MOV\t%%rbx, %%rax");
	insn("NEG\t%%rbx");
	insn("TEST\t%%rbp, %%rbp");
	insn("CMOVL\t%%rbx, %%rax");
	insn("RET");
	insn(".size\tscan, . - scan");
}

void gen(const ast_t *ast)
{
	gen_lib();

	state_t st;
	state_init(&st, NULL);

	while (ast != NULL)
	{
		switch (ast->var)
		{
			case AST_FN	:
			{
				endl();
				gen_fn(ast_as_fn(ast), &st);
			}	break;
			case AST_END	:
				break;
			default		:
			{
				fprintf(stderr, "internal error: "
					"invalid top-level statement, "
					"aborting\n");
				abort();
			}	break;
		}

		ast = ast->next;
	}

	state_pop(&st);
}
