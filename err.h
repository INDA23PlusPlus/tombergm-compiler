#ifndef ERR_H
#define ERR_H

#include "tok.h"
#include "where.h"

typedef enum
{
	ERR_EXP,
	ERR_OTH,
} err_var_t;

typedef struct err err_t;

struct err
{
	err_var_t	var;
	where_t		where;
	err_t *		next;
};

typedef struct
{
	err_t		err;
	const char *	what;
	tok_var_t	tok_var;
} err_exp_t;

typedef struct
{
	err_t		err;
	const char *	what;
} err_oth_t;

#define err_as(var, v) \
( \
	_Generic \
	( \
		(v), \
		err_t *		: (err_ ## var ## _t *) v, \
		const err_t *	: (const err_ ## var ## _t *) v \
	) \
)
#define err_as_exp(v) err_as(exp, v)
#define err_as_oth(v) err_as(oth, v)

#define err_set_m(err_list, where, var, ...) \
({ \
	where_t __err_set_m_where = (where); \
	__typeof__(err_ ## var(__err_set_m_where, __VA_ARGS__)) \
	__err_set_m_err = err_ ## var(__err_set_m_where, __VA_ARGS__); \
	err_set(err_list, &__err_set_m_err.err); \
})

static inline err_exp_t err_exp_some(where_t where, const char *what)
{
	err_exp_t err;

	err.err.var = ERR_EXP;
	err.err.where = where;
	err.err.next = NULL;
	err.what = what;
	err.tok_var = (tok_var_t) -1;

	return err;
}

static inline err_exp_t err_exp_tok(where_t where, tok_var_t var)
{
	err_exp_t err;

	err.err.var = ERR_EXP;
	err.err.where = where;
	err.err.next = NULL;
	err.what = NULL;
	err.tok_var = var;

	return err;
}

static inline err_oth_t err_oth(where_t where, const char *what)
{
	err_oth_t err;

	err.err.var = ERR_OTH;
	err.err.where = where;
	err.err.next = NULL;
	err.what = what;

	return err;
}

err_t *	err_dup(const err_t *err);
void	err_del(err_t *err);
void	err_set(err_t **err_list, const err_t *err);
err_t *	err_save(err_t **err_list);
void	err_rstor(err_t **err_list, const err_t *err_st);
void	err_rstor_to(err_t **err_list, const err_t *err_st, const where_t *to);
void	err_print(err_t *err);

#endif
