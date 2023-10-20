#ifndef LEX_H
#define LEX_H

#include "err.h"
#include "tok.h"

tok_t *lex(const char *src, const char *file, err_t **err_list);

#endif
