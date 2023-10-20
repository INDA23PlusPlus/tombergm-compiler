#ifndef PARSE_H
#define PARSE_H

#include "ast.h"
#include "err.h"
#include "tok.h"

ast_t *parse(const tok_t *tok, err_t **err);

#endif
