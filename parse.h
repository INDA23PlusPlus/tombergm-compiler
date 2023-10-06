#ifndef PARSE_H
#define PARSE_H

#include "ast.h"
#include "tok.h"

ast_t *parse(const tok_t *tok);

#endif

