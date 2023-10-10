#include <stdio.h>
#include <stdlib.h>
#include "gen.h"
#include "lex.h"
#include "parse.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		return EXIT_FAILURE;
	}

	tok_t *tok_list = lex(argv[1]);
	ast_t *ast_list = parse(tok_list);

#if 0
	fprintf(stderr, "lex: ");
	tok_t *tok = tok_list;
	while (tok != NULL)
	{
		tok_print(tok);

		if (tok->next != NULL)
		{
			fprintf(stderr, " ");
		}

		tok = tok->next;
	}
	fprintf(stderr, "\n");

	fprintf(stderr, "parse: ");
	ast_t *ast = ast_list;
	while (ast != NULL)
	{
		ast_print(ast);

		if (ast->next != NULL)
		{
			fprintf(stderr, " ");
		}

		ast = ast->next;
	}
	fprintf(stderr, "\n");
#endif

	gen(ast_list);
}

