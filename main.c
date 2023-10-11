#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gen.h"
#include "lex.h"
#include "parse.h"

int main(int argc, char *argv[])
{
	const char *input = NULL;
	int verbose = 0;

	for (int i = 1; i < argc; i++)
	{
		char *arg = argv[i];

		if (strcmp(arg, "-v") == 0)
		{
			verbose = 1;
		}
		else
		{
			if (input == NULL)
			{
				input = arg;
			}
			else
			{
				return EXIT_FAILURE;
			}
		}
	}

	if (input == NULL)
	{
		return EXIT_FAILURE;
	}

	tok_t *tok_list = lex(input);
	ast_t *ast_list = parse(tok_list);

	if (verbose)
	{
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
	}

	gen(ast_list);
}
