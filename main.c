#include <stdio.h>
#include <stdlib.h>
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

	printf("lex: ");
	tok_t *tok = tok_list;
	while (tok != NULL)
	{
		tok_print(tok);

		if (tok->next != NULL)
		{
			printf(" ");
		}

		tok = tok->next;
	}
	printf("\n");

	printf("parse: ");
	ast_t *ast = ast_list;
	while (ast != NULL)
	{
		ast_print(ast);

		if (ast->next != NULL)
		{
			printf(" ");
		}

		ast = ast->next;
	}
	printf("\n");
}

