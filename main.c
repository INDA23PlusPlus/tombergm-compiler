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
	ast_t *ast = parse(tok_list);

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

	if (ast != NULL)
	{
		printf("parse: ");
		ast_print(ast);
		printf("\n");
	}
}

