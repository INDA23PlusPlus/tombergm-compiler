#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gen.h"
#include "lex.h"
#include "parse.h"
#include "xmalloc.h"

static char *read_stdin(void)
{
	long size = 0;
	long cap = 512;
	char *data = NULL;

	while (!feof(stdin) && !ferror(stdin))
	{
		cap = cap * 2;
		data = xrealloc(data, cap);
		size += fread(&data[size], sizeof(char), cap - size, stdin);
	}

	if (ferror(stdin))
	{
		xfree(data);

		return NULL;
	}

	if (size == cap)
	{
		cap = cap + 1;
		data = xrealloc(data, cap);
	}

	data[size] = '\0';

	return data;
}

static char *read_file(const char *filename)
{
	FILE *f = fopen(filename, "r");

	if (f == NULL)
	{
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *data = xmalloc(size + 1);

	int n = fread(data, size, 1, f);

	fclose(f);

	if (n != 1)
	{
		xfree(data);

		return NULL;
	}

	data[size] = '\0';

	return data;
}

int main(int argc, char *argv[])
{
	const char *filename = NULL;
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
			if (filename == NULL)
			{
				filename = arg;
			}
			else
			{
				return EXIT_FAILURE;
			}
		}
	}

	char *input;

	if (filename == NULL || strcmp(filename, "-") == 0)
	{
		input = read_stdin();
	}
	else
	{
		input = read_file(filename);
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

	xfree(input);
}
