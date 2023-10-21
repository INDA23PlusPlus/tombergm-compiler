#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "err.h"
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

static char *read_file(const char *fname)
{
	FILE *f = fopen(fname, "r");

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
	const char *ifname = NULL;
	const char *ofname = NULL;
	int verbose = 0;

	for (int i = 1; i < argc; i++)
	{
		char *arg = argv[i];

		if (strcmp(arg, "-v") == 0)
		{
			verbose = 1;
		}
		else if (strcmp(arg, "-o") == 0)
		{
			if (ofname != NULL)
			{
				fprintf(stderr,
					"error: multiple output files "
					"specified\n");

				return EXIT_FAILURE;
			}

			i++;

			if (i == argc)
			{
				fprintf(stderr,
					"error: expected output filename\n");

				return EXIT_FAILURE;
			}

			arg = argv[i];
			ofname = arg;
		}
		else
		{
			if (ifname != NULL)
			{
				fprintf(stderr,
					"error: multiple input files "
					"specified\n");

				return EXIT_FAILURE;
			}

			ifname = arg;
		}
	}

	char *input;

	if (ifname == NULL || strcmp(ifname, "-") == 0)
	{
		ifname = "stdin";
		input = read_stdin();
	}
	else
	{
		input = read_file(ifname);
	}

	if (input == NULL)
	{
		fprintf(stderr, "error: failed to read `%s`\n", ifname);

		return EXIT_FAILURE;
	}

	tok_t *tok_list;

	{
		err_t *err_list = NULL;
		err_t *err_st = err_save(&err_list);

		tok_list = lex(input, ifname, &err_list);

		err_print(err_list);
		err_rstor(&err_list, err_st);
	}

	if (tok_list == NULL)
	{
		return EXIT_FAILURE;
	}

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
	}

	ast_t *ast_list;

	{
		err_t *err_list = NULL;
		err_t *err_st = err_save(&err_list);

		ast_list = parse(tok_list, &err_list);

		err_print(err_list);
		err_rstor(&err_list, err_st);
	}

	if (ast_list == NULL)
	{
		return EXIT_FAILURE;
	}

	if (verbose)
	{
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

	if (ofname != NULL && strcmp(ofname, "-") != 0)
	{
		if (freopen(ofname, "w", stdout) == NULL)
		{
			fprintf(stderr,
				"error: failed to open `%s` for writing\n",
				ofname);

			return EXIT_FAILURE;
		}
	}

	gen(ast_list);

	ast_del_list(ast_list);
	tok_del_list(tok_list);
	xfree(input);
}
