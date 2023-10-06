CFLAGS	= -Wall -Og -g

all: bin/compiler

bin/compiler: ast.c lex.c main.c parse.c tok.c xmalloc.c | bin/
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^

%/:
	mkdir -p $@

