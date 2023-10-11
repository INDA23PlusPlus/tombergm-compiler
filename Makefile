CFLAGS	= -Wall -Og -g
ASFLAGS	= -Wall -g

all: fib

fib: fib.s
	$(LINK.s) -o $@ $^

fib.s: fib.dpp compiler
	cat $< | xargs -d '\0' ./compiler >$@

compiler: ast.c gen.c lex.c main.c parse.c tok.c xmalloc.c
	$(LINK.c) -o $@ $^

clean:
	rm -f fib fib.s compiler
