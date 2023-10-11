CFLAGS	= -Wall -Og -g
ASFLAGS	= -Wall -g

.PHONY: all clean

all: fib

fib: fib.s
	$(LINK.s) -o $@ $^

fib.s: fib.dpp compiler
	./compiler $(DPPFLAGS) -o $@ $<

compiler: ast.c gen.c lex.c main.c parse.c tok.c xmalloc.c
	$(LINK.c) -o $@ $^

clean:
	rm -f fib fib.s compiler
