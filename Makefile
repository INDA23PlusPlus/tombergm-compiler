CFLAGS	= -Wall -Og -g
ASFLAGS	= -Wall -g

PROGS	= fib prime

.PHONY: all clean

all: $(PROGS)

$(PROGS): %: %.s
	$(LINK.s) -o $@ $^

$(PROGS:%=%.s): %.s: %.dpp compiler
	./compiler $(DPPFLAGS) -o $@ $<

compiler: ast.c gen.c lex.c main.c parse.c tok.c xmalloc.c
	$(LINK.c) -o $@ $^

clean:
	rm -f $(PROGS:%=%.s) $(PROGS) compiler
