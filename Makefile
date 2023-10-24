CFLAGS	= -Wall -Og -g
ASFLAGS	= -Wall -g

PROGS	= ack fib prime

.PHONY: all clean

all: $(PROGS)

$(PROGS): %: %.s
	$(LINK.s) -o $@ $^

$(PROGS:%=%.s): %.s: %.dpp dppc
	./dppc $(DPPFLAGS) -o $@ $<

dppc: ast.c err.c gen.c lex.c main.c parse.c tok.c where.c xmalloc.c
	$(LINK.c) -o $@ $^

clean:
	rm -f $(PROGS:%=%.s) $(PROGS) dppc
