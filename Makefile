CFLAGS	= -Wall -Og -g
ASFLAGS	= -g

DPPC	= ./dppc
PROGS	= ack fib prime
PROGS_O	= $(PROGS:%=%.o)
PROGS_S	= $(PROGS:%=%.s)

.PHONY: all clean

all: $(PROGS)

clean:
	rm -f $(PROGS) $(PROGS_O) $(PROGS_S) $(DPPC)

$(PROGS): %: %.o
	$(LD) $(LDFLAGS) -o $@ $^

$(PROGS_O): %.o: %.s
	$(AS) $(ASFLAGS) -o $@ $<

$(PROGS_S): %.s: %.dpp $(DPPC)
	$(DPPC) $(DPPCFLAGS) -o $@ $<

$(DPPC): ast.c err.c gen.c lex.c main.c parse.c tok.c where.c xmalloc.c
	$(LINK.c) -o $@ $^
