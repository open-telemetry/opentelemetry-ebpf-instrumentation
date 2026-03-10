CC=clang
CFLAGS=-Wall -Werror -g -I. -I.. # the order here matters to override bpfcore
LFLAGS=

sources = $(wildcard *.c)
targets = $(sources:.c=)

all: $(targets)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LFLAGS)

.PHONY: clean
clean:
	rm -f $(targets)
