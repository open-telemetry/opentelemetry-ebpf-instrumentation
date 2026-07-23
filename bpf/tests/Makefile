CC=clang
CFLAGS=-Wall -Werror -g -I. -I.. # the order here matters to override bpfcore
LFLAGS=

sources = $(wildcard *.c)
targets = $(sources:.c=)

all: $(targets)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LFLAGS)

.PHONY: test
test: $(targets)
	@set -e; for t in $(targets); do echo "### running $$t"; ./$$t; done
	@echo "All BPF unit tests passed"

.PHONY: clean
clean:
	rm -f $(targets)
