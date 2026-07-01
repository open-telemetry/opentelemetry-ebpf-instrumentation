
CC=gcc
CFLAGS= -std=gnu11
LDFLAGS=-lelf -ldl -Wl,-z,noexecstack
VERSION=0.1.0

PREFIX=/usr

ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    ASM_SRC = src/asm/libstapsdt-aarch64.s
    ASM_OBJ = build/lib/libstapsdt-aarch64.o
else
    ASM_SRC = src/asm/libstapsdt-x86_64.s
    ASM_OBJ = build/lib/libstapsdt-x86_64.o
endif

OBJECTS = $(patsubst src/%.c, build/lib/%.o, $(wildcard src/*.c))
HEADERS = $(wildcard src/*.h)

SOLINK = libstapsdt.so
SONAME = libstapsdt.so.0

all: out/libstapsdt.a out/$(SONAME)

install:
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	mkdir -p $(DESTDIR)$(PREFIX)/include
	cp out/$(SONAME) $(DESTDIR)$(PREFIX)/lib/$(SONAME)
	cp src/libstapsdt.h $(DESTDIR)$(PREFIX)/include/
	ln -sf $(SONAME) $(DESTDIR)$(PREFIX)/lib/$(SOLINK)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(SONAME)
	rm -f $(DESTDIR)$(PREFIX)/lib/$(SOLINK)
	rm -f $(DESTDIR)$(PREFIX)/include/libstapsdt.h

$(ASM_OBJ): $(ASM_SRC)
	mkdir -p build/lib
	$(CC) $(CFLAGS) -fPIC -c $^ -o $@

build/lib/%.o: src/%.c $(HEADERS)
	mkdir -p build/lib/
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

out/libstapsdt.a: $(OBJECTS) $(ASM_OBJ)
	mkdir -p out
	ar rcs $@ $^

out/$(SONAME): $(OBJECTS) $(ASM_OBJ)
	mkdir -p out
	$(CC) $(CFLAGS) -shared -Wl,-soname=$(SONAME) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf build/* out/*

.PHONY: all install uninstall clean
