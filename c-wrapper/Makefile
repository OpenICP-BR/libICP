CC=gcc
CCFLAGS=-I.
ifeq ($(OS),Windows_NT)
	CCFLAGS += -D WIN32
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CCFLAGS += -D LINUX
	endif
	ifeq ($(UNAME_S),Darwin)
		CCFLAGS += -framework CoreFoundation -framework Security
	endif
endif

DOCFILES := $(shell find ./docs/src -type f -name "*.pod")
MANFILES := ${subst docs/src,docs/man,$(patsubst %.pod,%.3,$(DOCFILES))}
TXTFILES := ${subst docs/src,docs/txt,$(patsubst %.pod,%.3.txt,$(DOCFILES))}
HTMLFILES := ${subst docs/src,docs/html,$(patsubst %.pod,%.3.html,$(DOCFILES))}



.PHONY: all clean docs

all: libICP.a

stage1.a: stage1/stage1.go
	cd stage1 && goimports -w .
	cd stage1 && go fmt
	cd stage1 && go build -v -i -o ../$@ -buildmode=c-archive

stage2.o: stage1.h stage2/stage2.c
	$(CC) -c stage2/stage2.c -o $@ -I.

libICP.a: stage1.a stage2.o
	libtool -o libICP.a stage1.a stage2.o

examples/%.bin: examples/%.c libICP.a
	$(CC) $(CCFLAGS) -o $@ $^

docs: $(MANFILES) $(TXTFILES) $(HTMLFILES)

docs/man/%.3: docs/src/%.pod
	pod2man -n ${subst .3,,${subst docs/man/,,$@}} -s "3" -r "0.0.1" -c "OpenICP-BR" $^ > $@

docs/txt/%.3.txt: docs/man/%.3
	man $^ > $@

docs/html/%.3.html: docs/txt/%.3.txt
	man2html -cgiurl \$$title.\$$section.html -topm 0 < $^ > $@

clean:
	rm *.a *.o *.so