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
INSTALL_PATH=/usr/local/

.PHONY: all clean docs install

all: libICP.a

stage1.a: stage1/*
	cd stage1 && goimports -w .
	cd stage1 && go fmt
	cd stage1 && go build -v -i -o ../$@ -buildmode=c-archive

stage2.o: stage2/stage2.c stage1.a
	$(CC) -c stage2/stage2.c -o $@ -I. -Istage1

libICP.a: stage1.a stage2.o
	libtool -o libICP.a stage1.a stage2.o

examples/%.bin: examples/%.c libICP.a
	$(CC) $(CCFLAGS) -o $@ $^

docs: $(MANFILES) $(TXTFILES) $(HTMLFILES)

docs/%:
	mkdir -p $@

docs/man/%.3: docs/src/%.pod docs/man
	pod2man -n ${subst .3,,${subst docs/man/,,$@}} -s "3" -r "0.0.1" -c "OpenICP-BR" $^ > $@

docs/txt/%.3.txt: docs/man/%.3 docs/txt
	man $^ > $@

docs/html/%.3.html: docs/txt/%.3.txt docs/html
	man2html -cgiurl \$$title.\$$section.html -topm 0 < $^ > $@

clean:
	rm *.a *.o *.so

install: libICP.a libICP.h $(MANFILES) $(HTMLFILES)
	-mkdir -pv $(INSTALL_PATH)/share/man/man3/
	-mkdir -pv $(INSTALL_PATH)/include/
	-mkdir -pv $(INSTALL_PATH)/lib/
	cp docs/man/*.3 $(INSTALL_PATH)/share/man/man3/
	cp docs/html/*.3.html $(INSTALL_PATH)/share/man/man3/
	cp libICP.h $(INSTALL_PATH)/include/
	cp libICP.a $(INSTALL_PATH)/lib


