CC=gcc
LIBTOOL = libtool
CFLAGS=-std=c99 -O2 -pedantic -Wall -Wextra -Wundef -Wshadow -Wunreachable-code -Wfloat-equal -Werror -Wno-unused-command-line-argument
ifeq ($(OS),Windows_NT)
	CFLAGS += -D WIN32
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		LIBTOOL = libtool
		CFLAGS += -D LINUX
	endif
	ifeq ($(UNAME_S),Darwin)
		LIBTOOL = glibtool
		CFLAGS += -framework CoreFoundation -framework Security
	endif
endif

ANSI_RED="\033[0;31m"
ANSI_GREEN="\033[0;32m"
ANSI_BLUE="\033[0;34m"
ANSI_RESET="\033[0m"

ifneq ("$(wildcard /usr/local/opt/coreutils/libexec/gnubin/echo)","")
	ECHO="/usr/local/opt/coreutils/libexec/gnubin/echo"
else
	ECHO="/bin/echo"
endif

DOCFILES := $(shell find ./docs/src -type f -name "*.pod")
MANFILES := ${subst docs/src,docs/man,$(patsubst %.pod,%.3,$(DOCFILES))}
EXAMPLES := $(patsubst %.c,%.bin,$(shell find ./examples -type f -name "*.c"))
TXTFILES := ${subst docs/src,docs/txt,$(patsubst %.pod,%.3.txt,$(DOCFILES))}
HTMLFILES := ${subst docs/src,docs/html,$(patsubst %.pod,%.3.html,$(DOCFILES))}
INSTALL_PATH=/usr/local/

.PHONY: all clean docs install examples

all: libICP.a examples docs

stage1.a: stage1/*
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Fixing imports..."$(ANSI_RESET)
	cd stage1 && goimports -w .
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Formatting code..."$(ANSI_RESET)
	cd stage1 && go fmt
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Compiling code..."$(ANSI_RESET)
	cd stage1 && go build -v -i -o ../$@ -buildmode=c-archive
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

stage2.o: stage2/stage2.c stage1.a
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Compiling code..."$(ANSI_RESET)
	$(CC) $(CFLAGS) -c stage2/stage2.c -o $@ -I. -Istage1
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

libICP.a: stage1.a stage2.o
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Joining libraries..."$(ANSI_RESET)
	$(LIBTOOL) --tag=CC --mode=link gcc -o libICP.a stage1.a stage2.o
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

examples: $(EXAMPLES)

examples/%.bin: examples/%.c libICP.a
	$(CC) $(CFLAGS) -o $@ $^

docs: $(MANFILES) $(TXTFILES) $(HTMLFILES)
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

docs/man:
	mkdir -p $@
docs/html:
	mkdir -p $@
docs/txt:
	mkdir -p $@

docs/man/%.3: docs/src/%.pod docs/man
	pod2man -n ${subst .3,,${subst docs/man/,,$@}} -s "3" -r "0.0.1" -c "OpenICP-BR" $< > $@

docs/txt/%.3.txt: docs/man/%.3 docs/txt
	man $< > $@

docs/html/%.3.html: docs/txt/%.3.txt docs/html
	man2html -cgiurl \$$title.\$$section.html -topm 0 < $< > $@

clean:
	rm *.a *.o *.so

install: libICP.a libICP.h $(MANFILES) $(HTMLFILES)
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Installing to "$(INSTALL_PATH)$(ANSI_RESET)
	-mkdir -pv $(INSTALL_PATH)/share/man/man3/
	-mkdir -pv $(INSTALL_PATH)/include/
	-mkdir -pv $(INSTALL_PATH)/lib/
	cp docs/man/*.3 $(INSTALL_PATH)/share/man/man3/
	cp docs/html/*.3.html $(INSTALL_PATH)/share/man/man3/
	cp libICP.h $(INSTALL_PATH)/include/
	cp libICP.a $(INSTALL_PATH)/lib
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)


