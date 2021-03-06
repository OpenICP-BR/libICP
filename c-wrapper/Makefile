CC=gcc
CXX=g++
LIBTOOL = libtool
CFLAGS=-fPIC -O2 -pedantic -Wall -Wextra -Wundef -Wshadow -Wunreachable-code -Wfloat-equal -Werror -I.
LDFLAGS=
ifeq ($(OS),Windows_NT)
	LDFLAGS += -l winmm -l ntdll -l Ws2_32
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		LIBTOOL = libtool
		LDFLAGS += -pthread
		LDFLAGS +=  -pthread
	endif
	ifeq ($(UNAME_S),Darwin)
		LIBTOOL = glibtool
		LDFLAGS += -framework CoreFoundation -framework Security
		LDFLAGS += -framework CoreFoundation -framework Security
	endif
endif
CXXFLAGS:=$(CFLAGS) -std=gnu++98 # It was c++11, but g++ on MinGW is a bit weird
CFLAGS+= -std=c99

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
C_OBJS := $(patsubst %.c,%.o,$(shell find ./stage2 -type f -name "*.c"))
CPP_OBJS := $(patsubst %.cpp,%.o,$(shell find ./stage3 -type f -name "*.cpp"))
INSTALL_PATH=/usr/local/

.PHONY: all clean docs install examples

all: libICP++.a libICP.a examples

stage1.a: stage1/*
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Fixing imports..."$(ANSI_RESET)
	-cd stage1 && goimports -w .
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Formatting code..."$(ANSI_RESET)
	cd stage1 && go fmt
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Compiling code..."$(ANSI_RESET)
	cd stage1 && go build -v -o ../$@ -buildmode=c-archive
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

stage2/%.o: stage2/%.c stage1.a
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Compiling code..."$(ANSI_RESET)
	$(CC) $(CFLAGS) -c $< -o $@ -I. -Istage1 $(LDFLAGS)
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

stage3/%.o: stage3/%.cpp libICP.a libICP++.h
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Compiling code..."$(ANSI_RESET)
	$(CXX) $(CXXFLAGS) -c $< -o $@ -I. -L. -lICP.a $(LDFLAGS)
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

libICP.a: stage1.a $(C_OBJS)
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Joining libraries..."$(ANSI_RESET)
	cd stage1 && ar -x ../stage1.a
	ar -cr libICP.a $(C_OBJS) stage1/*.o
	ranlib libICP.a
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

libICP++.a: libICP.a $(C_OBJS) $(CPP_OBJS)
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Joining libraries..."$(ANSI_RESET)
	ar -cr libICP++.a stage1/*.o $(C_OBJS) $(CPP_OBJS)
	ranlib libICP++.a
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)

examples: $(EXAMPLES)

examples/%.bin: examples/%.c libICP.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

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
	-rm *.a *.o *.so *.dll
	-cd stage1 && rm *.a *.o *.so *.dll
	-cd stage2 && rm *.a *.o *.so *.dll
	-cd stage3 && rm *.a *.o *.so *.dll

install: libICP.a libICP.h libICP++.a libICP++.h $(MANFILES) $(HTMLFILES) examples
	@$(ECHO) -e $(ANSI_GREEN)"["$@"] Installing to "$(INSTALL_PATH)$(ANSI_RESET)
	-mkdir -pv $(INSTALL_PATH)/share/man/man3/
	-mkdir -pv $(INSTALL_PATH)/include/
	-mkdir -pv $(INSTALL_PATH)/lib/
	cp docs/man/*.3 $(INSTALL_PATH)/share/man/man3/
	cp docs/html/*.3.html $(INSTALL_PATH)/share/man/man3/
	cp libICP.h $(INSTALL_PATH)/include/
	cp libICP.a $(INSTALL_PATH)/lib
	cp libICP++.h $(INSTALL_PATH)/include/
	cp libICP++.a $(INSTALL_PATH)/lib
	@$(ECHO) -e $(ANSI_BLUE)"["$@"] Finished target $@"$(ANSI_RESET)


