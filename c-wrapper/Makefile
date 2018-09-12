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


.PHONY: all clean

all: libICP.a

stage1.a: stage1.go
	go build -v -i -o $@ -buildmode=c-archive $<

stage2.o: stage2.c
	$(CC) -c $< -o $@

libICP.a: stage1.a stage2.o
	libtool -o libICP.a stage1.a stage2.o

examples/%.bin: examples/%.c libICP.a
	$(CC) $(CCFLAGS) -o $@ $^

clean:
	rm *.a *.o *.so