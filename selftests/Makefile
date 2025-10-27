.PHONY: clean test

BPF_SOURCES = $(wildcard ../alloc/*.bpf.c) $(wildcard ../lib/*.bpf.c) $(wildcard *.bpf.c)
BPF_OBJECTS = $(notdir $(BPF_SOURCES:.bpf.c=.bpf.o))
vpath %.bpf.c ../alloc ../lib .

BPFTOOL=bpftool

INCLUDES=-I../include -I../include/arch -I ../include/arch/bpf-compat

BPF_CFLAGS=--target=bpf -g -O2 -Wall -Wno-compare-distinct-pointer-types -D__TARGET_ARCH_x86 -mcpu=v3 -mlittle-endian -c
BPF_ASAN_FLAGS=-fsanitize=address -shared-libasan -fno-sanitize-link-runtime 
BPF_LLVM_FLAGS=-mllvm -asan-instrument-address-spaces=1 -mllvm -asan-use-stack-safety=0 -mllvm -asan-stack=0 -mllvm -asan-kernel=1

BPF_FLAGS=$(BPF_CFLAGS) $(BPF_ASAN_FLAGS) $(BPF_LLVM_FLAGS)

BPF_CFLAGS+=-I../vmlinux -I/usr/include/bpf -I/usr/include/$(shell uname -m)-linux-gnu 
BPF_CFLAGS+=$(INCLUDES)

LIBBPF_DIR=../bpftool/src/libbpf
LIBBPF_A=$(LIBBPF_DIR)/libbpf.a
CFLAGS=-O2 -no-pie
CFLAGS+=$(INCLUDES)
CFLAGS+=-I$(LIBBPF_DIR)/include
LDFLAGS=$(LIBBPF_A) -lelf -lz -lzstd

test: selftest
	sudo ./$<

selftest: selftest.c selftest.skel.h
	clang $(CFLAGS) $< $(LDFLAGS) -o $@

selftest.skel.h: main.bpf.o
	$(BPFTOOL) gen skeleton $< name "selftest" > $@

main.bpf.o: $(BPF_OBJECTS)
	$(BPFTOOL) gen object $@ $^
	objcopy --change-section-address .addr_space.1=0x1000000 $@ $@

%.bpf.o: %.bpf.c
	clang $(BPF_FLAGS) -c $< -o $@
		
clean:
	rm -f *.skel.h *.bpf.o selftest
