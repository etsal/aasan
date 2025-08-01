
LLVMDIR=$(PWD)/../llvm-project/
INCLUDEDIR=$(PWD)/include
BPFTOOL=$(PWD)/../bpftool
LIBBPF=$(BPFTOOL)/src/libbpf

CC=$(LLVMDIR)/build/bin/clang 
FLAGS=--target=bpf -g -O2 -Wall -Wno-compare-distinct-pointer-types -D__TARGET_ARCH_x86 -mcpu=v3 -mlittle-endian -c
ASANFLAGS=-fsanitize=address -shared-libasan -fno-sanitize-link-runtime 
LLVMFLAGS=-mllvm -asan-instrument-address-spaces=1 -mllvm -asan-use-stack-safety=0 -mllvm -asan-stack=0 
INCLUDEFLAGS=-I$(INCLUDEDIR)/arch/x86 -I$(INCLUDEDIR) -I$(INCLUDEDIR)/bpf-compat 
INCLUDEFLAGS+=-idirafter $(LLVMDIR)/build/lib/clang/21/include -idirafter /usr/local/include -idirafter /usr/include -I$(LIBBPF)/include

BUILDDIR=$(PWD)/build

build/rusty.bpf.o: rusty/main.bpf.c
	cd rusty; $(CC) $(FLAGS) $(ASANFLAGS) $(LLVMFLAGS) $(INCLUDEFLAGS) -o ../$@ main.bpf.c
