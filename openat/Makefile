CLANG ?= clang
STRIP ?= llvm-strip
# CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CFLAGS := -O2 -g  $(CFLAGS)


.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS) -D__TARGET_ARCH_x86
generate:
	go generate
