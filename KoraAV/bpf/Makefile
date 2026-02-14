# eBPF Programs Makefile
# Compiles .bpf.c files to .bpf.o object files for loading into the kernel

# Compiler
CLANG ?= clang
LLVM_STRIP ?= llvm_strip
BPFTOOL ?= bpftool

# Architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Output directory
OUTPUT := ../build/lib/bpf

# Vmlinux header
VMLINUX_H := monitors/vmlinux.h
VMLINUX_BTF := /sys/kernel/btf/vmlinux

# Source files
SOURCES := $(wildcard monitors/*.bpf.c)
OBJECTS := $(patsubst monitors/%.bpf.c,$(OUTPUT)/%.bpf.o,$(SOURCES))

# Compiler flags for eBPF
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS += -Wall -Werror
CFLAGS += -Wno-unused-value
CFLAGS += -Wno-pointer-sign
CFLAGS += -Wno-compare-distinct-pointer-types
CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
CFLAGS += -Wno-address-of-packed-member
CFLAGS += -Wno-tautological-compare
CFLAGS += -Wno-unknown-warning-option

.PHONY: all clean vmlinux

all: vmlinux $(OBJECTS)

$(OUTPUT):
	@mkdir -p $(OUTPUT)

# Generate vmlinux.h from BTF
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@if [ -f $(VMLINUX_BTF) ]; then \
		echo "  GEN     $@"; \
		$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@; \
	else \
		echo "  WARN    BTF not found at $(VMLINUX_BTF)"; \
		echo "  WARN    Creating minimal vmlinux.h"; \
		echo "#ifndef __VMLINUX_H__" > $@; \
		echo "#define __VMLINUX_H__" >> $@; \
		echo "typedef unsigned char __u8;" >> $@; \
		echo "typedef unsigned short __u16;" >> $@; \
		echo "typedef unsigned int __u32;" >> $@; \
		echo "typedef unsigned long long __u64;" >> $@; \
		echo "#endif" >> $@; \
	fi

$(OUTPUT)/%.bpf.o: monitors/%.bpf.c $(VMLINUX_H) | $(OUTPUT)
	@echo "  BPF     $@"
	@$(CLANG) $(CFLAGS) -c $< -o $@
	@$(LLVM_STRIP) -g $@

clean:
	@rm -rf $(OUTPUT)/*.bpf.o $(VMLINUX_H)
	@echo "Cleaned eBPF objects and vmlinux.h"

install: all
	@echo "Installing eBPF programs to /opt/koraav/lib/bpf/"
	@mkdir -p /opt/koraav/lib/bpf
	@install -m 644 $(OUTPUT)/*.bpf.o /opt/koraav/lib/bpf/
	@echo "✓ eBPF programs installed"

# Debug: show what would be built
show:
	@echo "Sources: $(SOURCES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Architecture: $(ARCH)"
	@echo "Vmlinux: $(VMLINUX_H)"
