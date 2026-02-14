# eBPF Programs Makefile
# Compiles .bpf.c files to .bpf.o object files for loading into the kernel

# Compiler
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

# Architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Kernel headers
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
LIBBPF_HEADERS := /usr/include

# Output directory
OUTPUT := ../build/lib/bpf

# Source files
SOURCES := $(wildcard monitors/*.bpf.c)
OBJECTS := $(patsubst monitors/%.bpf.c,$(OUTPUT)/%.bpf.o,$(SOURCES))

# Compiler flags for eBPF
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS += -I$(LIBBPF_HEADERS)
CFLAGS += -I$(KERNEL_HEADERS)/include
CFLAGS += -I$(KERNEL_HEADERS)/include/uapi
CFLAGS += -I$(KERNEL_HEADERS)/include/generated
CFLAGS += -I$(KERNEL_HEADERS)/include/generated/uapi
CFLAGS += -I$(KERNEL_HEADERS)/arch/$(ARCH)/include
CFLAGS += -I$(KERNEL_HEADERS)/arch/$(ARCH)/include/uapi
CFLAGS += -I$(KERNEL_HEADERS)/arch/$(ARCH)/include/generated
CFLAGS += -I$(KERNEL_HEADERS)/arch/$(ARCH)/include/generated/uapi

# Disable some warnings that are common in BPF code
CFLAGS += -Wno-unused-value
CFLAGS += -Wno-pointer-sign
CFLAGS += -Wno-compare-distinct-pointer-types

.PHONY: all clean

all: $(OBJECTS)

$(OUTPUT):
	@mkdir -p $(OUTPUT)

$(OUTPUT)/%.bpf.o: monitors/%.bpf.c | $(OUTPUT)
	@echo "  BPF     $@"
	@$(CLANG) $(CFLAGS) -c $< -o $@
	@$(LLVM_STRIP) -g $@

clean:
	@rm -rf $(OUTPUT)/*.bpf.o
	@echo "Cleaned eBPF objects"

install: all
	@echo "Installing eBPF programs to /opt/koraav/lib/bpf/"
	@mkdir -p /opt/koraav/lib/bpf
	@install -m 644 $(OUTPUT)/*.bpf.o /opt/koraav/lib/bpf/
	@echo "eBPF programs installed"

# Debug: show what would be built
show:
	@echo "Sources: $(SOURCES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Architecture: $(ARCH)"
