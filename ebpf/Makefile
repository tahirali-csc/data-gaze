# Variables
CLANG := clang
LLC := llc
BPFTOOL := bpftool
SRC := packet_tracker.c
OBJ := packet_tracker.o
BPF_DIR := /sys/fs/bpf
PROG_NAME := packet_tracker
# test interface for loading the program
IFACE := enp0s3

# Default target
all: build install

# Compile eBPF program
build:
	$(CLANG) -O2 -g -target bpf -c $(SRC) -o $(OBJ)
	cp $(OBJ) ../app/

# Install eBPF program
remove_prog:
	sudo bpftool net detach xdp dev $(IFACE)
	sudo rm -rf /sys/fs/bpf/$(PROG_NAME)

install:
	sudo $(BPFTOOL) prog load $(OBJ) $(BPF_DIR)/$(PROG_NAME)
	sudo $(BPFTOOL) net attach xdp pinned $(BPF_DIR)/$(PROG_NAME) dev $(IFACE)
    # sudo ip link set dev cni0 xdp obj $(BPF_DIR)/$(PROG_NAME)

# Clean up
clean:
	rm -f $(OBJ)

.PHONY: all build install clean