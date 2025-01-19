# Variables
CLANG := clang
LLC := llc
BPFTOOL := bpftool
# SRC := packet_tracker.c
OBJ_DIR := ./obj
OBJ := $(OBJ_DIR)/data_gaze.o
BPF_DIR := /sys/fs/bpf
PROG_NAME := packet_tracker
# test interface for loading the program
IFACE := enp0s3

# Default target
all: build install

# Compile eBPF program
build: clean 
# -g enable the debugging
	@mkdir -p $(OBJ_DIR)  # Create obj directory if not exists
	# Compile each .c file in xdp and inet directories into individual .o files
	$(CLANG) -O2 -g -target bpf -c ./xdp/*.c -o $(OBJ_DIR)/xdp.o
	$(CLANG) -O2 -g -target bpf -c ./inet/*.c -o $(OBJ_DIR)/inet.o
	# Generate final BPF object file using bpftool
	@OBJECT_FILES=$$(find $(OBJ_DIR) -type f -name "*.o"); \
	echo "Object files: $$OBJECT_FILES"; \
	bpftool gen object $(OBJ) $$OBJECT_FILES
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
	rm -rf $(OBJ_DIR)

.PHONY: all build install clean