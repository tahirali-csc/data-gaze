# Installs necessary ebpf related dependencies
sudo apt update
sudo apt install clang -y

sudo apt install linux-headers-$(uname -r) -y
# bpf_helpers.h and other eBPF utility headers are part of the libbpf package
sudo apt install libbpf-dev

# hack for this error
# usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found 
# https://stackoverflow.com/questions/77454504/asm-types-h-error-during-compilation-of-ebpf-code
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

