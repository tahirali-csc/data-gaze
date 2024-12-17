rm -rf packet_tracker.o
# add -g
# https://lists.iovisor.org/g/iovisor-dev/topic/reading_pinned_maps_in_ebpf/76194102
clang -O2 -g -target bpf -c packet_tracker.c -o packet_tracker.o
cp packet_tracker.o ../app/

# llvm-objdump -h packet_tracker.o

sudo bpftool net detach xdp dev enp0s3

sudo rm -rf /sys/fs/bpf/packet_tracker

sudo bpftool prog load packet_tracker.o /sys/fs/bpf/packet_tracker
sudo bpftool net attach xdp pinned /sys/fs/bpf/packet_tracker dev enp0s3
sudo bpftool net list dev enp0s3