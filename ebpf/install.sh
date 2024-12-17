# list programs on enp0s3
sudo bpftool net list dev enp0s3

# delete program
sudo bpftool net detach xdp dev enp0s3

# read logs
sudo cat /sys/kernel/debug/tracing/trace_pipe