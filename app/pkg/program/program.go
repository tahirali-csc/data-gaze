package program

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func Load(file string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("Failed to load eBPF program: %v", err)
	}

	return coll, nil
}

func Attach(prog *ebpf.Program, ifaceName string) (link.Link, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	return link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		// Flags:     link.XDPGeneric,
	})
}
