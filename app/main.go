package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Packet struct {
	SrcIP   uint32
	DstIP   uint32
	PktSize uint32
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("packet_tracker.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["capture_packet"]
	if prog == nil {
		log.Fatalf("Program 'xdp_prog' not found")
	}

	ringBuffer, err := ringbuf.NewReader(coll.Maps["ringbuf"])
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader: %v", err)
	}
	defer ringBuffer.Close()

	iface, err := net.InterfaceByName("enp0s3")
	if err != nil {
		log.Fatal(err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		// Flags:     link.XDPGeneric,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()

	for {
		record, err := ringBuffer.Read()
		if err != nil {
			log.Printf("Failed to read from ring buffer: %v", err)
			continue
		}

		fmt.Println(record)

		// var pkt Packet
		// err = binary.Read(record, binary.LittleEndian, &pkt)
		// if err != nil {
		// 	log.Printf("Failed to decode packet: %v", err)
		// 	continue
		// }

		// // Format packet data for Python script
		// data := fmt.Sprintf("%d,%d,%d\n", pkt.SrcIP, pkt.DstIP, pkt.PktSize)
		// fmt.Println(data)
		// cmd := exec.Command("python3", "predict.py")
		// cmd.Stdin = strings.NewReader(data)
		// output, err := cmd.Output()
		// if err != nil {
		//     log.Printf("Failed to execute Python script: %v", err)
		//     continue
		// }

		// log.Printf("Python script output: %s", output)
	}
}
