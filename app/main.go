package main

import (
	"bytes"
	"encoding/binary"
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

func uint32ToIP(ipUint32 uint32) string {
	// Convert from network byte order to host byte order
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, ipUint32)

	// Convert to net.IP and then to string
	ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
	return ip.String()
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

		// fmt.Println(record)

		rawData := record.RawSample

		var pkt Packet
		reader := bytes.NewReader(rawData)
		err = binary.Read(reader, binary.BigEndian, &pkt)
		if err != nil {
			log.Printf("Failed to decode packet: %v", err)
			continue
		}

		// // Format packet data for Python script
		data := fmt.Sprintf("%s, %s, %d", uint32ToIP(pkt.SrcIP), uint32ToIP(pkt.DstIP), pkt.PktSize)
		fmt.Println(data)
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
