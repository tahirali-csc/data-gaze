package reader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// Define the event structure that matches what the eBPF program emits.
type inetSockEvent struct {
	Comm    [16]byte
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
	_       [4]byte
	DeltaUs uint64
	RxB     uint64
	TxB     uint64
	Closed  bool
	_       [7]byte
}

type NetSocketReader struct {
	events *ebpf.Map
}

func NewNetSocketReader(events *ebpf.Map) *NetSocketReader {
	return &NetSocketReader{
		events: events,
	}
}

func (nsr *NetSocketReader) Read() {
	rd, err := perf.NewReader(nsr.events, 4096)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	for {
		// Read from the perf buffer
		record, err := rd.Read()
		if err != nil {
			log.Printf("Error reading from perf buffer: %v", err)
			continue
		}

		// Parse the data emitted by the eBPF program
		var event inetSockEvent
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Printf("Failed to parse event: %v", err)
			continue
		}

		// log.Println(event)

		// Log the event details
		fmt.Printf("Prog %s Sadd: %s Sport%d Daddr: %s Dport: %d\n",
			string(bytes.Trim(event.Comm[:], "\x00")),
			intToIPv4(event.Saddr),
			event.Sport,
			intToIPv4(event.Daddr),
			event.Dport)
	}
}

func intToIPv4(ipUint32 uint32) string {
	// Convert from network byte order to host byte order
	// ipBytes := make([]byte, 4)
	// binary.BigEndian.PutUint32(ipBytes, ipUint32)

	// // Convert to net.IP and then to string
	// ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
	// return ip.String()

	// return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipUint32)
	return ip.String()
}
