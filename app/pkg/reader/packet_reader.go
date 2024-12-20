package reader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type Packet struct {
	SrcIP   uint32
	DstIP   uint32
	PktSize uint32
}

type PacketReader struct {
	reader *ringbuf.Reader
}

// NewRingBufferReader creates a new RingBufferReader instance
func NewRingBufferReader(dataMap *ebpf.Map) (*PacketReader, error) {
	rbReader, err := ringbuf.NewReader(dataMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create ring buffer reader: %v", err)
	}
	return &PacketReader{
		reader: rbReader,
	}, nil
}

// Close closes the ring buffer reader
func (rb *PacketReader) Close() {
	rb.reader.Close()
}

// Read reads from the ring buffer and processes the packet
func (rb *PacketReader) Read() (string, error) {
	record, err := rb.reader.Read()
	if err != nil {
		return "", fmt.Errorf("failed to read from ring buffer: %v", err)
	}

	rawData := record.RawSample
	var pkt Packet
	reader := bytes.NewReader(rawData)
	err = binary.Read(reader, binary.BigEndian, &pkt)
	if err != nil {
		return "", fmt.Errorf("failed to decode packet: %v", err)
	}

	// Format packet data (for example, this can be used to pass data to a Python script)
	data := fmt.Sprintf("%s, %s, %d", uint32ToIP(pkt.SrcIP), uint32ToIP(pkt.DstIP), pkt.PktSize)
	return data, nil
}

func uint32ToIP(ipUint32 uint32) string {
	// Convert from network byte order to host byte order
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, ipUint32)

	// Convert to net.IP and then to string
	ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
	return ip.String()
}
