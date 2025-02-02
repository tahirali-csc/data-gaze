package model

type Packet struct {
	SrcIP   uint32 `json:"srcIp"`
	DstIP   uint32 `json:"dstIp"`
	SrcPort uint16 `json:"srcPort"`
	DstPort uint16 `json:"dstPort"`
	PktSize uint32 `json:"pktSize"`
}
