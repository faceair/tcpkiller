package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("en0", 128, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter("tcp"); err != nil {
		panic(err)
	}

	options := gopacket.SerializeOptions{
		FixLengths: true,
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range src.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip := ipLayer.(*layers.IPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)

		if tcp.SYN || tcp.FIN || tcp.RST {
			continue
		}

		fmt.Printf("%s:%d > %s:%d\n", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort)

		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, options,
			&layers.Ethernet{
				SrcMAC:       eth.DstMAC,
				DstMAC:       eth.SrcMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{
				SrcIP:    ip.DstIP,
				DstIP:    ip.SrcIP,
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
			},
			&layers.TCP{
				SrcPort: tcp.DstPort,
				DstPort: tcp.SrcPort,
				Seq:     tcp.Ack,
				RST:     true,
				ACK:     true,
				Ack:     tcp.Seq + 1,
			},
		)
		if err != nil {
			panic(err)
		}

		if err := handle.WritePacketData(buffer.Bytes()); err != nil {
			panic(err)
		}

	}
}
