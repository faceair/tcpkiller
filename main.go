package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var iface, filter string
	flag.StringVar(&iface, "i", "eth0", "specify the interface to listen on")
	flag.Parse()

	filter = strings.Join(flag.Args(), " ")

	handle, err := pcap.OpenLive(iface, 64, true, time.Millisecond)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
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

		if tcp.FIN || tcp.RST {
			continue
		}

		fmt.Printf("%s:%d > %s:%d\n", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort)

		neth := &layers.Ethernet{
			SrcMAC:       eth.DstMAC,
			DstMAC:       eth.SrcMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		nip := &layers.IPv4{
			SrcIP:    ip.DstIP,
			DstIP:    ip.SrcIP,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		ntcp := &layers.TCP{
			SrcPort: tcp.DstPort,
			DstPort: tcp.SrcPort,
			RST:     true,
			Seq:     tcp.Ack,
		}
		ntcp.SetNetworkLayerForChecksum(nip)

		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, options, neth, nip, ntcp); err != nil {
			panic(err)
		}

		if err := handle.WritePacketData(buffer.Bytes()); err != nil {
			panic(err)
		}

	}
}
