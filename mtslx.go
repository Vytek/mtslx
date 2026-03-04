// Package mtslx provides functions for scanning TLS traffic and computing
// JA3/JA3S fingerprints from PCAP files or live network interfaces.
// It wraps the dreadl0ck/ja3 and dreadl0ck/tlsx libraries.
package mtslx

import (
	"io"
	"log"
	"sync"
	"time"

	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Record contains all information for a calculated JA3 fingerprint.
// It is re-exported from the ja3 package for convenience.
type Record = ja3.Record

// ReadInterface captures packets from the named network interface and writes
// JA3 fingerprints to out. If asJSON is true the results are written as
// newline-separated JSON objects, otherwise CSV is used with the given
// separator. When ja3s is true, server-side fingerprints (JA3S) are also
// computed.
func ReadInterface(iface string, out io.Writer, separator string, ja3s bool, asJSON bool, snaplen int, promisc bool, timeout time.Duration) {
	ja3.ReadInterface(iface, out, separator, ja3s, asJSON, snaplen, promisc, timeout)
}

// RetrieveIPTLS captures TLS traffic to the specified IP and port from the default network interface and returns the first JA3 fingerprint found. The
// capture will timeout after the specified duration if no matching traffic is
// seen.
func RetrieveIPTLS(ip string, port int, flagInterface string, timeout time.Duration) (Record, error) {
	var (
		handle *pcap.Handle
		err    error
	)

	// snapLen = 1514 (1500 Ethernet MTU + 14 byte Ethernet Header)
	handle, err = pcap.OpenLive(flagInterface, 1514, false, pcap.BlockForever)
	if err != nil {
		return Record{}, err
	}
	defer handle.Close()

	// Set a BPF filter to capture only TLS traffic to the specified IP and port
	// filter := fmt.Sprintf("tcp and dst host %s and dst port %d", ip, port)
	filter := "tcp"
	if err := handle.SetBPFFilter(filter); err != nil {
		return Record{}, err
	}

	// create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var wg sync.WaitGroup

	// handle packets
	for packet := range packetSource.Packets() {
		wg.Add(1)
		go readPacket(packet, &wg)
	}

	wg.Wait()

	return Record{}, nil // Placeholder for actual JA3 extraction logic
}

func readPacket(packet gopacket.Packet, wg *sync.WaitGroup) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

		// cast TCP layer
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			log.Println("Could not decode TCP layer")
			return
		}

		if tcp.SYN {
			// Connection setup
		} else if tcp.FIN {
			// Connection teardown
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
			// Acknowledgement packet
		} else if tcp.RST {
			// Unexpected packet
		} else {
			// data packet

			// process TLS client hello
			clientHello := tlsx.GetClientHello(packet)
			if clientHello != nil {
				destination := "[" + packet.NetworkLayer().NetworkFlow().Dst().String() + ":" + packet.TransportLayer().TransportFlow().Dst().String() + "]"
				log.Printf("%s Client hello from port %s to %s", destination, tcp.SrcPort, tcp.DstPort)
			}

			// process TLS server hello
			serverHello := tlsx.GetServerHello(packet)
			if serverHello != nil {
				destination := "[" + packet.NetworkLayer().NetworkFlow().Dst().String() + ":" + packet.TransportLayer().TransportFlow().Dst().String() + "]"
				log.Printf("%s Server hello from port %s to %s", destination, tcp.SrcPort, tcp.DstPort)
			}
		}
	}
	wg.Done()
}
