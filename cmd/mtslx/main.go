// mtslx is a command-line tool for scanning TLS traffic and computing
// JA3/JA3S fingerprints from PCAP files or live network interfaces.
package main

import (
	"flag"
	"time"

	"github.com/Vytek/mtslx"
)

const version = "v0.1.1"

func main() {
	var (
		iface   string
		IP      string
		port    int
		timeout time.Duration
	)

	flag.StringVar(&iface, "i", "", "Network interface to capture from")
	flag.StringVar(&IP, "ip", "", "IP address to capture TLS traffic from")
	flag.IntVar(&port, "port", 443, "Port to capture TLS traffic from")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "Timeout for capturing TLS traffic")

	mtslx.RetrieveIPTLS(IP, port, iface, timeout)
}
