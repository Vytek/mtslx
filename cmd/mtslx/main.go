// mtslx is a command-line tool for scanning TLS traffic and computing
// JA3/JA3S fingerprints from PCAP files or live network interfaces.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dreadl0ck/ja3"
	"github.com/gopacket/gopacket/pcap"

	"github.com/Vytek/mtslx"
)

var (
	flagJSON      = flag.Bool("json", true, "print as JSON array")
	flagCSV       = flag.Bool("csv", false, "print as CSV")
	flagTSV       = flag.Bool("tsv", false, "print as TAB separated values")
	flagSeparator = flag.String("separator", ",", "set a custom separator")
	flagInput     = flag.String("read", "", "read PCAP file")
	flagDebug     = flag.Bool("debug", false, "toggle debug mode")
	flagInterface = flag.String("iface", "", "specify network interface to read packets from")
	flagJa3S      = flag.Bool("ja3s", true, "include ja3 server hashes (ja3s)")
	flagOnlyJa3S  = flag.Bool("ja3s-only", false, "dump ja3s only")
	flagSnaplen   = flag.Int("snaplen", 1514, "default snap length for ethernet frames")
	flagPromisc   = flag.Bool("promisc", true, "capture in promiscuous mode (requires root)")
	// https://godoc.org/github.com/gopacket/gopacket/pcap#hdr-PCAP_Timeouts
	flagTimeout = flag.Duration("timeout", pcap.BlockForever, "timeout for collecting packet batches")
	flagVersion = flag.Bool("version", false, "display version and exit")
)

const version = "v0.1.0"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  mtslx reads PCAP files or captures from a live interface and prints\n")
		fmt.Fprintf(os.Stderr, "  JA3/JA3S TLS fingerprints as JSON (default) or CSV.\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *flagVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	ja3.Debug = *flagDebug

	// live capture from a network interface
	if *flagInterface != "" {
		mtslx.ReadInterface(*flagInterface, os.Stdout, *flagSeparator, *flagJa3S, *flagJSON, *flagSnaplen, *flagPromisc, *flagTimeout)
		return
	}

	if *flagInput == "" {
		fmt.Fprintln(os.Stderr, "use the -read flag to supply an input file, or -iface for live capture.")
		flag.Usage()
		os.Exit(1)
	}

	if *flagOnlyJa3S {
		mtslx.ReadFileJa3s(*flagInput, os.Stdout)
		return
	}

	if *flagTSV {
		mtslx.ReadFileCSV(*flagInput, os.Stdout, "\t", *flagJa3S)
		return
	}

	if *flagCSV {
		mtslx.ReadFileCSV(*flagInput, os.Stdout, *flagSeparator, *flagJa3S)
		return
	}

	// default: JSON output
	if *flagJSON {
		mtslx.ReadFileJSON(*flagInput, os.Stdout, *flagJa3S)
	}
}
