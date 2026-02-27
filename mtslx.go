// Package mtslx provides functions for scanning TLS traffic and computing
// JA3/JA3S fingerprints from PCAP files or live network interfaces.
// It wraps the dreadl0ck/ja3 and dreadl0ck/tlsx libraries.
package mtslx

import (
	"io"
	"time"

	"github.com/dreadl0ck/ja3"
)

// Record contains all information for a calculated JA3 fingerprint.
// It is re-exported from the ja3 package for convenience.
type Record = ja3.Record

// ReadFileJSON reads the PCAP file at the given path and writes all JA3
// fingerprints as a JSON array to out. If doJA3s is true, server-side
// fingerprints (JA3S) are also included.
func ReadFileJSON(file string, out io.Writer, doJA3s bool) {
	ja3.ReadFileJSON(file, out, doJA3s)
}

// ReadFileCSV reads the PCAP file at the given path and writes all JA3
// fingerprints as CSV to out using the specified separator. If doJA3s is
// true, server-side fingerprints (JA3S) are also included.
func ReadFileCSV(file string, out io.Writer, separator string, doJA3s bool) {
	ja3.ReadFileCSV(file, out, separator, doJA3s)
}

// ReadFileJa3s reads the PCAP file at the given path and writes only the
// JA3S (server) fingerprints to out.
func ReadFileJa3s(file string, out io.Writer) {
	ja3.ReadFileJa3s(file, out)
}

// ReadInterface captures packets from the named network interface and writes
// JA3 fingerprints to out. If asJSON is true the results are written as
// newline-separated JSON objects, otherwise CSV is used with the given
// separator. When ja3s is true, server-side fingerprints (JA3S) are also
// computed.
func ReadInterface(iface string, out io.Writer, separator string, ja3s bool, asJSON bool, snaplen int, promisc bool, timeout time.Duration) {
	ja3.ReadInterface(iface, out, separator, ja3s, asJSON, snaplen, promisc, timeout)
}
