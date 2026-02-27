# mtslx

Micro TLS scanner – a Go library and command-line tool for extracting
[JA3/JA3S](https://github.com/salesforce/ja3) TLS fingerprints from PCAP files
or live network captures.

Built on top of:
- [`dreadl0ck/tlsx`](https://github.com/dreadl0ck/tlsx) – TLS ClientHello / ServerHello parser
- [`dreadl0ck/ja3`](https://github.com/dreadl0ck/ja3) – JA3/JA3S fingerprint computation

## Library

Import the package and use the exported functions:

```go
import "github.com/Vytek/mtslx"

// Read a PCAP file and print JA3 records as JSON (including JA3S).
mtslx.ReadFileJSON("capture.pcap", os.Stdout, true)

// Read a PCAP file and print JA3 records as CSV.
mtslx.ReadFileCSV("capture.pcap", os.Stdout, ",", true)

// Print only JA3S (server) fingerprints from a PCAP file.
mtslx.ReadFileJa3s("capture.pcap", os.Stdout)

// Live capture from a network interface.
mtslx.ReadInterface("eth0", os.Stdout, ",", true, true, 1514, true, pcap.BlockForever)
```

The `mtslx.Record` type (re-exported from `ja3.Record`) holds all fields for a
single fingerprint:

```go
type Record struct {
    DestinationIP   string
    DestinationPort int
    JA3             string
    JA3Digest       string
    JA3S            string
    JA3SDigest      string
    SourceIP        string
    SourcePort      int
    Timestamp       float64
}
```

## Command-line tool

### Build

```sh
go build -o mtslx ./cmd/mtslx
```

### Usage

```
Usage of mtslx:
  mtslx reads PCAP files or captures from a live interface and prints
  JA3/JA3S TLS fingerprints as JSON (default) or CSV.

  -csv
        print as CSV
  -debug
        toggle debug mode
  -iface string
        specify network interface to read packets from
  -ja3s
        include ja3 server hashes (ja3s) (default true)
  -ja3s-only
        dump ja3s only
  -json
        print as JSON array (default true)
  -promisc
        capture in promiscuous mode (requires root) (default true)
  -read string
        read PCAP file
  -separator string
        set a custom separator (default ",")
  -snaplen int
        default snap length for ethernet frames (default 1514)
  -timeout duration
        timeout for collecting packet batches (default -1ns)
  -tsv
        print as TAB separated values
  -version
        display version and exit
```

### Examples

Read a PCAP file and print JSON output (including JA3S):

```sh
mtslx -read capture.pcap
```

Read a PCAP file and print CSV output:

```sh
mtslx -read capture.pcap -csv
```

Capture live from `eth0` and print JSON:

```sh
sudo mtslx -iface eth0
```

Print only JA3S fingerprints:

```sh
mtslx -read capture.pcap -ja3s-only
```

## Requirements

- Go 1.24+
- `libpcap` development headers (`apt install libpcap-dev` on Debian/Ubuntu)

## License

See [LICENSE](LICENSE).
