# PHANTOM

**A passive network-capture analyzer written in x86-64 Assembly.**

PHANTOM reads classic PCAP captures and produces deterministic traffic summaries without libc, third-party runtime libraries, raw sockets, or packet transmission. Its executable is assembled from GNU assembler source using Intel syntax and links directly against the Linux syscall ABI.

## Capabilities

- Classic PCAP reader with little- and big-endian file support, including microsecond and nanosecond timestamp formats.
- Bounded 64 MiB input buffer and strict record-boundary checks.
- Ethernet II and one 802.1Q/802.1ad VLAN tag.
- IPv4, IPv6, and bounded IPv6 extension-header traversal.
- TCP, UDP, ICMP, and ICMPv6 packet classification.
- UDP length and TCP data-offset validation.
- DNS port-53 candidate detection and DNS header query/response counters.
- Bounded directional TCP/UDP 5-tuple table with full-key collision checks.
- Human-readable summary and deterministic JSON output.
- Direct Linux syscalls; no C runtime or dynamic interpreter.

## Requirements

- Linux x86-64
- GNU binutils (`as`, `ld`, `readelf`, `nm`)
- GNU Make
- Python 3 (tests only)

Python is used only to generate packet-capture fixtures and run black-box regression assertions. The PHANTOM executable itself is Assembly.

## Build and verify

```sh
make clean all
make check
make test
```

`make check` verifies that the output is ELF64/x86-64, statically linked, and has no undefined symbols.

## Usage

```sh
./build/phantom --help
./build/phantom --version
./build/phantom capture.pcap
./build/phantom --json capture.pcap
```

The JSON output is suitable for downstream tooling. Example fields include packet counts, captured bytes, protocol counts, DNS header counts, fragment counts, VLAN counts, directional flows, and flow-table overflow events.

## Important semantics and limits

- PHANTOM is an **offline, passive analyzer**. It does not capture live interfaces, transmit packets, inject frames, scan hosts, spoof identities, or modify traffic.
- Classic PCAP with Ethernet link type is accepted in microsecond and nanosecond timestamp resolutions, in both byte orders. PCAP-NG is not supported.
- Captures are limited to 64 MiB and loaded into a fixed buffer. PHANTOM is not yet a streaming reader.
- At most one VLAN tag is decoded.
- IPv6 extension traversal is bounded by the captured payload length. ESP and unknown next-header values are not decoded.
- DNS classification begins with UDP port 53. PHANTOM checks for a complete 12-byte DNS header and classifies the QR bit; it does not yet decode question names or resource records. A port-53 packet without a complete header remains a candidate, not a validated DNS message.
- Flow keys are directional 5-tuples. The fixed table stores up to 4,096 distinct keys. Once full, additional insertion attempts increment `flow_table_overflow`; no eviction occurs.
- Protocol counters describe structurally recognized headers, not security verdicts. Checksums are not validated.

## Product and engineering direction\n\n- [Product vision](docs/VISION.md)\n- [Technical architecture](docs/ARCHITECTURE.md)\n- [Protocol support and parsing boundaries](docs/PROTOCOLS.md)\n- [Delivery roadmap](docs/ROADMAP.md)\n- [Requirements and verification matrix](docs/REQUIREMENTS.md)\n\n## Project layout

```text
src/phantom.S          x86-64 Assembly implementation
tests/test_phantom.py  PCAP fixture generation and regression tests
docs/                  Architecture, protocol, memory, and security notes
Makefile               Assembly, static-link, and test targets
```

## License

MIT. See [LICENSE](LICENSE).
