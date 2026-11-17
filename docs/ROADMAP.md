# PHANTOM delivery status

PHANTOM is an operational Assembly-native offline PCAP analyzer. The target product is defined in [VISION.md](VISION.md), and subsystem contracts are defined in [ARCHITECTURE.md](ARCHITECTURE.md), and verification status is tracked in [REQUIREMENTS.md](REQUIREMENTS.md). This document separates implemented behavior from future scope.

## Implemented

- [x] x86-64 Assembly executable using direct Linux syscalls
- [x] Static ELF64 link with no dynamic interpreter or undefined symbols
- [x] Bounded 64 MiB input buffer and EINTR-safe reads
- [x] Classic PCAP little-/big-endian parsing, microsecond and nanosecond timestamp resolutions
- [x] PCAP 2.4 and Ethernet link-type validation
- [x] Record boundary, captured/original length, and capacity checks
- [x] Ethernet II and one 802.1Q/802.1ad VLAN tag
- [x] IPv4 header-length, total-length, and fragment handling
- [x] IPv6 base-header and payload validation
- [x] Bounded IPv6 extension traversal for supported headers
- [x] TCP data-offset and UDP length validation
- [x] TCP, UDP, ICMP, and ICMPv6 classification
- [x] DNS port candidate and DNS header QR counters
- [x] Bounded 4,096-entry directional TCP/UDP 5-tuple table
- [x] Full-key collision resolution
- [x] Terminal and JSON summaries
- [x] Positive, negative, endian, VLAN, fragment, IPv6 extension, and transport-boundary tests
- [x] Static binary checks

## Remaining extensions

### Input and protocol depth
- [ ] PCAP-NG sections, interfaces, and packet blocks
- [ ] Streaming reader to remove the 64 MiB whole-file limit
- [ ] Stacked VLAN/QinQ parsing
- [ ] Full DNS question and resource-record decoding with compression-loop limits
- [ ] ICMP type/code interpretation
- [ ] Optional checksum validation

### Analysis
- [ ] Bidirectional flow normalization
- [ ] Per-flow packet and byte counters
- [ ] Flow timestamps, duration, and expiry policies
- [ ] Endpoint and protocol distributions
- [ ] Deterministic filter expressions
- [ ] Exportable per-flow records

### Assurance and release
- [ ] Differential testing against independent protocol tooling
- [ ] Dedicated malformed-input corpus and coverage-guided fuzzing
- [ ] Large-capture performance and memory benchmarks
- [ ] CI matrix across supported Linux x86-64 distributions
- [ ] Versioned release artifacts and checksums

## Completion definition

The current release is a working passive analyzer, not a full-featured Wireshark replacement. Future extensions are complete only when their format semantics, resource bounds, output contract, and regression tests are documented and verified. Active network operations remain out of scope.
