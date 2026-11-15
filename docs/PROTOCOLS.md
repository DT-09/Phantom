# Protocol support and parsing boundaries

## Capture container

| Format | Status | Notes |
|---|---|---|
| Classic PCAP, little-endian | Supported | Microsecond magic only |
| Classic PCAP, big-endian | Supported | Microsecond magic only |
| PCAP-NG | Unsupported | Planned separately |
| Nanosecond PCAP | Unsupported | Rejected by magic validation |
| Ethernet link type | Supported | DLT 1 |

## Link layer

- Ethernet II header length is checked before EtherType access.
- One outer VLAN tag is supported for EtherTypes `0x8100` and `0x88a8`.
- Untagged IPv4 (`0x0800`) and IPv6 (`0x86dd`) are recognized.
- Other EtherTypes are ignored after the Ethernet frame is counted.

## Network layer

### IPv4

- Version, minimum header size, IHL, total length, and captured bounds are checked.
- Non-initial fragments are not interpreted as transport headers.
- Fragmented datagrams are counted when MF or a nonzero fragment offset is present.
- IPv4 options are skipped using IHL; option contents and header checksum are not validated.

### IPv6

- Version, 40-byte base header, payload length, and captured bounds are checked.
- Supported extension headers: Hop-by-Hop Options (0), Routing (43), Fragment (44), AH (51), Destination Options (60), and Mobility (135).
- Extension lengths are checked against remaining payload before advancing.
- Non-initial fragments are not interpreted as transport headers.
- ESP (50), jumbograms, extension-header semantic validation, and unknown next-header values are not decoded.

## Transport layer

| Protocol | Validation | Output |
|---|---|---|
| TCP | Minimum 20 bytes; data offset at least 20 and no larger than payload | Packet count and directional flow key |
| UDP | Minimum 8 bytes; UDP length at least 8 and within IP payload | Packet count and directional flow key |
| ICMP | Minimum 4 bytes | ICMP/ICMPv6 count |
| ICMPv6 | Minimum 4 bytes | ICMP/ICMPv6 count |

Checksums, TCP options, UDP application payloads other than DNS header recognition, and ICMP type/code semantics are not validated.

## DNS header recognition

A UDP packet with source or destination port 53 increments `dns_port_candidates`. If the UDP payload contains at least 12 bytes, PHANTOM reads the DNS flags and QR bit and increments `dns_headers` plus either `dns_queries` or `dns_responses`.

This is header-level classification only. It does not parse labels, compression pointers, questions, answers, authority records, or additional records. It does not assert that the full DNS message is semantically valid.

## Flow key semantics

A flow key contains address family, IP protocol, source address, destination address, source port, and destination port. Direction is significant: reversing endpoints creates a separate key. TCP and UDP are tracked; ICMP is not included. The table is bounded at 4,096 entries.
