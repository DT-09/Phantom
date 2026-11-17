# PHANTOM requirements and verification matrix

This matrix is the source of truth for whether a capability is implemented, tested, and releasable. A roadmap checkbox alone is not evidence.

| ID | Requirement | Current state | Verification required | Release gate |
|---|---|---|---|---|
| CAP-001 | Classic PCAP little-endian microsecond | Implemented | fixture + counters | Pass |
| CAP-002 | Classic PCAP big-endian microsecond | Implemented | fixture + counters | Pass |
| CAP-003 | Classic PCAP little-/big-endian nanosecond | Implemented | both byte orders + invalid fraction | Pass |
| CAP-004 | PCAP-NG section/interface/packet blocks | Not implemented | multi-section, endian, timestamp, truncation fixtures | Blocked |
| CAP-005 | Streaming input independent of file size | Not implemented; 64 MiB whole-file buffer | boundary-crossing reads, large capture, bounded RSS | Blocked |
| L2-001 | Ethernet II | Implemented | minimum/truncated frame fixtures | Pass |
| L2-002 | Single VLAN tag | Implemented | 802.1Q and 802.1ad fixtures | Pass |
| L2-003 | Stacked VLAN tags | Not implemented | QinQ and malformed nesting fixtures | Blocked |
| L3-001 | IPv4 structural validation | Implemented | IHL/total length/fragment fixtures | Pass |
| L3-002 | IPv6 base and bounded extensions | Implemented | supported extension and truncation fixtures | Pass |
| L3-003 | Fragment association/reassembly | Not implemented | overlap, ordering, timeout, memory-bound fixtures | Blocked |
| L4-001 | TCP header validation | Implemented | data offset and truncation fixtures | Pass |
| L4-002 | UDP header validation | Implemented | length and truncation fixtures | Pass |
| L4-003 | ICMP semantics | Partial; minimum header only | type/code-specific fixtures | Blocked |
| FLOW-001 | Directional 5-tuple counting | Implemented | key and collision fixtures | Pass |
| FLOW-002 | Canonical bidirectional conversations | Not implemented | reversed endpoints map to same flow, direction counters | Blocked |
| FLOW-003 | Per-flow bytes, packets, timestamps, duration | Not implemented | exact counters and timestamp fixtures | Blocked |
| APP-001 | DNS header QR classification | Partial | existing header fixtures | Pass with documented limitation |
| APP-002 | DNS question and resource-record decoding | Not implemented | compression pointer bounds/loops and RR fixtures | Blocked |
| OUT-001 | Deterministic terminal summary | Implemented | repeat-run comparison | Pass |
| OUT-002 | Versioned JSON schema | Partial; stable fields, no declared schema version | JSON Schema validation and compatibility tests | Blocked |
| OUT-003 | Flow and finding exports with packet evidence | Not implemented | schema, packet references, deterministic exports | Blocked |
| QA-001 | Static ELF/no dynamic interpreter | Implemented | `make check` | Pass |
| QA-002 | Malformed-input regression suite | Partial | expanded corpus, timeout, sanitizer/differential checks | Blocked |
| QA-003 | Differential protocol validation | Not implemented | compare supported fields to independent dissector | Blocked |
| PERF-001 | Reproducible throughput and memory benchmarks | Not implemented | benchmark generator, multiple sizes, RSS and throughput | Blocked |
| REL-001 | Reproducible release artifacts and checksums | Not implemented | tagged build, artifact inspection, SHA-256 manifest | Blocked |

## Rules for changing status

- **Implemented** means code exists.
- **Verified** means automated tests exercise the behavior.
- **Release-ready** means verification, documentation, failure behavior, and resource limits all agree.
- Partial support must remain labeled partial.
- A requirement cannot be marked complete solely because the happy path works.

## Immediate execution order

1. Audit and harden the current reader's format and size semantics.
2. Design and implement bounded streaming input.
3. Add PCAP-NG support on top of the streaming record abstraction.
4. Implement canonical bidirectional flow state and exact counters.
5. Version the output schema before adding more analysis fields.
6. Expand protocol depth and evidence-backed findings.
7. Add differential testing and reproducible performance gates.
