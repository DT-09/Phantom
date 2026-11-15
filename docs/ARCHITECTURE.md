# PHANTOM architecture

## Runtime contract

PHANTOM is a single-process Linux x86-64 executable. `src/phantom.S` is assembled by GNU `as` in Intel syntax and linked by GNU `ld`. The program enters at `_start` and uses Linux syscalls directly. It has no libc dependency and no dynamic interpreter.

## Processing pipeline

1. **CLI** — accepts a capture path, `--json`, `--help`, or `--version`.
2. **Input** — opens the file read-only and fills a fixed 64 MiB buffer. Interrupted reads are retried.
3. **Global PCAP validation** — validates classic PCAP magic, version 2.4, and Ethernet link type.
4. **Record iteration** — validates each 16-byte record header, `incl_len <= orig_len`, the configured capacity, and the remaining file length.
5. **Link layer** — parses Ethernet II and one 802.1Q/802.1ad VLAN tag.
6. **Network layer** — validates IPv4 header length and total length; validates IPv6 base-header and payload lengths.
7. **Extension traversal** — walks supported IPv6 hop-by-hop, routing, destination-options, mobility, AH, and fragment headers. Every extension length is checked against the remaining payload.
8. **Transport layer** — validates minimum TCP/UDP header sizes, TCP data offset, and UDP length before classification.
9. **Flow accounting** — stores directional TCP/UDP 5-tuples in a fixed-capacity open-addressed table. Hash collisions are checked against the complete key.
10. **DNS header accounting** — counts UDP port-53 candidates, headers at least 12 bytes long, and query/response QR flags.
11. **Output** — emits a stable terminal summary or JSON object.

## Register and state conventions

The implementation uses the Linux x86-64 syscall ABI. Registers are assigned by the active parsing stage; the source documents the non-local state used by the record loop and flow routine. The flow routine preserves the record captured-length register and the network/transport pointers it needs to return to the parser.

## Bounded structures

| Structure | Capacity | Policy |
|---|---:|---|
| Capture buffer | 64 MiB + 1 byte | Reject larger captures |
| Flow table | 4,096 entries | Open addressing; count overflow events |
| Flow key | 40 bytes | Family, protocol, padded addresses, ports |
| Output number buffer | 32 bytes | Decimal formatting |

The flow table is reset on each process invocation. No state is persisted between captures.

## Output contract

The JSON schema uses stable snake_case numeric fields. Counters are unsigned integers. `directional_flows` is the number of distinct directional keys stored; `flow_table_overflow` is the number of insertion attempts that could not be stored after the table filled. It is not a count of all distinct flows in an over-capacity capture.

## Explicit non-goals

Live packet acquisition, packet transmission, active probing, packet injection, traffic modification, and stealth/evasion behavior are outside PHANTOM's scope.
