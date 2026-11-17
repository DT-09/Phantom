# PHANTOM technical architecture

**Status:** Target architecture. Current implementation details are identified separately from planned contracts.

## Runtime contract

- Linux x86-64 executable.
- GNU assembler, Intel syntax; direct Linux syscalls.
- No libc or dynamic runtime dependency in the core executable.
- Python may generate fixtures and run tests; it is not part of analyzer runtime.
- OS-specific I/O is isolated from parsing and analysis semantics.

## Target module boundaries

| Module | Responsibility | Required contract |
|---|---|---|
| Syscall I/O | open/read/close/write | partial reads and EINTR handled |
| Capture reader | PCAP and PCAP-NG framing | yields bounded packet records |
| Timestamp | normalize source timestamps | preserve precision and source clock |
| Link parser | Ethernet and VLAN | returns bounded network payload |
| Network parser | IPv4/IPv6/extensions/fragments | returns bounded transport payload |
| Transport parser | TCP/UDP/ICMP | validates header lengths |
| Flow manager | bidirectional conversations | bounded state and explicit overflow |
| Analyzers | protocol metadata and measurements | observation/derived result separation |
| Findings | deterministic rules | evidence references and limitations |
| Serializers | terminal/JSON/CSV | versioned deterministic schema |

## Current processing path

1. CLI accepts a capture path, `--json`, `--help`, or `--version`.
2. Input currently loads the complete capture into a fixed 64 MiB buffer.
3. Classic PCAP global header and Ethernet link type are validated.
4. Record headers and captured/original lengths are checked.
5. Ethernet II and one VLAN tag are parsed.
6. IPv4/IPv6 and supported extension headers are bounded by captured payload.
7. TCP, UDP, and ICMP headers are classified.
8. DNS is recognized at header/QR-bit level only.
9. Directional TCP/UDP 5-tuples are stored in a bounded 4,096-entry table.
10. Terminal or JSON counters are emitted.

## Parser interface invariant

Every parser must receive a pointer to the first byte of its bounded input slice and the number of available bytes. It must return a recognized, unsupported, malformed, or truncated status; a consumed header length where valid; and a bounded payload slice where valid.

No parser may assume original wire length equals captured length. No parser may dereference a byte before proving it is available.

## Streaming reader invariants

- A record may cross any read boundary.
- The reader must not require the entire capture in memory.
- Fixed-size header staging is allowed.
- Large records follow an explicit policy: bounded allocation, skip with warning, or documented failure.
- Interrupted reads retry; EOF inside a record header or body is a truncation error.
- File offsets use checked 64-bit arithmetic.
- Captured length, original length, and bytes actually read remain distinct.

## Flow identity

A bidirectional flow key is the canonical ordering of address family, transport protocol, endpoint A address/port, and endpoint B address/port. Original packet direction is stored separately. IPv4 and IPv6 keys must not alias. Non-port protocols require a separately specified identity model.

## Evidence and output contract

- Every structured report declares schema and engine versions.
- Identifiers and ordering are deterministic for identical input and options.
- Counts distinguish captured bytes from original wire length.
- Warnings include stable codes and packet/record offsets where available.
- Findings link to packet indices and flow identifiers.
- Unsupported features are reported as coverage limitations, not silently omitted.

## Resource controls

Every stateful subsystem defines maximum entries, memory use, and overflow behavior. A reached limit produces a visible warning and never silently corrupts prior results.

## Testing boundaries

- Parser fixtures for byte order, truncation, minimum/maximum lengths, and malformed values.
- End-to-end capture fixtures.
- Differential comparisons for decoded fields.
- Determinism tests.
- Resource-pressure tests.
- Malformed-input corpus with timeouts and crash detection.
- Benchmarks with documented generation parameters.

## Current bounded structures

| Structure | Current capacity | Current policy |
|---|---:|---|
| Capture buffer | 64 MiB + 1 byte | Reject larger captures |
| Flow table | 4,096 entries | Open addressing; count overflow events |
| Flow key | 40 bytes | Family, protocol, padded addresses, ports |
| Output number buffer | 32 bytes | Decimal formatting |

These are current implementation limits, not permanent product requirements.
