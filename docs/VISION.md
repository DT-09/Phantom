# PHANTOM — Product and engineering vision

**Version:** 1.0  
**Status:** Target architecture  
**Product class:** Offline network observability and forensic analysis engine  
**Implementation constraint:** x86-64 Assembly core, Linux x86-64, direct system-call boundary

## 1. Mission

PHANTOM converts packet captures into deterministic, inspectable explanations of network activity. It is designed for defensive analysis, incident investigation, protocol education, and reproducible network measurement.

PHANTOM is not a packet generator, scanner, interception tool, or Wireshark clone. It does not transmit traffic or perform active network operations. Its primary input is a user-supplied capture file.

## 2. Product promise

Given a supported capture, PHANTOM should produce:
- a validated account of what the capture contains;
- a normalized model of endpoints, conversations, protocols, and time;
- measurable traffic behavior with explicit definitions;
- findings tied to packet-level evidence;
- deterministic machine-readable output and a human-readable report;
- clear warnings when truncation, unsupported formats, missing packets, or parser limits weaken conclusions.

Every finding must distinguish **observation**, **inference**, and **unknown**. PHANTOM must never present a heuristic as proof or a traffic anomaly as proof of compromise.

## 3. Users and jobs

### Network and systems engineers
Understand traffic composition, endpoint relationships, protocol usage, and performance characteristics from saved captures.

### Defensive security analysts
Triage supplied captures, inspect suspicious or malformed behavior, establish timelines, and export evidence for further investigation.

### Researchers and educators
Study protocol behavior with reproducible outputs and explicit parsing semantics.

## 4. Product principles

1. **Evidence before interpretation.** Every derived claim must be traceable to packets and documented logic.
2. **Determinism.** Identical input and options produce byte-for-byte stable structured output, excluding explicitly documented volatile metadata.
3. **Bounded execution.** Memory, CPU, parser depth, table sizes, and output size have explicit limits and failure behavior.
4. **Fail closed on malformed structure.** Never read beyond captured bytes or silently reinterpret invalid lengths.
5. **Honest uncertainty.** Distinguish capture loss, truncation, unsupported protocol features, and inference confidence.
6. **Assembly-native core.** Parsing, state management, analysis, and report generation remain implemented in x86-64 Assembly.
7. **Offline and passive by default.** No packet transmission, active scanning, traffic injection, or hidden collection.
8. **Interoperability.** Stable documented output schemas support external tools without coupling the core to a specific UI.
9. **Privacy by design.** Default reports emphasize metadata. Payload extraction, if ever introduced, must be opt-in, bounded, and carefully documented.
10. **Measured performance.** Publish reproducible throughput, memory, and scaling benchmarks instead of unsupported speed claims.

## 5. Target architecture

### A. Input and capture subsystem
- Classic PCAP and PCAP-NG readers.
- Streaming file ingestion; no whole-capture fixed-size ceiling.
- Timestamp normalization with precision preserved.
- Interface/link-type metadata and snap-length awareness.
- Strict record-boundary validation and structured parse errors.

### B. Protocol subsystem
- Link layer: Ethernet, stacked VLAN tags.
- Network layer: IPv4, IPv6, bounded extension traversal, fragment metadata.
- Transport: TCP, UDP, ICMP, ICMPv6.
- Application metadata: DNS first; additional parsers only when semantics and tests are specified.
- Every parser receives a bounded byte slice and returns a structured parse result.

### C. Reconstruction subsystem
- Canonical bidirectional flow identity with direction counters.
- Packet and byte counts per direction.
- First/last timestamps and duration.
- TCP flags and retransmission indicators where observable.
- Fragment association only when safely supported.
- Explicit handling of incomplete captures, out-of-order packets, and flow-table pressure.

### D. Analysis subsystem
- Endpoint, protocol, service, and conversation distributions.
- Time-series traffic rates and burst summaries.
- DNS query/response metadata and transaction matching where possible.
- Structural anomalies and protocol inconsistencies.
- Configurable, deterministic filters.
- Rule-based findings with evidence references and confidence labels.
- No opaque security verdicts.

### E. Evidence and output subsystem
- Versioned JSON schema.
- CSV exports for flows and findings.
- Human-readable terminal report.
- Packet index references with capture offsets and timestamps.
- Explicit parser warnings and coverage summary.
- Stable ordering and deterministic serialization.

### F. User interface
- First: reliable CLI and machine-readable outputs.
- Second: interactive terminal exploration.
- Later: optional local graphical interface consuming the stable output contract.
- The interface must never own protocol truth; the Assembly engine does.

## 6. Analysis model

PHANTOM uses a three-tier claim model:

- **Observed:** directly decoded from validated packet bytes or capture metadata.
- **Derived:** calculated from observations using documented deterministic rules.
- **Hypothesis:** a possible explanation that requires analyst validation.

Each finding should carry:
- stable finding identifier and rule version;
- severity and confidence, kept as separate concepts;
- concise explanation;
- affected flow or endpoint identifiers;
- packet indices and byte offsets;
- supporting measurements;
- limitations and alternative explanations.

A suspicious pattern is not equivalent to malicious intent. Absence of evidence in a partial capture is not evidence of absence.

## 7. Non-functional requirements

### Correctness
- Bounds-checked parsing at every layer.
- No crashes, hangs, or out-of-bounds access on malformed input.
- Differential tests against independent capture/protocol tooling.
- Golden fixtures for valid, truncated, malformed, and edge-case captures.

### Performance
- Streaming ingestion with bounded working memory.
- Near-linear processing cost in input bytes, subject to documented state tables.
- Benchmarks at multiple capture sizes and protocol mixes.
- Report throughput, peak resident memory, and flow-table behavior.

### Reliability
- Clear exit codes and actionable errors.
- No partial success presented as complete analysis.
- Resource exhaustion is reported, not hidden.
- Stable schema versioning and backwards-compatibility policy.

### Portability
- Initial target: Linux x86-64 with GNU binutils.
- Keep OS-specific syscall code isolated from parsing and analysis routines.
- Other architectures and operating systems are separate future ports, not implied compatibility.

## 8. Release gates

A release is not complete merely because it assembles.

1. Build and static ELF checks pass.
2. Regression suite passes.
3. Malformed-input corpus passes without crash or hang.
4. Differential checks pass for supported fields.
5. JSON validates against the published schema.
6. Resource bounds and failure modes are tested.
7. Benchmarks are published with reproducible commands.
8. Documentation matches actual behavior.
9. Release artifact, source revision, and checksums are published.
10. Known limitations are visible in the release notes.

## 9. Delivery sequence

### Stage 0 — Establish truth
Audit parser semantics, correct documentation, freeze current output contract, and build a requirements-to-tests matrix.

### Stage 1 — Streaming foundation
Replace whole-file loading with a bounded streaming reader. Preserve record boundaries across reads and test partial reads, interrupted syscalls, EOF, and oversized records.

### Stage 2 — Capture format completeness
Implement PCAP-NG section, interface, and enhanced packet blocks with byte-order and timestamp-resolution tests. Support link types explicitly and reject unsupported ones clearly.

### Stage 3 — Conversation reconstruction
Replace directional-only flow identity with canonical bidirectional flows. Track direction-specific packet/byte counts, timestamps, TCP flags, and state pressure.

### Stage 4 — Protocol depth
Add stacked VLAN, complete DNS question/resource-record parsing with safe compression-pointer limits, and defined ICMP semantics. Add more application protocols only after test specifications exist.

### Stage 5 — Evidence and query
Introduce versioned schemas, packet references, deterministic filters, CSV exports, and findings linked to evidence.

### Stage 6 — Defensive analysis
Add transparent rules for malformed traffic, unusual protocol behavior, and traffic-shape deviations. Include false-positive caveats and reproducible rule tests.

### Stage 7 — Assurance and release
Differential validation, malformed-input corpus, performance benchmarks, CI matrix, reproducible release artifacts, checksums, and user documentation.

## 10. Explicit non-goals

- Active scanning, exploitation, credential theft, stealth, evasion, or traffic injection.
- Replacing specialist packet analyzers in every workflow.
- Claiming attribution or compromise from packet metadata alone.
- Cloud upload of captures or telemetry by default.
- Opaque AI-generated verdicts.
- Features without a written semantic contract and test plan.

## 11. Definition of done

PHANTOM is ready for a production-minded 1.0 release when it can process large supported captures with bounded memory, reconstruct conversations, explain protocol behavior, produce versioned evidence-backed outputs, survive malformed inputs, and demonstrate correctness and performance through reproducible tests.

The standard is not feature count. The standard is whether an analyst can trust what PHANTOM says, inspect why it says it, and identify what it cannot know.
