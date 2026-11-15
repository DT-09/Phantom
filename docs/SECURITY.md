# Security model

PHANTOM is a passive offline capture analyzer. It opens a user-supplied file read-only. It does not open raw sockets, transmit packets, inject frames, scan hosts, spoof identities, or change traffic.

Capture files are untrusted input. The implementation applies a fixed input-size cap, validates global and record headers, checks captured lengths against original lengths and remaining file bytes, and bounds protocol traversal by the enclosing packet length. The flow table has a fixed capacity and bounded probing. IPv6 extension parsing consumes a checked positive length on each iteration.

A protocol counter is not a security verdict. DNS port 53 is a candidate heuristic; the DNS counter only establishes that a 12-byte header was present and classifies its QR bit. Checksums and full application-layer semantics are not validated.

Known limitations include the 64 MiB whole-file buffer, lack of PCAP-NG support, lack of full DNS name/resource-record parsing, and lack of checksum validation. PHANTOM should not be used as a security control or as the sole basis for incident conclusions.
