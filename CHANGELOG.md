# Changelog

## 0.3.0

- Add classic PCAP nanosecond timestamp support.
- Recognize little-endian and big-endian nanosecond PCAP magic values.
- Validate nanosecond timestamp fractions against the one-billion bound.
- Add regression coverage for both byte orders and malformed timestamp fractions.
- Preserve the Assembly-only executable, direct Linux syscalls, and static ELF checks.

## 0.2.0

- Initial Assembly-native passive PCAP analyzer.
- Classic microsecond PCAP parsing, Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP, DNS header recognition, bounded directional flows, terminal and JSON reports.
