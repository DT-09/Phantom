#!/usr/bin/env python3
"""Black-box regression tests. Python generates fixtures; PHANTOM remains Assembly."""
import json
import random
import os
import struct
import subprocess
import tempfile

BIN = os.path.abspath("build/phantom")

def pcap(path, packets, endian='<', major=2, minor=4, linktype=1, snaplen=65535, magic=0xa1b2c3d4):
    with open(path, 'wb') as f:
        f.write(struct.pack(endian+'IHHIIII', magic, major, minor, 0, 0, snaplen, linktype))
        for i, packet in enumerate(packets):
            f.write(struct.pack(endian+'IIII', 1700000000+i, 0, len(packet), len(packet)))
            f.write(packet)

def ethernet(payload, ethertype=0x0800):
    return bytes.fromhex('00112233445566778899aabb') + struct.pack('!H', ethertype) + payload

def ipv4(payload, proto, flags_offset=0):
    total = 20 + len(payload)
    return (bytes([0x45, 0, total >> 8, total & 255, 0, 1,
                   flags_offset >> 8, flags_offset & 255, 64, proto, 0, 0])
            + bytes([192, 0, 2, 1, 198, 51, 100, 2]) + payload)

def udp(src=12345, dst=53, data=b''):
    length = 8 + len(data)
    return struct.pack('!HHHH', src, dst, length, 0) + data

def dns(query=True):
    # A complete 12-byte DNS header. Counts are zero; this tests header-level decoding only.
    flags = 0x0100 if query else 0x8180
    return struct.pack('!HHHHHH', 0x1234, flags, 0, 0, 0, 0)

def run(path):
    return subprocess.run([BIN, path], text=True, capture_output=True)

def check(condition, message):
    if not condition:
        raise AssertionError(message)

with tempfile.TemporaryDirectory() as td:
    good = os.path.join(td, 'good.pcap')
    packets = [
        ethernet(ipv4(udp(data=dns(True)), 17)),
        ethernet(ipv4(udp(data=dns(True)), 17)),
        ethernet(ipv4(udp(53, 40000, dns(False)), 17)),
    ]
    pcap(good, packets)
    r = run(good)
    check(r.returncode == 0, r.stderr)
    for expected in ['Packets:       3', 'IPv4:          3', 'UDP:           3',
                     'DNS port candidates: 3', 'DNS headers:         3',
                     'DNS queries:         2', 'DNS responses:       1',
                     'Directional flows:   2']:
        check(expected in r.stdout, f'missing {expected!r}\n{r.stdout}')
    jr = subprocess.run([BIN, '--json', good], text=True, capture_output=True)
    check(jr.returncode == 0, jr.stderr)
    report = json.loads(jr.stdout)
    check(report['packets'] == 3 and report['ipv4'] == 3 and report['udp'] == 3,
          f'JSON report values incorrect: {report}')
    check(report['dns_headers'] == 3 and report['dns_queries'] == 2
          and report['dns_responses'] == 1 and report['directional_flows'] == 2, f'DNS JSON counters incorrect: {report}')

    big = os.path.join(td, 'big-endian.pcap')
    pcap(big, [ethernet(ipv4(udp(data=dns()), 17))], endian='>')
    rb = run(big)
    check(rb.returncode == 0, rb.stderr)
    check('IPv4:          1' in rb.stdout and 'UDP:           1' in rb.stdout,
          f'big-endian protocol decode failed\n{rb.stdout}')

    # Nanosecond-resolution classic PCAP, both byte orders.
    nano_le = os.path.join(td, 'nano-little.pcap')
    pcap(nano_le, [ethernet(ipv4(udp(data=dns()), 17))], magic=0xa1b23c4d)
    rnle = run(nano_le)
    check(rnle.returncode == 0 and 'UDP:           1' in rnle.stdout,
          f'little-endian nanosecond PCAP failed\\n{rnle.stderr}')
    nano_be = os.path.join(td, 'nano-big.pcap')
    pcap(nano_be, [ethernet(ipv4(udp(data=dns()), 17))],
         endian='>', magic=0xa1b23c4d)
    rnbe = run(nano_be)
    check(rnbe.returncode == 0 and 'UDP:           1' in rnbe.stdout,
          f'big-endian nanosecond PCAP failed\\n{rnbe.stderr}')
    bad_nano = os.path.join(td, 'bad-nano-fraction.pcap')
    with open(bad_nano, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
        packet = ethernet(ipv4(udp(), 17))
        f.write(struct.pack('<IIII', 1, 1000000000, len(packet), len(packet)) + packet)
    check(run(bad_nano).returncode != 0, 'invalid nanosecond timestamp accepted')

    # IPv6 with a Destination Options extension header followed by UDP/DNS.
    ipv6_ext = os.path.join(td, 'ipv6-extension.pcap')
    udp_payload = udp(data=dns())
    ipv6_payload = bytes([17, 0, 0, 0, 0, 0, 0, 0]) + udp_payload
    ipv6_header = bytes([0x60, 0, 0, 0, 0, len(ipv6_payload), 60, 64]) + bytes(range(32))
    pcap(ipv6_ext, [ethernet(ipv6_header + ipv6_payload, 0x86dd)])
    ri = run(ipv6_ext)
    check(ri.returncode == 0 and 'IPv6:          1' in ri.stdout
          and 'UDP:           1' in ri.stdout and 'DNS headers:         1' in ri.stdout,
          f'IPv6 extension parsing failed\n{ri.stdout}\n{ri.stderr}')

    # One VLAN tag; Ethernet type remains network byte order regardless of PCAP byte order.
    vlan = os.path.join(td, 'vlan.pcap')
    frame = bytes.fromhex('00112233445566778899aabb810000640800') + ipv4(udp(data=dns()), 17)
    pcap(vlan, [frame])
    rv = run(vlan)
    check(rv.returncode == 0 and 'VLAN frames:         1' in rv.stdout,
          f'VLAN decode failed\n{rv.stdout}\n{rv.stderr}')

    # TCP data-offset validation: valid 20-byte header accepted; offset < 5 rejected.
    tcp_test = os.path.join(td, 'tcp-offset.pcap')
    valid_tcp = bytes.fromhex('3039005000000000000000005002100000000000')
    invalid_tcp = bytes.fromhex('3039005000000000000000004002100000000000')
    pcap(tcp_test, [ethernet(ipv4(valid_tcp, 6)), ethernet(ipv4(invalid_tcp, 6))])
    rt = run(tcp_test)
    check(rt.returncode == 0 and 'TCP:           1' in rt.stdout,
          f'TCP data-offset validation failed\n{rt.stdout}')

    # Port-53 datagram with only the UDP header is a candidate, not a DNS header.
    dns_short = os.path.join(td, 'dns-short.pcap')
    pcap(dns_short, [ethernet(ipv4(udp(data=b''), 17))])
    rs = run(dns_short)
    check(rs.returncode == 0 and 'DNS port candidates: 1' in rs.stdout
          and 'DNS headers:         0' in rs.stdout,
          f'short DNS payload misclassified\n{rs.stdout}')

    # UDP length must fit inside the IPv4 payload.
    udp_bad = os.path.join(td, 'udp-length.pcap')
    bad_udp = struct.pack('!HHHH', 12345, 53, 40, 0)
    pcap(udp_bad, [ethernet(ipv4(bad_udp, 17))])
    ru = run(udp_bad)
    check(ru.returncode == 0 and 'UDP:           0' in ru.stdout,
          f'oversized UDP length accepted\n{ru.stdout}')

    # Non-initial IPv4 fragment must not be misclassified as a transport header.
    frag = os.path.join(td, 'fragment.pcap')
    pcap(frag, [ethernet(ipv4(b'abcdefgh', 17, flags_offset=1))])
    rf = run(frag)
    check(rf.returncode == 0 and 'IP fragments:        1' in rf.stdout,
          f'fragment accounting failed\n{rf.stdout}')
    check('UDP:           0' in rf.stdout, 'non-initial fragment counted as UDP')

    truncated = os.path.join(td, 'truncated.pcap')
    with open(truncated, 'wb') as f:
        f.write(open(good, 'rb').read()[:-3])
    check(run(truncated).returncode != 0, 'truncated record accepted')

    wrong_version = os.path.join(td, 'wrong-version.pcap')
    pcap(wrong_version, [], major=3)
    check(run(wrong_version).returncode != 0, 'invalid PCAP version accepted')

    wrong_link = os.path.join(td, 'wrong-link.pcap')
    pcap(wrong_link, [], linktype=101)
    check(run(wrong_link).returncode != 0, 'unsupported link type accepted')

    bad_orig = os.path.join(td, 'bad-orig-length.pcap')
    with open(bad_orig, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack('<IIII', 1, 0, 20, 10) + b'X' * 20)
    check(run(bad_orig).returncode != 0, 'incl_len > orig_len accepted')

    bad_snap = os.path.join(td, 'bad-snaplen.pcap')
    pcap(bad_snap, [ethernet(ipv4(udp(), 17))], snaplen=10)
    check(run(bad_snap).returncode != 0, 'record larger than snaplen accepted')

    bad_timestamp = os.path.join(td, 'bad-timestamp.pcap')
    with open(bad_timestamp, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        packet = ethernet(ipv4(udp(), 17))
        f.write(struct.pack('<IIII', 1, 1000000, len(packet), len(packet)) + packet)
    check(run(bad_timestamp).returncode != 0, 'invalid microsecond timestamp accepted')

    # Fill the fixed flow table and verify bounded overflow accounting.
    flow_full = os.path.join(td, 'flow-full.pcap')
    many = [ethernet(ipv4(udp(src, 53), 17)) for src in range(1024, 5121)]
    pcap(flow_full, many)
    rfull = run(flow_full)
    check(rfull.returncode == 0 and 'Directional flows:   4096' in rfull.stdout
          and 'Flow table overflow: 1' in rfull.stdout,
          f'flow-table capacity policy failed\n{rfull.stdout}\n{rfull.stderr}')

    bad = os.path.join(td, 'bad.pcap')
    with open(bad, 'wb') as f:
        f.write(b'not a pcap')
    check(run(bad).returncode != 0, 'non-PCAP input accepted')
    check(run(os.path.join(td, 'missing.pcap')).returncode != 0,
          'missing input accepted')

    # Deterministic malformed-frame smoke corpus: the parser must reject or skip
    # hostile lengths without crashing or hanging.
    rng = random.Random(0x5048414E)
    fuzz_capture = os.path.join(td, 'fuzz-smoke.pcap')
    fuzz_frames = []
    for _ in range(256):
        payload = bytearray(rng.randbytes(rng.randrange(0, 129)))
        ethertype = rng.choice([0x0800, 0x86dd, 0x0806, 0x8100])
        fuzz_frames.append(ethernet(bytes(payload), ethertype))
    pcap(fuzz_capture, fuzz_frames)
    fuzz_result = subprocess.run([BIN, fuzz_capture], text=True, capture_output=True,
                                  timeout=5)
    check(fuzz_result.returncode == 0,
          f'malformed-frame smoke corpus crashed: {fuzz_result.stderr}')

    usage = subprocess.run([BIN], text=True, capture_output=True)
    check(usage.returncode != 0 and 'Usage:' in usage.stderr,
          'usage handling failed')

print('PHANTOM regression tests: PASS')
