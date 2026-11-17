.intel_syntax noprefix
.global _start
.equ SYS_read, 0
.equ SYS_write, 1
.equ SYS_open, 2
.equ SYS_close, 3
.equ SYS_exit, 60
.equ O_RDONLY, 0
.equ CAPACITY, 67108864
.equ BUFFER_SIZE, 67108865
.section .rodata
usage: .ascii "PHANTOM — Assembly-native passive PCAP analyzer\nUsage: phantom [--json] <capture.pcap>\n"
usage_len = . - usage
version_text: .ascii "PHANTOM 0.3.0\n"
version_len = . - version_text
err_open: .ascii "phantom: cannot open input file\n"
err_open_len = . - err_open
err_read: .ascii "phantom: read error\n"
err_read_len = . - err_read
err_size: .ascii "phantom: capture exceeds 64 MiB safety limit\n"
err_size_len = . - err_size
err_format: .ascii "phantom: unsupported or invalid classic PCAP file\n"
err_format_len = . - err_format
hdr: .ascii "\nPHANTOM / CAPTURE SUMMARY\n-------------------------\n"
hdr_len = . - hdr
s_packets: .ascii "Packets:       "
s_packets_len = . - s_packets
s_bytes: .ascii "Captured bytes: "
s_bytes_len = . - s_bytes
s_eth: .ascii "Ethernet:      "
s_eth_len = . - s_eth
s_ipv4: .ascii "IPv4:          "
s_ipv4_len = . - s_ipv4
s_ipv6: .ascii "IPv6:          "
s_ipv6_len = . - s_ipv6
s_tcp: .ascii "TCP:           "
s_tcp_len = . - s_tcp
s_udp: .ascii "UDP:           "
s_udp_len = . - s_udp
s_icmp: .ascii "ICMP/ICMPv6:   "
s_icmp_len = . - s_icmp
s_dns: .ascii "DNS port candidates: "
s_dns_len = . - s_dns
s_dns_valid: .ascii "DNS headers:         "
s_dns_valid_len = . - s_dns_valid
s_dns_query: .ascii "DNS queries:         "
s_dns_query_len = . - s_dns_query
s_dns_response: .ascii "DNS responses:       "
s_dns_response_len = . - s_dns_response
s_frag: .ascii "IP fragments:        "
s_frag_len = . - s_frag
s_vlan: .ascii "VLAN frames:         "
s_vlan_len = . - s_vlan
s_flows: .ascii "Directional flows:   "
s_flows_len = . - s_flows
s_flow_full: .ascii "Flow table overflow: "
s_flow_full_len = . - s_flow_full
j_open: .ascii "{\"packets\":"
j_open_len = . - j_open
j_bytes: .ascii ",\"captured_bytes\":"
j_bytes_len = . - j_bytes
j_eth: .ascii ",\"ethernet\":"
j_eth_len = . - j_eth
j_ipv4: .ascii ",\"ipv4\":"
j_ipv4_len = . - j_ipv4
j_ipv6: .ascii ",\"ipv6\":"
j_ipv6_len = . - j_ipv6
j_tcp: .ascii ",\"tcp\":"
j_tcp_len = . - j_tcp
j_udp: .ascii ",\"udp\":"
j_udp_len = . - j_udp
j_icmp: .ascii ",\"icmp\":"
j_icmp_len = . - j_icmp
j_dns: .ascii ",\"dns_port_candidates\":"
j_dns_len = . - j_dns
j_dns_valid: .ascii ",\"dns_headers\":"
j_dns_valid_len = . - j_dns_valid
j_dns_query: .ascii ",\"dns_queries\":"
j_dns_query_len = . - j_dns_query
j_dns_response: .ascii ",\"dns_responses\":"
j_dns_response_len = . - j_dns_response
j_frag: .ascii ",\"ip_fragments\":"
j_frag_len = . - j_frag
j_vlan: .ascii ",\"vlan_frames\":"
j_vlan_len = . - j_vlan
j_flows: .ascii ",\"directional_flows\":"
j_flows_len = . - j_flows
j_flow_full: .ascii ",\"flow_table_overflow\":"
j_flow_full_len = . - j_flow_full
j_close: .ascii "}\n"
j_close_len = . - j_close
nl: .byte 10
.section .bss
.align 16
buffer: .skip BUFFER_SIZE
num_buf: .skip 32
file_size: .quad 0
packet_count: .quad 0
captured_bytes: .quad 0
eth_count: .quad 0
ipv4_count: .quad 0
ipv6_count: .quad 0
tcp_count: .quad 0
udp_count: .quad 0
icmp_count: .quad 0
dns_count: .quad 0
dns_valid_count: .quad 0
dns_query_count: .quad 0
dns_response_count: .quad 0
fragment_count: .quad 0
vlan_count: .quad 0
flow_count: .quad 0
flow_overflow_count: .quad 0
flow_key: .skip 40
.align 16
flow_table: .skip 196608
little_endian: .skip 8
nano_precision: .skip 8
json_mode: .skip 8
snap_length: .long 0
.section .text
_start:
    mov rax, [rsp]
    cmp rax, 2
    je .arg_capture
    cmp rax, 3
    jne .usage
    mov rdi, [rsp+16]
    cmp dword ptr [rdi], 0x736a2d2d
    jne .usage
    cmp word ptr [rdi+4], 0x6e6f
    jne .usage
    mov qword ptr [rip+json_mode], 1
    mov rdi, [rsp+24]
    jmp .open_input
.arg_capture:
    mov rdi, [rsp+16]
    cmp dword ptr [rdi], 0x65682d2d
    jne .check_version
    cmp word ptr [rdi+4], 0x706c
    jne .check_version
    lea rsi, [rip+usage]
    mov edx, usage_len
    call write_stdout
    xor edi, edi
    jmp exit
.check_version:
    cmp dword ptr [rdi], 0x65762d2d
    jne .capture_path
    cmp dword ptr [rdi+4], 0x6f697372
    jne .capture_path
    cmp byte ptr [rdi+8], 'n'
    jne .capture_path
    lea rsi, [rip+version_text]
    mov edx, version_len
    call write_stdout
    xor edi, edi
    jmp exit
.capture_path:
.open_input:
    mov eax, SYS_open
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .open_error
    mov r12, rax
    lea r13, [rip+buffer]
    xor r14, r14
.read_loop:
    mov rax, SYS_read
    mov rdi, r12
    mov rsi, r13
    mov rdx, BUFFER_SIZE
    sub rdx, r14
    syscall
    test rax, rax
    jns .read_result_ok
    cmp rax, -4
    je .read_loop
    jmp .read_error_close
.read_result_ok:
    jz .read_done
    add r14, rax
    add r13, rax
    cmp r14, CAPACITY
    ja .size_error_close
    jmp .read_loop
.read_done:
    mov [rip+file_size], r14
    mov eax, SYS_close
    mov rdi, r12
    syscall
    cmp r14, 24
    jb .format_error
    lea rbx, [rip+buffer]
    mov eax, dword ptr [rbx]
    cmp eax, 0xa1b2c3d4
    je .pcap_little
    cmp eax, 0xd4c3b2a1
    je .pcap_big
    cmp eax, 0xa1b23c4d
    je .pcap_nano_little
    cmp eax, 0x4d3cb2a1
    je .pcap_nano_big
    jmp .format_error
.pcap_little:
    mov qword ptr [rip+little_endian], 1
    jmp .records_start
.pcap_big:
    mov qword ptr [rip+little_endian], 0
    jmp .records_start
.pcap_nano_little:
    mov qword ptr [rip+little_endian], 1
    mov qword ptr [rip+nano_precision], 1
    jmp .records_start
.pcap_nano_big:
    mov qword ptr [rip+little_endian], 0
    mov qword ptr [rip+nano_precision], 1
.records_start:
    /* Validate classic PCAP version 2.4 and Ethernet link type 1. */
    movzx eax, word ptr [rbx+4]
    movzx ecx, word ptr [rbx+6]
    cmp qword ptr [rip+little_endian], 1
    je .validate_header_fields
    xchg al, ah
    xchg cl, ch
.validate_header_fields:
    cmp ax, 2
    jne .format_error
    cmp cx, 4
    jne .format_error
    mov eax, dword ptr [rbx+20]
    cmp qword ptr [rip+little_endian], 1
    je .validate_linktype
    bswap eax
.validate_linktype:
    cmp eax, 1
    jne .format_error
    mov eax, dword ptr [rbx+16]
    cmp qword ptr [rip+little_endian], 1
    je .snaplen_ready
    bswap eax
.snaplen_ready:
    test eax, eax
    jz .format_error
    mov dword ptr [rip+snap_length], eax
    mov r15, 24
.record_loop:
    mov rax, [rip+file_size]
    cmp r15, rax
    je .summary
    mov rdx, rax
    sub rdx, r15
    cmp rdx, 16
    jb .format_error
    lea rbx, [rip+buffer]
    lea rbx, [rbx+r15]
    mov eax, dword ptr [rbx+4]
    cmp qword ptr [rip+little_endian], 1
    je .timestamp_ready
    bswap eax
.timestamp_ready:
    mov ecx, 1000000
    cmp qword ptr [rip+nano_precision], 1
    jne .timestamp_limit_ready
    mov ecx, 1000000000
.timestamp_limit_ready:
    cmp eax, ecx
    jae .format_error
    mov eax, dword ptr [rbx+8]
    cmp qword ptr [rip+little_endian], 1
    je .record_len_ready
    bswap eax
.record_len_ready:
    mov r8d, eax
    mov eax, dword ptr [rbx+12]
    cmp qword ptr [rip+little_endian], 1
    je .orig_len_ready
    bswap eax
.orig_len_ready:
    cmp r8d, eax
    ja .format_error
    cmp r8d, dword ptr [rip+snap_length]
    ja .format_error
    cmp r8, CAPACITY
    ja .format_error
    mov rax, [rip+file_size]
    sub rax, r15
    sub rax, 16
    cmp r8, rax
    ja .format_error
    inc qword ptr [rip+packet_count]
    add qword ptr [rip+captured_bytes], r8
    lea r9, [rbx+16]
    mov r10, r8
    cmp r10, 14
    jb .next_record
    inc qword ptr [rip+eth_count]
    movzx eax, word ptr [r9+12]
    xchg al, ah
    cmp ax, 0x0800
    je .ether_ipv4
    cmp ax, 0x86dd
    je .ether_ipv6
    cmp ax, 0x8100
    je .vlan_frame
    cmp ax, 0x88a8
    jne .next_record
.vlan_frame:
    cmp r10, 18
    jb .next_record
    inc qword ptr [rip+vlan_count]
    movzx eax, word ptr [r9+16]
    xchg al, ah
    cmp ax, 0x0800
    je .ether_ipv4_vlan
    cmp ax, 0x86dd
    je .ether_ipv6_vlan
    jmp .next_record
.ether_ipv4:
    add r9, 14
    sub r10, 14
    jmp .parse_ipv4
.ether_ipv4_vlan:
    add r9, 18
    sub r10, 18
    jmp .parse_ipv4
.ether_ipv6:
    add r9, 14
    sub r10, 14
    jmp .parse_ipv6
.ether_ipv6_vlan:
    add r9, 18
    sub r10, 18
    jmp .parse_ipv6
.parse_ipv4:
    cmp r10, 20
    jb .next_record
    movzx eax, byte ptr [r9]
    shr eax, 4
    cmp eax, 4
    jne .next_record
    inc qword ptr [rip+ipv4_count]
    movzx ecx, byte ptr [r9]
    and ecx, 15
    shl ecx, 2
    cmp ecx, 20
    jb .next_record
    cmp rcx, r10
    ja .next_record
    movzx eax, word ptr [r9+2]
    xchg al, ah
    cmp eax, ecx
    jb .next_record
    cmp rax, r10
    ja .next_record
    mov r10, rax
    movzx eax, word ptr [r9+6]
    xchg al, ah
    test ax, 0x3fff
    jz .ipv4_not_fragmented
    inc qword ptr [rip+fragment_count]
    test ax, 0x1fff
    jnz .next_record
.ipv4_not_fragmented:
    mov r12, r9
    mov r13d, 4
    movzx eax, byte ptr [r9+9]
    mov r11d, eax
    add r9, rcx
    sub r10, rcx
    cmp r11d, 6
    je .count_tcp
    cmp r11d, 17
    je .count_udp
    cmp r11d, 1
    je .count_icmp
    jmp .next_record
.parse_ipv6:
    cmp r10, 40
    jb .next_record
    movzx eax, byte ptr [r9]
    shr eax, 4
    cmp eax, 6
    jne .next_record
    inc qword ptr [rip+ipv6_count]
    movzx eax, word ptr [r9+4]
    xchg al, ah
    lea rcx, [rax+40]
    cmp rcx, r10
    ja .next_record
    mov r10, rax
    mov r12, r9
    mov r13d, 6
    movzx eax, byte ptr [r9+6]
    add r9, 40
    mov r11d, eax
.ipv6_extension_loop:
    cmp r11d, 0
    je .ipv6_ext_eight
    cmp r11d, 43
    je .ipv6_ext_eight
    cmp r11d, 60
    je .ipv6_ext_eight
    cmp r11d, 135
    je .ipv6_ext_eight
    cmp r11d, 51
    je .ipv6_ext_ah
    cmp r11d, 44
    je .ipv6_ext_fragment
    jmp .ipv6_dispatch
.ipv6_ext_eight:
    cmp r10, 2
    jb .next_record
    movzx eax, byte ptr [r9+1]
    inc eax
    shl eax, 3
    jmp .ipv6_ext_apply
.ipv6_ext_ah:
    cmp r10, 2
    jb .next_record
    movzx eax, byte ptr [r9+1]
    add eax, 2
    shl eax, 2
    jmp .ipv6_ext_apply
.ipv6_ext_fragment:
    cmp r10, 8
    jb .next_record
    inc qword ptr [rip+fragment_count]
    movzx eax, word ptr [r9+2]
    xchg al, ah
    and eax, 0xfff8
    test eax, eax
    jnz .next_record
    mov eax, 8
.ipv6_ext_apply:
    cmp rax, r10
    ja .next_record
    movzx r11d, byte ptr [r9]
    add r9, rax
    sub r10, rax
    jmp .ipv6_extension_loop
.ipv6_dispatch:
    cmp r11d, 6
    je .count_tcp
    cmp r11d, 17
    je .count_udp
    cmp r11d, 58
    je .count_icmp
    jmp .next_record
.count_tcp:
    cmp r10, 20
    jb .next_record
    movzx eax, byte ptr [r9+12]
    shr eax, 4
    shl eax, 2
    cmp eax, 20
    jb .next_record
    cmp rax, r10
    ja .next_record
    call record_flow
    inc qword ptr [rip+tcp_count]
    jmp .next_record
.count_udp:
    cmp r10, 8
    jb .next_record
    movzx eax, word ptr [r9+4]
    xchg al, ah
    cmp eax, 8
    jb .next_record
    cmp rax, r10
    ja .next_record
    mov r10, rax
    call record_flow
    inc qword ptr [rip+udp_count]
    movzx eax, word ptr [r9]
    xchg al, ah
    cmp ax, 53
    je .dns_candidate
    movzx eax, word ptr [r9+2]
    xchg al, ah
    cmp ax, 53
    jne .next_record
.dns_candidate:
    inc qword ptr [rip+dns_count]
    cmp r10, 20
    jb .next_record
    lea rbx, [r9+8]
    movzx eax, word ptr [rbx+4]
    xchg al, ah
    movzx ecx, word ptr [rbx+6]
    xchg cl, ch
    movzx edx, word ptr [rbx+8]
    xchg dl, dh
    movzx r11d, byte ptr [rbx+10]
    shl r11d, 8
    movzx esi, byte ptr [rbx+11]
    or r11d, esi
    add eax, ecx
    add eax, edx
    add eax, r11d
    cmp eax, 65535
    ja .next_record
    inc qword ptr [rip+dns_valid_count]
    test byte ptr [rbx+2], 0x80
    jnz .dns_response
    inc qword ptr [rip+dns_query_count]
    jmp .next_record
.dns_response:
    inc qword ptr [rip+dns_response_count]
    jmp .next_record
.count_icmp:
    cmp r10, 4
    jb .next_record
    inc qword ptr [rip+icmp_count]
.next_record:
    lea rax, [r15+r8+16]
    mov r15, rax
    jmp .record_loop
.summary:
    cmp qword ptr [rip+json_mode], 1
    je .json_summary
    lea rsi, [rip+hdr]
    mov edx, hdr_len
    call write_stdout
    lea rsi, [rip+s_packets]
    mov edx, s_packets_len
    call write_stdout
    mov rax, [rip+packet_count]
    call print_number
    lea rsi, [rip+s_bytes]
    mov edx, s_bytes_len
    call write_stdout
    mov rax, [rip+captured_bytes]
    call print_number
    lea rsi, [rip+s_eth]
    mov edx, s_eth_len
    call write_stdout
    mov rax, [rip+eth_count]
    call print_number
    lea rsi, [rip+s_ipv4]
    mov edx, s_ipv4_len
    call write_stdout
    mov rax, [rip+ipv4_count]
    call print_number
    lea rsi, [rip+s_ipv6]
    mov edx, s_ipv6_len
    call write_stdout
    mov rax, [rip+ipv6_count]
    call print_number
    lea rsi, [rip+s_tcp]
    mov edx, s_tcp_len
    call write_stdout
    mov rax, [rip+tcp_count]
    call print_number
    lea rsi, [rip+s_udp]
    mov edx, s_udp_len
    call write_stdout
    mov rax, [rip+udp_count]
    call print_number
    lea rsi, [rip+s_icmp]
    mov edx, s_icmp_len
    call write_stdout
    mov rax, [rip+icmp_count]
    call print_number
    lea rsi, [rip+s_dns]
    mov edx, s_dns_len
    call write_stdout
    mov rax, [rip+dns_count]
    call print_number
    lea rsi, [rip+s_dns_valid]
    mov edx, s_dns_valid_len
    call write_stdout
    mov rax, [rip+dns_valid_count]
    call print_number
    lea rsi, [rip+s_dns_query]
    mov edx, s_dns_query_len
    call write_stdout
    mov rax, [rip+dns_query_count]
    call print_number
    lea rsi, [rip+s_dns_response]
    mov edx, s_dns_response_len
    call write_stdout
    mov rax, [rip+dns_response_count]
    call print_number
    lea rsi, [rip+s_frag]
    mov edx, s_frag_len
    call write_stdout
    mov rax, [rip+fragment_count]
    call print_number
    lea rsi, [rip+s_vlan]
    mov edx, s_vlan_len
    call write_stdout
    mov rax, [rip+vlan_count]
    call print_number
    lea rsi, [rip+s_flows]
    mov edx, s_flows_len
    call write_stdout
    mov rax, [rip+flow_count]
    call print_number
    lea rsi, [rip+s_flow_full]
    mov edx, s_flow_full_len
    call write_stdout
    mov rax, [rip+flow_overflow_count]
    call print_number
    xor edi, edi
    jmp exit
.json_summary:
    lea rsi, [rip+j_open]
    mov edx, j_open_len
    call write_stdout
    mov rax, [rip+packet_count]
    call print_json_number
    lea rsi, [rip+j_bytes]
    mov edx, j_bytes_len
    call write_stdout
    mov rax, [rip+captured_bytes]
    call print_json_number
    lea rsi, [rip+j_eth]
    mov edx, j_eth_len
    call write_stdout
    mov rax, [rip+eth_count]
    call print_json_number
    lea rsi, [rip+j_ipv4]
    mov edx, j_ipv4_len
    call write_stdout
    mov rax, [rip+ipv4_count]
    call print_json_number
    lea rsi, [rip+j_ipv6]
    mov edx, j_ipv6_len
    call write_stdout
    mov rax, [rip+ipv6_count]
    call print_json_number
    lea rsi, [rip+j_tcp]
    mov edx, j_tcp_len
    call write_stdout
    mov rax, [rip+tcp_count]
    call print_json_number
    lea rsi, [rip+j_udp]
    mov edx, j_udp_len
    call write_stdout
    mov rax, [rip+udp_count]
    call print_json_number
    lea rsi, [rip+j_icmp]
    mov edx, j_icmp_len
    call write_stdout
    mov rax, [rip+icmp_count]
    call print_json_number
    lea rsi, [rip+j_dns]
    mov edx, j_dns_len
    call write_stdout
    mov rax, [rip+dns_count]
    call print_json_number
    lea rsi, [rip+j_dns_valid]
    mov edx, j_dns_valid_len
    call write_stdout
    mov rax, [rip+dns_valid_count]
    call print_json_number
    lea rsi, [rip+j_dns_query]
    mov edx, j_dns_query_len
    call write_stdout
    mov rax, [rip+dns_query_count]
    call print_json_number
    lea rsi, [rip+j_dns_response]
    mov edx, j_dns_response_len
    call write_stdout
    mov rax, [rip+dns_response_count]
    call print_json_number
    lea rsi, [rip+j_frag]
    mov edx, j_frag_len
    call write_stdout
    mov rax, [rip+fragment_count]
    call print_json_number
    lea rsi, [rip+j_vlan]
    mov edx, j_vlan_len
    call write_stdout
    mov rax, [rip+vlan_count]
    call print_json_number
    lea rsi, [rip+j_flows]
    mov edx, j_flows_len
    call write_stdout
    mov rax, [rip+flow_count]
    call print_json_number
    lea rsi, [rip+j_flow_full]
    mov edx, j_flow_full_len
    call write_stdout
    mov rax, [rip+flow_overflow_count]
    call print_json_number
    lea rsi, [rip+j_close]
    mov edx, j_close_len
    call write_stdout
    xor edi, edi
    jmp exit
.usage:
    lea rsi, [rip+usage]
    mov edx, usage_len
    call write_stderr
    mov edi, 2
    jmp exit
.open_error:
    lea rsi, [rip+err_open]
    mov edx, err_open_len
    call write_stderr
    mov edi, 1
    jmp exit
.read_error_close:
    mov eax, SYS_close
    mov rdi, r12
    syscall
    lea rsi, [rip+err_read]
    mov edx, err_read_len
    call write_stderr
    mov edi, 1
    jmp exit
.size_error_close:
    mov eax, SYS_close
    mov rdi, r12
    syscall
    lea rsi, [rip+err_size]
    mov edx, err_size_len
    call write_stderr
    mov edi, 1
    jmp exit
.format_error:
    lea rsi, [rip+err_format]
    mov edx, err_format_len
    call write_stderr
    mov edi, 1
    jmp exit
/* Bounded directional 5-tuple table. Entries store a 64-bit FNV-1a hash
   plus the complete 40-byte key; hash collisions are resolved by key compare. */
record_flow:
    push r8
    push r10
    lea rdi, [rip+flow_key]
    xor eax, eax
    mov ecx, 40
    rep stosb
    mov byte ptr [rip+flow_key], r13b
    mov byte ptr [rip+flow_key+1], r11b
    cmp r13d, 4
    jne .flow_ipv6_key
    mov eax, dword ptr [r12+12]
    mov dword ptr [rip+flow_key+2], eax
    mov eax, dword ptr [r12+16]
    mov dword ptr [rip+flow_key+18], eax
    jmp .flow_ports
.flow_ipv6_key:
    mov rax, qword ptr [r12+8]
    mov qword ptr [rip+flow_key+2], rax
    mov rax, qword ptr [r12+16]
    mov qword ptr [rip+flow_key+10], rax
    mov rax, qword ptr [r12+24]
    mov qword ptr [rip+flow_key+18], rax
    mov rax, qword ptr [r12+32]
    mov qword ptr [rip+flow_key+26], rax
.flow_ports:
    mov ax, word ptr [r9]
    mov word ptr [rip+flow_key+34], ax
    mov ax, word ptr [r9+2]
    mov word ptr [rip+flow_key+36], ax
    lea rsi, [rip+flow_key]
    movabs rax, 0xcbf29ce484222325
    movabs r10, 0x100000001b3
    mov ecx, 40
.flow_hash_loop:
    movzx edi, byte ptr [rsi]
    xor rax, rdi
    imul rax, r10
    inc rsi
    dec ecx
    jnz .flow_hash_loop
    test rax, rax
    jnz .flow_hash_ready
    mov eax, 1
.flow_hash_ready:
    mov r8, rax
    mov r11d, eax
    and r11d, 4095
    mov r10d, 4096
.flow_probe:
    mov rdx, r11
    imul rdx, 48
    lea rdi, [rip+flow_table]
    add rdi, rdx
    mov rax, qword ptr [rdi]
    test rax, rax
    jz .flow_insert
    cmp rax, r8
    jne .flow_next_slot
    add rdi, 8
    lea rsi, [rip+flow_key]
    mov ecx, 40
    repe cmpsb
    je .flow_done
.flow_next_slot:
    inc r11d
    and r11d, 4095
    dec r10d
    jnz .flow_probe
    inc qword ptr [rip+flow_overflow_count]
    jmp .flow_done
.flow_insert:
    mov qword ptr [rdi], r8
    add rdi, 8
    lea rsi, [rip+flow_key]
    mov ecx, 40
    rep movsb
    inc qword ptr [rip+flow_count]
.flow_done:
    pop r10
    pop r8
    ret

write_stdout:
    mov edi, 1
    jmp write_all
write_stderr:
    mov edi, 2
write_all:
    mov r8, rdi
.write_loop:
    test rdx, rdx
    jz .write_done
    mov eax, SYS_write
    mov rdi, r8
    syscall
    test rax, rax
    jns .write_progress
    cmp rax, -4
    je .write_loop
    jmp .write_done
.write_progress:
    test rax, rax
    jz .write_done
    add rsi, rax
    sub rdx, rax
    jmp .write_loop
.write_done:
    ret
print_number:
    lea rdi, [rip+num_buf+31]
    mov byte ptr [rdi], 10
    mov ecx, 1
    mov ebx, 10
    test rax, rax
    jne .digits
    dec rdi
    mov byte ptr [rdi], '0'
    inc ecx
    jmp .emit
.digits:
    xor edx, edx
    div rbx
    add dl, '0'
    dec rdi
    mov byte ptr [rdi], dl
    inc ecx
    test rax, rax
    jne .digits
.emit:
    mov rsi, rdi
    mov edx, ecx
    call write_stdout
    ret
print_json_number:
    lea rdi, [rip+num_buf+31]
    xor ecx, ecx
    mov ebx, 10
    test rax, rax
    jne .json_digits
    dec rdi
    mov byte ptr [rdi], '0'
    inc ecx
    jmp .json_emit
.json_digits:
    xor edx, edx
    div rbx
    add dl, '0'
    dec rdi
    mov byte ptr [rdi], dl
    inc ecx
    test rax, rax
    jne .json_digits
.json_emit:
    mov rsi, rdi
    mov edx, ecx
    call write_stdout
    ret
exit:
    mov eax, SYS_exit
    syscall
