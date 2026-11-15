# Memory model

PHANTOM uses static storage in `.bss`; it does not call a general-purpose allocator.

| Region | Size | Purpose |
|---|---:|---|
| Capture buffer | 64 MiB + 1 byte | Bounded whole-file input and overflow detection |
| Decimal buffer | 32 bytes | Integer-to-text conversion |
| Flow key scratch | 40 bytes | Current directional 5-tuple |
| Flow table | 196,608 bytes | 4,096 entries × 48 bytes |
| Counters and flags | Small fixed set | Packet and parser accounting |

Each flow entry contains an 8-byte FNV-1a hash and a 40-byte complete key. The hash selects the initial slot; a full key comparison resolves collisions. Linear probing is bounded to 4,096 slots. There is no eviction or unbounded allocation.

The capture buffer is intentionally simple but limits maximum input size and increases virtual memory requirements. Streaming input is a future architectural change, not a current feature.
