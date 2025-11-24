# MiniDeflate

A secure, portable DEFLATE-style compressor in pure C99.

## Features

- **Hash Chain LZSS** - O(1) pattern lookup, 4KB sliding window, 128-entry chain limit
- **Fast Huffman Decoding** - 12-bit lookup table for O(1) symbol resolution
- **CRC32 Verification** - IEEE 802.3 polynomial with per-byte integrity
- **Security Hardened** - Path traversal protection, zip bomb prevention, bounds-safe access
- **Portable** - Little-endian serialization, cross-architecture compatible

## Build

```bash
gcc -O3 -march=native -Wall -Wextra -std=c99 deflate.c -o deflate
```

## Usage

```bash
./deflate -c input.txt output.bin    # Compress
./deflate -d output.bin restored.txt # Decompress
```

## Output

```
Compression Complete
Input:  1048576 bytes
Output: 345678 bytes
Ratio:  32.96%
CRC32:  0xABCD1234
```

## Limits

| Parameter | Value |
|-----------|-------|
| Max Input | 1 GB |
| Max Output | 10 GB |
| Window | 4 KB |
| Block | 32 KB |
| Hash Table | 32K entries |
| Chain Depth | 128 |

## Error Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| -1 | I/O error |
| -2 | Memory allocation failed |
| -3 | Invalid format |
| -4 | Data corrupted |
| -5 | Size limit exceeded |
| -6 | Unsafe path |

## Algorithm

1. **LZSS** - Hash chain matching emits literals or (length, distance) pairs
2. **Huffman** - Canonical codes built per 32KB block, depths stored in 4-bit nibbles
3. **CRC32** - Computed on compression, verified on decompression

## File Format

```
[Magic: 4B LE] [Blocks...] [CRC32: 4B LE]

Block = [LastFlag: 1b] [MaxSym: 16b] [Depths: 4b each] [Huffman Data] [EOB]
```

## License

Copyright (c) 2025 [GuestAUser](https://github.com/GuestAUser). All rights reserved.

Proprietary software. Unauthorized use prohibited.
