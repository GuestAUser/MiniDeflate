# DEFLATE Compressor

A secure, high-performance file compression utility in pure C99.

## Features

- **Hash Chain LZSS** - O(1) pattern lookup with 4KB sliding window
- **Fast Huffman Decoding** - 12-bit lookup table for O(1) symbol decoding
- **CRC32 Verification** - IEEE 802.3 polynomial integrity checking
- **Security Hardened** - Path traversal protection, size limits, zip bomb prevention

## Build

```bash
gcc -O3 -march=native -Wall -Wextra -std=c99 deflate.c -o deflate
```

## Usage

```bash
# Compress
./deflate -c input.txt output.bin

# Decompress
./deflate -d output.bin restored.txt
```

## Output Example

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
| Window Size | 4 KB |
| Block Size | 32 KB |

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

1. **LZSS Stage**: Finds repeated patterns using hash chains, emits literals or (distance, length) pairs
2. **Huffman Stage**: Builds optimal prefix codes per 32KB block, encodes tokens
3. **Verification**: CRC32 computed during compression, verified on decompression

## File Format

```
[Magic: 4B] [Blocks...] [CRC32: 4B]

Block = [LastFlag: 1b] [MaxSym: 16b] [Depths...] [Huffman Data] [EOB]
```

## License

Copyright (c) 2025 [GuestAUser](https://github.com/GuestAUser). All rights reserved.

This software is proprietary. Unauthorized copying, modification, distribution, or use is strictly prohibited without prior written permission from the copyright holder.
