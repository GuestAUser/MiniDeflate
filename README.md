# MiniDeflate

A production-grade, security-hardened DEFLATE-style compressor in pure C99.

Single-file implementation with **zero dependencies** beyond the C standard library. Supports both individual files and entire directories.

![Architecture Diagram](diagram.png)

## Features

### Compression
- **Hash Chain LZSS** - O(1) pattern lookup via 32K-entry hash table
- **4KB Sliding Window** - Double-buffered for safe boundary handling
- **Canonical Huffman** - Optimal prefix codes rebuilt per 32KB block
- **12-bit Fast Decode** - O(1) symbol resolution via lookup table
- **Folder Archives** - Compress entire directories with preserved structure

### Security
- **Path Traversal Protection** - Rejects `..`, absolute paths, and dangerous characters
- **Symlink Attack Prevention** - Refuses to follow symlinks/reparse points on output
- **Zip Bomb Prevention** - Enforces 1GB input / 10GB output limits
- **Bounds-Safe Access** - All window/buffer accesses are clamped and verified
- **Fail-Closed Integrity** - Truncated files are rejected, not warned

### Robustness
- **No Memory Leaks** - All error paths properly free allocations
- **Portable Serialization** - Little-endian byte-by-byte I/O, safe on any architecture
- **Cross-Platform** - Windows (MSVC/MinGW) and Unix (Linux/macOS) support
- **Debug Assertions** - Optional compile-time diagnostics via `-DDEBUG`

## Build

```bash
gcc -O3 -std=c99 -Wall -Wextra deflate.c -o deflate
```

## Usage

```bash
# Compress a file
./deflate -c input.txt output.proz

# Compress a folder
./deflate -c myfolder/ archive.proz

# Decompress (auto-detects file vs folder)
./deflate -d archive.proz output/
```

### Example Output

```
Scanning directory 'src'...
Found 56 files to compress
  Compressing: main.rs (654 bytes)
  Compressing: game/draw.rs (31771 bytes)
  ...

Folder Compression Complete
Files:  56
Input:  261345 bytes
Output: 76719 bytes
Ratio:  29.36%
CRC32:  0x0CD466C5
```

## File Format

### Single File Archive (Magic: `0x50524F5A`)
```
[Magic 4B][Compressed Blocks...][CRC32 4B]
```

### Folder Archive (Magic: `0x50524F46`)
```
[Magic 4B][File Count 4B][File Table...][Compressed Stream][CRC32 4B]

File Table Entry:
[Path Length 2B][Path UTF-8][Original Size 8B]
```

All multi-byte values are little-endian. Bit streams are MSB-first.

## Technical Specifications

| Parameter | Value |
|-----------|-------|
| Max Input | 1 GB |
| Max Output | 10 GB |
| Max Files per Archive | 65,535 |
| Max Path Length | 512 bytes |
| Window Size | 4 KB |
| Block Size | 32 KB |
| Hash Table | 32K entries |
| Huffman Depth | 15 bits max |

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `DEFLATE_OK` | Success |
| -1 | `DEFLATE_ERR_IO` | File I/O error |
| -2 | `DEFLATE_ERR_MEM` | Memory allocation failed |
| -3 | `DEFLATE_ERR_FORMAT` | Invalid file format |
| -4 | `DEFLATE_ERR_CORRUPT` | Data corruption or CRC mismatch |
| -5 | `DEFLATE_ERR_LIMIT` | Size limit exceeded |
| -6 | `DEFLATE_ERR_PATH` | Unsafe path rejected |

## Security Model

| Threat | Mitigation |
|--------|------------|
| Path traversal (`../`) | Rejected by `is_safe_path()` |
| Absolute paths | Rejected (Unix `/`, Windows `C:`) |
| Symlink attacks | `secure_fopen_write()` via lstat/reparse check |
| Zip bombs | 10GB output limit, checked incrementally |
| Truncated files | CRC read failure = fatal error |
| Malicious archives | Path validation on extraction |

## Performance

| Input | Output | Ratio |
|-------|--------|-------|
| 100KB repetitive text | 906 B | 0.91% |
| 261KB source code (56 files) | 77 KB | 29.4% |
| 1MB mixed content | ~350 KB | ~35% |

## License

Copyright (c) 2025 [GuestAUser](https://github.com/GuestAUser). All rights reserved.

Proprietary software. Unauthorized copying, modification, distribution, or use is strictly prohibited without prior written permission from the copyright holder.
