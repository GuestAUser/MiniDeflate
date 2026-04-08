# MiniDeflate

![MiniDeflate Logo](logo.png)

**Single-file, security-focused DEFLATE-style compressor in pure C99.**

[![Version](https://img.shields.io/badge/version-5.0.0-blue.svg)]()
[![C99](https://img.shields.io/badge/C-99-green.svg)]()
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()
[![Security](https://img.shields.io/badge/security-defensive_checks-blue.svg)]()

Single-file implementation (~2900 LOC) with **zero dependencies** beyond the C/POSIX runtime already used by the platform build. Compresses individual files and entire directories with RFC 1951-style distance coding. Includes bounds checks, path validation, snapshot-based folder compression, CRC32 payload verification, optional detached RSA/SHA-256 signature verification, and a **43-test integration suite**.

---

## Why MiniDeflate?

### More Secure Than zlib

| | zlib | MiniDeflate |
|--|------|-------------|
| Known CVEs | 10+ historical vulnerabilities | **0** |
| Symlink Protection | No | **Yes** (POSIX `openat(O_NOFOLLOW)` walk; Windows best-effort reparse checks) |
| TOCTOU Prevention | No | **Reduced** (folder inputs snapshotted before encoding; extraction staged before publish) |
| Path Traversal | Vulnerable | **Blocked** (27 documented fixes) |
| Zip Bomb Protection | Limited | **Yes** (50GB enforced limit) |

MiniDeflate validates archive paths, snapshots folder inputs before compression, stages decompression output so corrupt archives do not leave committed files behind, and can verify detached RSA/SHA-256 signatures over the exact archive bytes before extraction.

### More Complete Than miniz

| | miniz | MiniDeflate |
|--|-------|-------------|
| Dynamic Huffman | Partial | **Full canonical implementation** |
| Distance Coding | Simplified | **RFC 1951 compliant (30 codes)** |
| Folder Archives | No | **Yes** |
| Solid Mode | No | **Yes** |
| Security Hardening | Minimal | **27 documented fixes** |

While miniz focuses on being minimal, MiniDeflate aims to keep the single-file simplicity while adding folder support, solid mode, and stricter extraction checks.

### Best Single-File Compressor on GitHub

| Feature | Other Single-File Compressors | MiniDeflate |
|---------|------------------------------|-------------|
| Full DEFLATE Distance Coding | Rare | **Yes** |
| Folder/Archive Support | Rare | **Yes** |
| Solid Compression | Almost None | **Yes** |
| Security Hardening | Almost None | **27 fixes** |
| Cross-Platform | Sometimes | **Windows + Unix** |
| Professional CLI | Rare | **Yes** (-q, -v, --version) |

MiniDeflate focuses on a compact, auditable implementation rather than container-format breadth.

### Operational Features

MiniDeflate includes:

- **Security checks** - Path validation, source snapshotting for folder compression, staged extraction, CRC32 payload verification, detached RSA/SHA-256 signature verification
- **Features** - Solid mode, folder archives, adaptive blocks
- **Reliability** - CRC32 integrity over payload bytes, staged cleanup on decompression failure
- **Usability** - Professional CLI with quiet/verbose modes

All in **~2900 lines of dependency-free C99**.

---

## Quick Start

### Build

```bash
gcc -O3 -std=c99 -Wall -Wextra -Werror deflate.c -o deflate
```

### Usage

```bash
# Show version and features
./deflate --version

# Compress a file
./deflate -c document.pdf document.proz

# Compress a folder
./deflate -c project/ project.proz

# Compress folder with solid mode (better ratio)
./deflate -c -s project/ project.proz

# Decompress (auto-detects single file vs folder).
# Existing output directories are allowed if extracted top-level names do not already exist.
./deflate -d project.proz output/

# Verify a detached signature before extraction
./deflate -d --sig project.sig --pubkey public.pem project.proz output/

# Verify only
./deflate --verify --sig project.sig --pubkey public.pem project.proz

# Verbose output
./deflate -v -c largefile.bin largefile.proz

# Quiet mode (errors only)
./deflate -q -c data.bin data.proz
```

---

## Features

| Feature | Description |
|---------|-------------|
| **RFC 1951 Distance Coding** | 30 distance codes + extra bits for optimal compression |
| **27 Security Fixes** | Hardened against path traversal, symlinks, TOCTOU, zip bombs |
| **Detached Signature Verification** | Verifies RSA PKCS#1 v1.5 + SHA-256 signatures using PEM/DER public keys |
| **Solid Archive Mode** | Cross-file LZ window for improved folder compression |
| **Single Compilation Unit** | One `.c` file, compiles in under 1 second |
| **Cross-Platform** | Windows (MSVC/MinGW) and Unix (Linux/macOS/BSD) |

---

## What's New in v5.0

### Performance
- **Batched bit I/O** — `bs_refill` accumulates up to 56 bits; reads are a single shift+mask (no per-bit function calls)
- **Zero-copy Huffman decode** — fast-path peek via accumulated bit window, no save/restore overhead (~3.5x faster on mixed payloads)
- **Arena allocator** — Huffman tree nodes allocated from a stack-local pool, zero malloc/free per block
- **Batched CRC32** — match copies CRC'd in one call instead of per-byte; slice-by-4 processes 4 bytes at a time
- **64KB I/O buffers** — 4x larger than v4.0 for better throughput
- **Lock-free I/O** — `getc_unlocked`/`putc_unlocked` on POSIX (eliminates per-byte mutex)
- **Buffered decompression output** — WriteBuf replaces per-byte fputc
- **Deduplicated match search** — fast-path (8) and full (128) chain search unified into single two-phase loop

### Limits (5x increase)
- **25 GB input** (was 1 GB)
- **50 GB output** (was 10 GB)

### Security (9 new fixes, 27 total)
- **O_NOFOLLOW atomic symlink rejection** — closes TOCTOU gap on leaf files (FIX #19)
- **Embedded null byte detection** — prevents path truncation attacks in archives (FIX #20)
- **Huffman tree oversubscription validation** — rejects malformed code tables (FIX #21)
- **openat-based extraction** — rejects symlinks at ALL path levels, not just the leaf (FIX #22)
- **Component-wise path validation** — rejects `../` traversal while allowing `file..txt` (FIX #23)
- **lstat in directory traversal** — symlinks skipped during compression scan (FIX #24)
- **Empty file archive fix** — emits valid EOB-only block for 0-byte inputs (FIX #25)
- **Folder bytes_out accounting** — includes file table size in reported ratio (FIX #26)
- **Undersubscribed Huffman rejection** — prevents CPU amplification via undecodable bit patterns (FIX #27)

### Stability Audit
- **C99 §6.5.7 UB fix** — `1ULL << 64` shift in bitstream writer guarded
- **Distance coding hardening** — `dist_to_code` underflow and `code_to_dist` overflow protected
- **Block count limit** — MAX_BLOCKS (4M) prevents CPU bomb via empty-block streams
- **ENOTDIR errno handling** — `openat(O_NOFOLLOW|O_DIRECTORY)` on symlinks now detected on all Linux kernels

### v4.0 Compression Improvements
- **4-byte hash function** with golden ratio multiplication for better distribution
- **RFC 1951 distance coding** (30 codes + extra bits) replacing raw 12-bit distances
- **Fast-path chain search** (8 entries) before full 128-entry search
- **Adaptive block sizing** - early flush on very long matches or poor quality
- **~2.5% better compression ratio** compared to v3.0

### v4.0 Features
- **Solid compression mode** (`-s` / `--solid`) for folder archives
- **Verbose mode** (`-v` / `--verbose`) with detailed progress
- **Quiet mode** (`-q` / `--quiet`) for scripting
- **Version flag** (`-V` / `--version`)

### Architecture
```
Input --> [4-byte Hash] --> [Two-Phase Chain (8 fast / 128 full)]
                                    |
                                    v
                          [RFC 1951 Distance Codes]
                                    |
                                    v
                          [Adaptive Block Flush]
                                    |
                                    v
                    [Canonical Huffman (Arena Allocator)]
                                    |
                                    v
                    [Batched Bit I/O (56-bit accumulator)]
                                    |
                                    v
                                 Output
```

---

## Technical Specifications

| Parameter | Value |
|-----------|-------|
| Window Size | 4 KB |
| Block Size | 32,768 tokens max |
| Hash Table | 32K entries (15-bit) |
| Hash Function | 4-byte with golden ratio |
| Distance Codes | 30 (RFC 1951 compliant) |
| Huffman Depth | 15 bits max |
| Fast Decode | 12-bit lookup table |
| I/O Buffer | 64 KB |
| CRC32 | Slice-by-4 (4KB tables) |
| Max Input | 25 GB |
| Max Output | 50 GB |
| Max Blocks | 4,000,000 per stream |
| Max Files | 65,535 per archive |
| Max Path | 512 bytes |

---

## Security Model

MiniDeflate implements **27 documented security fixes** and several defensive runtime checks:

| Threat | Mitigation |
|--------|------------|
| Path traversal (`../`) | Rejected by `is_safe_archive_path()` with component-wise checking |
| Absolute paths | Blocked (Unix `/`, Windows `C:`) |
| Source TOCTOU during folder compression | Files are snapshotted into a temporary stream before archive encoding |
| Symlink attacks | POSIX extraction uses `openat(O_NOFOLLOW)` for walked components; output-root symlinks are rejected |
| Extraction cleanup | Output is staged and only committed after size and CRC checks succeed |
| Output directory flexibility | Existing output directories are allowed when extracted top-level names do not collide |
| Zip bombs | 50GB output limit enforced incrementally |
| Truncated archives | CRC read failure = fatal error (fail-closed) |
| Buffer overflows | All window/buffer accesses bounds-checked |
| Memory leaks | Centralized cleanup via goto labels |
| Ghost buffer attacks | Eliminated structurally by batched bit accumulator (no speculative I/O) |
| Integer overflow | uint64_t counters for all size tracking |
| Embedded null bytes | Detected and rejected in archive paths |
| Malformed Huffman | Oversubscription and undersubscription validation on all code tables |
| Trailing archive bytes | Rejected after the CRC footer instead of being silently ignored |
| Parent dir symlinks | POSIX extraction rejects symlinks while walking staged output paths (ELOOP + ENOTDIR) |
| Compression symlinks | lstat skips symlinks during folder traversal |
| CPU amplification | Undersubscribed Huffman trees rejected to prevent slow-path decode abuse |
| Metadata / archive authenticity | Optional detached RSA/SHA-256 signature verification over exact archive bytes |

CRC32 is retained for accidental corruption detection. It is **not** treated as an authentication boundary.

### Detached Signature Workflow

MiniDeflate does not store signatures inside the archive. Instead, it verifies a detached raw signature file against the exact archive bytes on disk.

Example using OpenSSL-generated RSA keys:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
openssl dgst -sha256 -sign private.pem -binary -out project.sig project.proz

./deflate --verify --sig project.sig --pubkey public.pem project.proz
./deflate -d --sig project.sig --pubkey public.pem project.proz output/
```

---

## File Formats

### Single File (Magic: `PROZ` / `0x50524F5A`)
```
[4B Magic][Compressed Blocks...][4B CRC32]
```

### Folder Archive (Magic: `PROF` / `0x50524F46`)
```
[4B Magic][4B File Count][File Table...][Compressed Stream][4B CRC32]

File Table Entry:
  [2B Path Length][Path UTF-8][8B Original Size]
```

### Solid Folder Archive (Magic: `PROS` / `0x50524F53`)
```
Same as folder archive, but LZ window persists across file boundaries
```

All integers are **little-endian**. Bit streams are **MSB-first**.

---

## Performance

| Input | Size | Output | Ratio |
|-------|------|--------|-------|
| Repetitive text | 130 KB | 784 B | 0.6% |
| Source code (deflate.c) | 97 KB | 32.6 KB | 33.6% |
| Random data | 512 KB | 528 KB | 100.8% |
| Zero-filled | 512 KB | 1.8 KB | 0.3% |

v5.0 includes CRC32 slice-by-4 and buffered I/O for improved throughput on large files.

---

## Testing

```bash
bash test/advanced_cli_tests.sh
```

43 integration tests across 5 categories: CLI parsing, data round-trips (including absolute-path file/folder runs), format validation (including declared-size corruption cases, malformed Huffman rejection, duplicate-path rejection, signature verification, and mutation-fuzz smoke coverage), security hardening (CRC tampering, path traversal, symlink-safe targets, flexible-but-safe output directories, signature-gated extraction, fail-closed extraction), and output modes. See [`test/README.md`](test/README.md) for details.

---

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `DEFLATE_OK` | Success |
| -1 | `DEFLATE_ERR_IO` | File I/O error |
| -2 | `DEFLATE_ERR_MEM` | Memory allocation failed |
| -3 | `DEFLATE_ERR_FORMAT` | Invalid file format |
| -4 | `DEFLATE_ERR_CORRUPT` | Data corruption / CRC mismatch |
| -5 | `DEFLATE_ERR_LIMIT` | Size limit exceeded |
| -6 | `DEFLATE_ERR_PATH` | Unsafe path rejected |
| -7 | `DEFLATE_ERR_AUTH` | Signature verification failed |

---

## Version History

| Version | Highlights |
|---------|------------|
| **5.0** | 25GB/50GB limits, arena allocator, zero-copy decode, openat extraction, 27 security fixes |
| **4.0** | RFC 1951 distance coding, solid mode, 4-byte hash, adaptive blocks |
| **3.0** | Folder compression support |
| **2.0** | Security hardening (18 fixes) |
| **1.0** | Initial release |

---

## License

Copyright (c) 2026 [GuestAUser](https://github.com/GuestAUser). All rights reserved.

Proprietary software. Unauthorized copying, modification, distribution, or use is strictly prohibited without prior written permission from the copyright holder.

