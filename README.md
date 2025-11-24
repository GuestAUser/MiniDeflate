# MiniDeflate

A high-performance, single-file implementation of a DEFLATE-style hybrid compression engine in standard C99.

This project implements the core logic behind modern archivers (like `gzip` and `zlib`) from first principles, combining **LZSS** (Lempel-Ziv-Storer-Szymanski) for dictionary compression and **Canonical Huffman Coding** for entropy encoding.

## Features

  * **Hybrid Architecture:** Chains LZSS tokenization with Block-Based Canonical Huffman coding.
  * **Zero Dependencies:** Written in pure C99 standard library (`<stdio.h>`, `<stdlib.h>`).
  * **Data Integrity:** Implements full **CRC32** checksum verification on decompression.
  * **Systems Ready:** Uses heap allocation for large structures to prevent stack overflows; completely encapsulated state.
  * **High Efficiency:** Achieves \~60-70% compression ratios on text and source code (comparable to early `zip` versions).

## Compilation

The project is contained entirely within `deflate.c`. For maximum performance (vectorization of the sliding window search), compile with `-O3`.

```bash
# GCC / MinGW
gcc -O3 deflate.c -o deflate

# Clang
clang -O3 deflate.c -o deflate

# MSVC
cl /O2 deflate.c
```

## Usage

### Compression

Compresses a source file into a proprietary `.bin` format.

```bash
./deflate -c <input_file> <output_file>
```

*Example:*

```bash
./deflate -c source_code.c payload.bin
# Output: Compression Complete. CRC32: 0xA1B2C3D4
```

### Decompression

Restores the original file and verifies bit-perfect integrity using CRC32.

```bash
./deflate -d <input_file> <output_file>
```

*Example:*

```bash
./deflate -d payload.bin restored.c
# Output: Integrity Verified: OK.
```

## Technical Architecture

The engine operates in a streaming pipeline:

1.  **LZSS Tokenizer:**

      * Uses a **4KB Sliding Window** (Circular Buffer).
      * Maintains a **Binary Search Tree** (BST) to find longest string matches in $O(\log n)$.
      * Emits a stream of **Tokens**: either *Literals* (0-255) or *Matches* (Length 3-258, Distance 1-4096).

2.  **Frequency Analysis (Block Based):**

      * Processes data in **32KB Blocks**.
      * Constructs a dynamic frequency table for the block's tokens.

3.  **Canonical Huffman Encoder:**

      * Builds a Min-Heap to generate an optimal prefix tree.
      * Calculates bit-lengths for every symbol.
      * Generates **Canonical Codes** (numerical sequence based on bit-length) to minimize header overhead.

4.  **Bitstream I/O:**

      * Packs variable-length codes into a buffered 16KB stream.
      * Appends a 32-bit CRC checksum at the file footer.

## File Format Specification

| Offset | Size | Description |
| :--- | :--- | :--- |
| 0x00 | 4 Bytes | **Magic Signature** (`0x50524F5A` / "PROZ") |
| 0x04 | Var | **Data Blocks** (Header + Bitstream) |
| EOF-4 | 4 Bytes | **CRC32 Checksum** (Little Endian) |

## License

This software is provided "as is", without warranty of any kind. Free to use for educational and commercial purposes.