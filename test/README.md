# MiniDeflate Test Suite

Integration tests for MiniDeflate v5.0. The suite builds `deflate.c` from
source in an isolated temp directory and exercises the resulting binary through
**43 test cases** organised into five categories.

---

## Quick Start

```bash
bash test/advanced_cli_tests.sh
```

Override the compiler with `CC`:

```bash
CC=gcc-13 bash test/advanced_cli_tests.sh
```

Typical run time is ~2 seconds on a modern machine.

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| C99 compiler (`cc` or `$CC`) | Builds `deflate.c` with `-O3 -std=c99 -Wall -Wextra -Werror` |
| `python3` | Data generators, binary patching, magic-byte inspection |
| `diff` | Recursive directory comparison (`assert_dir_eq`) |
| `cmp` | Byte-level file comparison (`assert_file_eq`) |
| `ln -s` | Symlink creation for security tests |

All tools are standard on Linux, macOS, and FreeBSD.

---

## Test Categories

### Category A — CLI Argument Parsing (8 tests)

Validates every documented flag and error path in `main()`.

| Test | What It Verifies |
|------|-----------------|
| `A01_version_flag` | `--version` exits 0, prints version string and feature list |
| `A02_help_flag` | `--help` exits 0, prints full usage with all options |
| `A03_no_args_shows_usage` | No arguments exits non-zero, still prints usage |
| `A04_conflicting_flags` | `-c -d` together is rejected |
| `A05_unknown_option` | `--bogus` is rejected |
| `A06_missing_paths` | `-c` with one path but no output is rejected |
| `A07_too_many_args` | Three positional arguments is rejected |
| `A08_verify_requires_sig` | `--verify` without `--sig/--pubkey` is rejected |

### Category B — Data Integrity Round-Trips (12 tests)

Compress then decompress, assert bit-exact output. Covers edge-case payloads
that stress different compressor code paths.

| Test | Payload | Key Assertion |
|------|---------|---------------|
| `B01_mixed_payload` | ~550 KB mixed text/binary with long runs, rotated alphabets, null bytes | Exact match + archive smaller than input |
| `B02_single_byte` | 1 byte (`Z`) | Exact match, output is exactly 1 byte |
| `B03_all_zeros` | 512 KB of `0x00` | Exact match, archive < 4 KB (~0.3% ratio) |
| `B04_incompressible` | 64 KB seeded PRNG (seed 42) | Exact match despite slight expansion |
| `B05_folder_nested` | 4-file tree: `root.txt`, `empty.bin` (0 bytes), `level1/file..txt`, `level1/level2/space name.bin` | Recursive `diff -qr` match. Tests empty files, double-dot in filename, spaces in paths |
| `B06_solid_mode` | 3 identical 3 KB files | Solid archive smaller than normal archive, `PROS` magic, exact extraction |
| `B07_empty_file` | 0 bytes | Exact match, output is exactly 0 bytes (validates FIX #25) |
| `B08_folder_empty_files` | Folder with 0-byte + non-empty files | Non-empty files extracted correctly alongside empty ones |
| `B09_large_multiblock` | 2 MB seeded PRNG (seed 99) | Exact match, exercises multiple Huffman blocks |
| `B10_folder_all_empty_files` | Folder with only 0-byte files, including nested paths | Recursive `diff -qr` match. Verifies every empty file is recreated |
| `B11_absolute_file_paths` | Absolute host paths for input, archive, and output | Exact round-trip using non-relative CLI arguments |
| `B12_absolute_folder_paths` | Absolute host paths for folder input, archive, and output directory | Recursive `diff -qr` match for folder mode |

### Category C — Archive Format Validation (12 tests)

Tests the binary format layer: magic bytes, bad input, truncation.

| Test | What It Verifies |
|------|-----------------|
| `C01_single_file_magic` | Single-file archives have `PROZ` (`0x50524F5A` LE) magic |
| `C02_folder_magic` | Non-solid folder archives have `PROF` (`0x50524F46` LE) magic |
| `C03_bad_magic` | Decompressing a non-archive file → `Unknown archive format` error |
| `C04_truncated_archive` | Archive cut to 10 bytes → decompression error (no crash) |
| `C05_nonexistent_input` | Missing input file → `Error opening input` on both `-c` and `-d` |
| `C06_folder_size_too_large` | Folder archive with declared file size larger than encoded payload | Rejects with folder payload size mismatch and leaves no extracted output |
| `C07_folder_size_too_small` | Folder archive with declared file size smaller than encoded payload | Rejects trailing decoded payload beyond declared file sizes and leaves no extracted output |
| `C08_trailing_data_after_footer` | Valid archive with bytes appended after CRC footer | Rejects trailing bytes instead of silently accepting them |
| `C09_duplicate_archive_paths` | Folder archive with two entries normalized to the same output path | Rejects the archive before any output is committed |
| `C10_missing_eob_huffman` | Archive with a complete Huffman tree that omits symbol 256 | Rejects canonical tables that cannot produce an end-of-block marker |
| `C11_mutation_fuzz_no_crash` | 100 random byte mutations of a valid archive | Decompressor never hangs or crashes on the mutation corpus |
| `C12_signature_verify_success` | Detached RSA/SHA-256 signature over a valid archive | `--verify` succeeds and reports `Signature Verified` |

### Category D — Security Hardening (9 tests)

Validates the 27 documented security fixes. These are adversarial tests that
craft malicious inputs and verify fail-closed behaviour.

| Test | Threat Model | Key Assertion |
|------|-------------|---------------|
| `D01_crc_corruption` | Bit-flip in CRC footer of a valid archive | `CRC Mismatch` error, non-zero exit, no output file left behind |
| `D02_path_traversal` | `../` injected into archive file table via binary patching | `Unsafe path in archive` error, escape file does not exist |
| `D03_output_root_symlink` | Folder extraction root is a symlink to another directory | Extraction is rejected before any payload is written to the symlink target |
| `D04_output_symlink` | Output path is a symlink to another file | `Output path is a symlink` error, target file not overwritten |
| `D05_existing_output_dir` | Folder extraction target already contains unrelated files | Extraction succeeds without modifying unrelated pre-existing files |
| `D06_folder_crc_cleanup` | CRC-corrupted folder archive | Extraction fails and leaves no extracted directory behind |
| `D07_existing_output_conflict` | Folder extraction target already contains a colliding top-level name | Extraction is rejected before any archive content is committed |
| `D08_signed_decompress_tampered` | Archive is modified after a detached signature is generated | Signature verification fails and decompression leaves no output behind |
| `D09_signature_wrong_key` | Archive signature checked with the wrong RSA public key | `--verify` fails authentication |

#### Path Traversal Test Details

The `D02` test exploits the archive binary format directly:

```c
PROF archive layout:
  [4B Magic][4B FileCount][2B PathLen][PathLen bytes Path][8B Size]...

The test creates a 1-file archive with filename "plainabc" (8 chars),
then patches bytes 10..17 to "../ab.cd" (also 8 chars). is_safe_archive_path()
rejects the ".." component.
```

#### Output Root Symlink Test Details

The `D03` test verifies that folder extraction refuses to use a symlinked
output root. A symlink is planted at `$out_dir` → `$escape_dir`. Extraction
must fail before any staging directory is committed to the final destination.

### Category E — Output Modes (2 tests)

| Test | What It Verifies |
|------|-----------------|
| `E01_verbose` | `-v` compress shows `CRC32:`, decompress shows `Computed CRC:` and `Integrity Verified` |
| `E02_quiet` | `-q` produces zero bytes on stdout and stderr for both compress and decompress |

---

## Framework API

The test framework provides a `run_in_workdir` + assertion pattern:

```bash
run_in_workdir <label> <command...>    # captures stdout/stderr/exit
assert_exit_ok                         # exit == 0
assert_exit_fail                       # exit != 0
assert_exit_code <N>                   # exit == N
assert_stdout_contains <string>        # grep -F in stdout
assert_stderr_contains <string>        # grep -F in stderr
assert_stdout_empty                    # stdout is 0 bytes
assert_stderr_empty                    # stderr is 0 bytes
assert_file_eq <path1> <path2>         # byte-identical (cmp -s)
assert_dir_eq <dir1> <dir2>            # recursive diff -qr
assert_smaller <smaller> <larger>      # file size comparison
assert_file_size <path> <N>            # exact byte count
assert_magic <archive> <PROZ|PROF|PROS># 4-byte LE magic check
assert_not_exists <path>               # path must not exist
```

All assertion failures call `fail()` which prints `FAIL: <message>` to stderr
and exits non-zero.

---

## Adding a New Test

1. Write a function named `test_X##_description` where `X` is the category
   letter and `##` is the next sequential number.

2. Use `run_in_workdir <label> "$BIN" ...` for relative-path tests or `run_raw`
   when you want to exercise absolute host filesystem paths.

3. Follow the run with assertions.

4. Register the test in `main()` with `run_test test_X##_description`.

Example:

```bash
test_B10_two_byte_roundtrip() {
    printf 'AB' > "$WORK_DIR/twobyte.bin"
    run_in_workdir 2b_c "$BIN" -c ./twobyte.bin ./twobyte.proz
    assert_exit_ok
    run_in_workdir 2b_d "$BIN" -d ./twobyte.proz ./twobyte.out
    assert_exit_ok
    assert_file_eq "$WORK_DIR/twobyte.bin" "$WORK_DIR/twobyte.out"
}
```

---

## Known Limitations

**Empty directories not preserved**: The archive format stores files, not
directory entries. Empty directories in the source tree are not recorded and
will not be recreated on extraction. Directories that contain at least one file
are created implicitly during extraction.

**Folder extraction conflicts are still fail-closed**: Folder decompression now
uses a staging directory and only commits output after the archive passes size,
CRC, and optional signature validation. Existing output directories are allowed,
but extraction is rejected if any extracted top-level path already exists.

## CI Integration

The script exits 0 on full pass, non-zero on any failure. It uses a fresh temp
directory per run and cleans up via `trap ... EXIT`. No persistent state is
written outside `/tmp`.

```yaml
# GitHub Actions example
- name: Test
  run: bash test/advanced_cli_tests.sh
```

Environment variables:
- `CC` — override compiler (default: `cc`)
- `TMPDIR` — override temp directory base (default: `/tmp`)
