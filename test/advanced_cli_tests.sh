#!/usr/bin/env bash
# ===========================================================================
# MiniDeflate v5.0 — Advanced Integration Test Suite
#
# Builds deflate.c in a disposable temp directory and exercises the binary
# through 20 test cases covering:
#
#   Category A  — CLI argument parsing and flags
#   Category B  — Data integrity round-trips (edge-case payloads)
#   Category C  — Archive format validation
#   Category D  — Security hardening (path traversal, symlinks, CRC)
#   Category E  — Output mode behaviour (verbose / quiet)
#
# Prerequisites: cc (or $CC), python3, diff, cmp, ln -s
# Usage:         bash test/advanced_cli_tests.sh
# ===========================================================================
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/minideflate-tests.XXXXXX")"
LOG_DIR="$WORK_DIR/logs"
BIN="$WORK_DIR/deflate"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
START_EPOCH=""

# Last-command state — set by run_in_workdir / run_raw
LAST_STDOUT=""
LAST_STDERR=""
LAST_EXIT=0

# ========================= LIFECYCLE =======================================

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

epoch_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

# ========================= CORE FRAMEWORK ==================================

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

file_size() { wc -c < "$1" | tr -d '[:space:]'; }

# --- Run helpers -----------------------------------------------------------

# Run a command inside WORK_DIR, capture stdout/stderr/exit.
# Sets LAST_STDOUT, LAST_STDERR, LAST_EXIT.
run_in_workdir() {
    local label="$1"; shift
    LAST_STDOUT="$LOG_DIR/${label}.stdout"
    LAST_STDERR="$LOG_DIR/${label}.stderr"
    LAST_EXIT=0
    (cd "$WORK_DIR" && "$@") >"$LAST_STDOUT" 2>"$LAST_STDERR" || LAST_EXIT=$?
}

# Run without chdir (used for build step).
run_raw() {
    local label="$1"; shift
    LAST_STDOUT="$LOG_DIR/${label}.stdout"
    LAST_STDERR="$LOG_DIR/${label}.stderr"
    LAST_EXIT=0
    "$@" >"$LAST_STDOUT" 2>"$LAST_STDERR" || LAST_EXIT=$?
}

# --- Assertions ------------------------------------------------------------

assert_exit_ok() {
    [ "$LAST_EXIT" -eq 0 ] || {
        [ ! -s "$LAST_STDOUT" ] || cat "$LAST_STDOUT" >&2
        [ ! -s "$LAST_STDERR" ] || cat "$LAST_STDERR" >&2
        fail "expected exit 0, got $LAST_EXIT"
    }
}

assert_exit_fail() {
    [ "$LAST_EXIT" -ne 0 ] || fail "expected non-zero exit, got 0"
}

assert_exit_code() {
    [ "$LAST_EXIT" -eq "$1" ] || fail "expected exit $1, got $LAST_EXIT"
}

assert_stdout_contains() {
    grep -Fq -- "$1" "$LAST_STDOUT" || {
        printf 'expected stdout to contain: %s\n' "$1" >&2
        [ ! -s "$LAST_STDOUT" ] || { printf '%s\n' "=== stdout ===" >&2; cat "$LAST_STDOUT" >&2; }
        fail "stdout missing: $1"
    }
}

assert_stderr_contains() {
    grep -Fq -- "$1" "$LAST_STDERR" || {
        printf 'expected stderr to contain: %s\n' "$1" >&2
        [ ! -s "$LAST_STDERR" ] || { printf '%s\n' "=== stderr ===" >&2; cat "$LAST_STDERR" >&2; }
        fail "stderr missing: $1"
    }
}

assert_stdout_empty() {
    [ ! -s "$LAST_STDOUT" ] || fail "expected empty stdout, got $(file_size "$LAST_STDOUT") bytes"
}

assert_stderr_empty() {
    [ ! -s "$LAST_STDERR" ] || fail "expected empty stderr, got $(file_size "$LAST_STDERR") bytes"
}

assert_file_eq() {
    cmp -s "$1" "$2" || fail "files differ: $1 vs $2"
}

assert_dir_eq() {
    local diff_log="$LOG_DIR/dir_${RANDOM}.diff"
    if ! diff -qr "$1" "$2" >"$diff_log" 2>&1; then
        cat "$diff_log" >&2
        fail "directories differ: $1 vs $2"
    fi
}

assert_not_exists() {
    [ ! -e "$1" ] || fail "path should not exist: $1"
}

assert_smaller() {
    [ "$(file_size "$1")" -lt "$(file_size "$2")" ] || \
        fail "expected $(basename "$1") ($(file_size "$1")B) < $(basename "$2") ($(file_size "$2")B)"
}

assert_file_size() {
    local actual
    actual="$(file_size "$1")"
    [ "$actual" -eq "$2" ] || fail "expected $(basename "$1") size $2, got $actual"
}

assert_magic() {
    local actual
    actual="$(python3 - "$1" <<'PY'
import sys
from pathlib import Path

magic = int.from_bytes(Path(sys.argv[1]).read_bytes()[:4], "little")
names = {0x50524F5A: "PROZ", 0x50524F46: "PROF", 0x50524F53: "PROS"}
print(names.get(magic, f"0x{magic:08X}"))
PY
)"
    [ "$actual" = "$2" ] || fail "expected magic $2, got $actual in $(basename "$1")"
}

# ========================= BUILD ===========================================

build_binary() {
    mkdir -p "$LOG_DIR"
    run_raw build "${CC:-cc}" -O3 -std=c99 -Wall -Wextra -Werror \
        "$ROOT_DIR/deflate.c" -o "$BIN"
    assert_exit_ok
}

# ========================= DATA GENERATORS =================================

gen_mixed_payload() {
    python3 - "$1" <<'PY'
import sys
from pathlib import Path

data = bytearray()
alphabet = bytes((i * 37) & 0xFF for i in range(256))

for block in range(640):
    data.extend(f"frame-{block:04d}|".encode())
    data.extend(b"AlphaBetaGammaDelta" * 24)
    data.extend(alphabet)
    data.extend(b"\x00\xff\x10\x20pattern\x7f" * 8)
    twist = block % len(alphabet)
    data.extend(alphabet[twist:] + alphabet[:twist])
    if block % 9 == 0:
        data.extend(b"LONG-RUN-" * 96)

Path(sys.argv[1]).write_bytes(data)
PY
}

gen_zeros() {
    python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path

Path(sys.argv[1]).write_bytes(b"\x00" * int(sys.argv[2]))
PY
}

gen_random_seeded() {
    python3 - "$1" "$2" "$3" <<'PY'
import random, sys
from pathlib import Path

rng = random.Random(int(sys.argv[3]))
Path(sys.argv[1]).write_bytes(bytes(rng.randrange(256) for _ in range(int(sys.argv[2]))))
PY
}

gen_folder_fixture() {
    local dir="$1"
    mkdir -p "$dir/level1/level2"
    : > "$dir/empty.bin"

    python3 - "$dir/root.txt" <<'PY'
import sys
from pathlib import Path

Path(sys.argv[1]).write_text("root-text\n" * 128, encoding="utf-8")
PY

    python3 - "$dir/level1/file..txt" <<'PY'
import sys
from pathlib import Path

payload = bytearray()
for i in range(2048):
    payload.extend(f"safe-dotdot-{i:04d}\n".encode())
Path(sys.argv[1]).write_bytes(payload)
PY

    python3 - "$dir/level1/level2/space name.bin" <<'PY'
import sys
from pathlib import Path

Path(sys.argv[1]).write_bytes(bytes((i * 19 + 7) & 0xFF for i in range(8192)))
PY
}

gen_solid_fixture() {
    python3 - "$1" <<'PY'
import random, sys
from pathlib import Path

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
rng = random.Random(12345)
shared = bytes(rng.randrange(256) for _ in range(3072))

for idx in range(3):
    (root / f"chunk-{idx}.bin").write_bytes(shared)
PY
}

gen_crc_source() {
    python3 - "$1" <<'PY'
import sys
from pathlib import Path

Path(sys.argv[1]).write_bytes((b"crc-check-block-" * 4096) + bytes(range(256)) * 8)
PY
}

flip_last_byte() {
    python3 - "$1" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
d = bytearray(p.read_bytes())
d[-1] ^= 0x5A
p.write_bytes(d)
PY
}

# Patch the first path entry inside a PROF/PROS folder archive.
# The replacement MUST be the same byte-length as the original stored path.
patch_archive_path() {
    python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
rep = sys.argv[2].encode("utf-8")
d = bytearray(p.read_bytes())
stored_len = int.from_bytes(d[8:10], "little")

if len(rep) != stored_len:
    raise SystemExit(
        f"replacement length {len(rep)} != stored path length {stored_len} -- "
        f"source filename must be exactly {stored_len} chars"
    )

d[10:10 + stored_len] = rep
p.write_bytes(d)
PY
}

# ========================= CATEGORY A: CLI FLAGS ===========================

test_A01_version_flag() {
    run_in_workdir version "$BIN" --version
    assert_exit_ok
    assert_stdout_contains "MiniDeflate version 5.0.0"
    assert_stdout_contains "RFC 1951"
}

test_A02_help_flag() {
    run_in_workdir help "$BIN" --help
    assert_exit_ok
    assert_stdout_contains "Usage:"
    assert_stdout_contains "--compress"
    assert_stdout_contains "--decompress"
}

test_A03_no_args_shows_usage() {
    run_in_workdir noargs "$BIN"
    assert_exit_fail
    assert_stdout_contains "Usage:"
}

test_A04_conflicting_flags_rejected() {
    run_in_workdir conflict "$BIN" -c -d ./a ./b
    assert_exit_fail
    assert_stderr_contains "Cannot specify both -c and -d"
}

test_A05_unknown_option_rejected() {
    run_in_workdir unknown "$BIN" --bogus
    assert_exit_fail
    assert_stderr_contains "Unknown option"
}

test_A06_missing_paths_rejected() {
    run_in_workdir nopaths "$BIN" -c ./only_input
    assert_exit_fail
    assert_stderr_contains "Must specify input and output paths"
}

test_A07_too_many_args_rejected() {
    run_in_workdir toomany "$BIN" -c ./a ./b ./c
    assert_exit_fail
    assert_stderr_contains "Too many arguments"
}

# ========================= CATEGORY B: DATA ROUND-TRIPS ====================

test_B01_mixed_payload_roundtrip() {
    gen_mixed_payload "$WORK_DIR/mixed.bin"
    run_in_workdir mixed_c "$BIN" -c ./mixed.bin ./mixed.proz
    assert_exit_ok
    run_in_workdir mixed_d "$BIN" -d ./mixed.proz ./mixed.out
    assert_exit_ok

    assert_file_eq "$WORK_DIR/mixed.bin" "$WORK_DIR/mixed.out"
    assert_smaller "$WORK_DIR/mixed.proz" "$WORK_DIR/mixed.bin"
}

test_B02_single_byte_roundtrip() {
    printf 'Z' > "$WORK_DIR/onebyte.bin"
    run_in_workdir 1b_c "$BIN" -c ./onebyte.bin ./onebyte.proz
    assert_exit_ok
    run_in_workdir 1b_d "$BIN" -d ./onebyte.proz ./onebyte.out
    assert_exit_ok

    assert_file_eq "$WORK_DIR/onebyte.bin" "$WORK_DIR/onebyte.out"
    assert_file_size "$WORK_DIR/onebyte.out" 1
}

test_B03_all_zeros_extreme_compression() {
    gen_zeros "$WORK_DIR/zeros.bin" 524288
    run_in_workdir zeros_c "$BIN" -c ./zeros.bin ./zeros.proz
    assert_exit_ok
    run_in_workdir zeros_d "$BIN" -d ./zeros.proz ./zeros.out
    assert_exit_ok

    assert_file_eq "$WORK_DIR/zeros.bin" "$WORK_DIR/zeros.out"
    assert_file_size "$WORK_DIR/zeros.out" 524288
    # 512KB of zeros should compress to well under 4KB
    local sz
    sz="$(file_size "$WORK_DIR/zeros.proz")"
    [ "$sz" -lt 4096 ] || fail "zeros compressed to ${sz}B, expected < 4096"
}

test_B04_incompressible_data_roundtrip() {
    gen_random_seeded "$WORK_DIR/random.bin" 65536 42
    run_in_workdir rand_c "$BIN" -c ./random.bin ./random.proz
    assert_exit_ok
    run_in_workdir rand_d "$BIN" -d ./random.proz ./random.out
    assert_exit_ok

    assert_file_eq "$WORK_DIR/random.bin" "$WORK_DIR/random.out"
    # Incompressible data may expand slightly — that's correct behaviour
}

test_B07_empty_file_roundtrip() {
    : > "$WORK_DIR/empty.bin"
    run_in_workdir empty_c "$BIN" -c ./empty.bin ./empty.proz
    assert_exit_ok
    run_in_workdir empty_d "$BIN" -d ./empty.proz ./empty.out
    assert_exit_ok

    assert_file_eq "$WORK_DIR/empty.bin" "$WORK_DIR/empty.out"
    assert_file_size "$WORK_DIR/empty.out" 0
}

test_B08_folder_with_empty_files() {
    mkdir -p "$WORK_DIR/mixed-empty/sub"
    : > "$WORK_DIR/mixed-empty/empty.bin"
    printf 'has-content\n' > "$WORK_DIR/mixed-empty/sub/data.txt"
    run_in_workdir mixedempty_c "$BIN" -c ./mixed-empty ./mixed-empty.proz
    assert_exit_ok
    run_in_workdir mixedempty_d "$BIN" -d ./mixed-empty.proz ./mixed-empty-out
    assert_exit_ok

    assert_file_eq "$WORK_DIR/mixed-empty/sub/data.txt" "$WORK_DIR/mixed-empty-out/sub/data.txt"
}

test_B09_large_multiblock() {
    gen_random_seeded "$WORK_DIR/large.bin" 2097152 99
    run_in_workdir large_c "$BIN" -c ./large.bin ./large.proz
    assert_exit_ok
    run_in_workdir large_d "$BIN" -d ./large.proz ./large.out
    assert_exit_ok

    assert_file_eq "$WORK_DIR/large.bin" "$WORK_DIR/large.out"
}

test_B05_folder_roundtrip_nested_paths() {
    gen_folder_fixture "$WORK_DIR/folder-src"
    run_in_workdir folder_c "$BIN" -c ./folder-src ./folder.proz
    assert_exit_ok
    run_in_workdir folder_d "$BIN" -d ./folder.proz ./folder-out
    assert_exit_ok

    assert_dir_eq "$WORK_DIR/folder-src" "$WORK_DIR/folder-out"
}

test_B06_solid_mode_cross_file_reuse() {
    gen_solid_fixture "$WORK_DIR/solid-src"
    run_in_workdir solid_n "$BIN" -c    ./solid-src ./normal.proz
    assert_exit_ok
    run_in_workdir solid_s "$BIN" -c -s ./solid-src ./solid.proz
    assert_exit_ok
    run_in_workdir solid_d "$BIN" -d    ./solid.proz ./solid-out
    assert_exit_ok

    assert_dir_eq "$WORK_DIR/solid-src" "$WORK_DIR/solid-out"
    assert_smaller "$WORK_DIR/solid.proz" "$WORK_DIR/normal.proz"
    assert_magic   "$WORK_DIR/solid.proz" "PROS"
}

# ========================= CATEGORY C: FORMAT VALIDATION ===================

test_C01_single_file_magic_proz() {
    printf 'magic-test\n' > "$WORK_DIR/m.txt"
    run_in_workdir mag_c "$BIN" -c ./m.txt ./m.proz
    assert_exit_ok
    assert_magic "$WORK_DIR/m.proz" "PROZ"
}

test_C02_folder_archive_magic_prof() {
    mkdir -p "$WORK_DIR/mag-dir"
    printf 'inside\n' > "$WORK_DIR/mag-dir/f.txt"
    run_in_workdir mag_f "$BIN" -c ./mag-dir ./mag-dir.proz
    assert_exit_ok
    assert_magic "$WORK_DIR/mag-dir.proz" "PROF"
}

test_C03_bad_magic_rejected() {
    printf 'NOT_AN_ARCHIVE' > "$WORK_DIR/bad.proz"
    run_in_workdir badmag "$BIN" -d ./bad.proz ./bad.out
    assert_exit_fail
    assert_stderr_contains "Unknown archive format"
}

test_C04_truncated_archive_rejected() {
    printf 'trunc-data\n' > "$WORK_DIR/trunc-src.txt"
    run_in_workdir trunc_c "$BIN" -c ./trunc-src.txt ./trunc-full.proz
    assert_exit_ok

    # Keep only the first 10 bytes (magic + partial block header)
    python3 -c "
from pathlib import Path
Path('$WORK_DIR/trunc.proz').write_bytes(Path('$WORK_DIR/trunc-full.proz').read_bytes()[:10])
"
    run_in_workdir trunc_d "$BIN" -d ./trunc.proz ./trunc.out
    assert_exit_fail
}

test_C05_nonexistent_input_rejected() {
    run_in_workdir nofile_c "$BIN" -c ./does_not_exist.txt ./out.proz
    assert_exit_fail
    assert_stderr_contains "Error opening input"

    run_in_workdir nofile_d "$BIN" -d ./does_not_exist.proz ./out.bin
    assert_exit_fail
    assert_stderr_contains "Error opening input"
}

# ========================= CATEGORY D: SECURITY ============================

test_D01_crc_corruption_detected() {
    gen_crc_source "$WORK_DIR/crc.bin"
    run_in_workdir crc_c "$BIN" -c ./crc.bin ./crc.proz
    assert_exit_ok

    cp "$WORK_DIR/crc.proz" "$WORK_DIR/crc-bad.proz"
    flip_last_byte "$WORK_DIR/crc-bad.proz"

    run_in_workdir crc_d "$BIN" -d ./crc-bad.proz ./crc.out
    assert_exit_fail
    assert_stderr_contains "CRC Mismatch"
}

test_D02_path_traversal_rejected() {
    # Source filename "plainabc" is 8 chars — same length as "../ab.cd"
    mkdir -p "$WORK_DIR/trav-src"
    printf 'payload\n' > "$WORK_DIR/trav-src/plainabc"
    run_in_workdir trav_c "$BIN" -c ./trav-src ./trav.proz
    assert_exit_ok

    patch_archive_path "$WORK_DIR/trav.proz" "../ab.cd"

    run_in_workdir trav_d "$BIN" -d ./trav.proz ./trav-out
    assert_exit_fail
    assert_stderr_contains "Unsafe path in archive"
    assert_not_exists "$WORK_DIR/ab.cd"
}

test_D03_intermediate_symlink_blocked() {
    mkdir -p "$WORK_DIR/sym-src/nested"
    mkdir -p "$WORK_DIR/sym-escape"
    printf 'secret\n' > "$WORK_DIR/sym-src/nested/payload.txt"
    run_in_workdir sym_c "$BIN" -c ./sym-src ./sym.proz
    assert_exit_ok

    # Plant a symlink at the intermediate directory in the output tree
    mkdir -p "$WORK_DIR/sym-out"
    ln -s "$WORK_DIR/sym-escape" "$WORK_DIR/sym-out/nested"

    run_in_workdir sym_d "$BIN" -d ./sym.proz ./sym-out
    assert_exit_fail
    assert_stderr_contains "symlink in path"
    assert_not_exists "$WORK_DIR/sym-escape/payload.txt"
}

test_D04_output_symlink_rejected() {
    printf 'benign\n' > "$WORK_DIR/sym-in.txt"
    printf 'SENTINEL\n' > "$WORK_DIR/sym-real.proz"
    ln -s "$WORK_DIR/sym-real.proz" "$WORK_DIR/sym-link.proz"

    run_in_workdir sym_out "$BIN" -c ./sym-in.txt ./sym-link.proz
    assert_exit_fail
    assert_stderr_contains "Output path is a symlink"

    # Verify the symlink target was not overwritten
    grep -Fq "SENTINEL" "$WORK_DIR/sym-real.proz" || \
        fail "symlink target was overwritten"
}

# ========================= CATEGORY E: OUTPUT MODES ========================

test_E01_verbose_shows_details() {
    printf 'verbose-data\n' > "$WORK_DIR/verb.txt"
    run_in_workdir verb_c "$BIN" -v -c ./verb.txt ./verb.proz
    assert_exit_ok
    assert_stdout_contains "CRC32:"

    run_in_workdir verb_d "$BIN" -v -d ./verb.proz ./verb.out
    assert_exit_ok
    assert_stdout_contains "Computed CRC:"
    assert_stdout_contains "Integrity Verified"
}

test_E02_quiet_suppresses_output() {
    printf 'quiet-data\n' > "$WORK_DIR/quiet.txt"
    run_in_workdir quiet_c "$BIN" -q -c ./quiet.txt ./quiet.proz
    assert_exit_ok
    assert_stdout_empty
    assert_stderr_empty

    run_in_workdir quiet_d "$BIN" -q -d ./quiet.proz ./quiet.out
    assert_exit_ok
    assert_stdout_empty
    assert_stderr_empty

    assert_file_eq "$WORK_DIR/quiet.txt" "$WORK_DIR/quiet.out"
}

# ========================= TEST RUNNER =====================================

run_test() {
    local name="$1"
    local t_start t_end elapsed
    t_start="$(epoch_ms)"

    if "$name"; then
        t_end="$(epoch_ms)"
        elapsed=$(( t_end - t_start ))
        printf '  PASS  %-45s  %4d ms\n' "$name" "$elapsed"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        t_end="$(epoch_ms)"
        elapsed=$(( t_end - t_start ))
        printf '  FAIL  %-45s  %4d ms\n' "$name" "$elapsed" >&2
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

main() {
    require_cmd python3
    require_cmd diff
    require_cmd cmp
    require_cmd ln

    printf 'MiniDeflate Advanced Test Suite\n'
    printf '================================\n'
    printf 'Work directory: %s\n\n' "$WORK_DIR"

    START_EPOCH="$(epoch_ms)"
    build_binary
    printf 'Binary built OK (%s)\n\n' "$BIN"

    # --- Category A: CLI flags ---
    printf '\n%s\n' '--- Category A: CLI Argument Parsing ---'
    run_test test_A01_version_flag
    run_test test_A02_help_flag
    run_test test_A03_no_args_shows_usage
    run_test test_A04_conflicting_flags_rejected
    run_test test_A05_unknown_option_rejected
    run_test test_A06_missing_paths_rejected
    run_test test_A07_too_many_args_rejected

    # --- Category B: Data round-trips ---
    printf '\n%s\n' '--- Category B: Data Integrity Round-Trips ---'
    run_test test_B01_mixed_payload_roundtrip
    run_test test_B02_single_byte_roundtrip
    run_test test_B03_all_zeros_extreme_compression
    run_test test_B04_incompressible_data_roundtrip
    run_test test_B05_folder_roundtrip_nested_paths
    run_test test_B06_solid_mode_cross_file_reuse
    run_test test_B07_empty_file_roundtrip
    run_test test_B08_folder_with_empty_files
    run_test test_B09_large_multiblock

    # --- Category C: Format validation ---
    printf '\n%s\n' '--- Category C: Archive Format Validation ---'
    run_test test_C01_single_file_magic_proz
    run_test test_C02_folder_archive_magic_prof
    run_test test_C03_bad_magic_rejected
    run_test test_C04_truncated_archive_rejected
    run_test test_C05_nonexistent_input_rejected

    # --- Category D: Security ---
    printf '\n%s\n' '--- Category D: Security Hardening ---'
    run_test test_D01_crc_corruption_detected
    run_test test_D02_path_traversal_rejected
    run_test test_D03_intermediate_symlink_blocked
    run_test test_D04_output_symlink_rejected

    # --- Category E: Output modes ---
    printf '\n%s\n' '--- Category E: Output Mode Behaviour ---'
    run_test test_E01_verbose_shows_details
    run_test test_E02_quiet_suppresses_output

    # --- Summary ---
    local end_epoch total_ms
    end_epoch="$(epoch_ms)"
    total_ms=$(( end_epoch - START_EPOCH ))

    local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
    printf '\n================================\n'
    printf 'Results: %d passed, %d failed, %d skipped  (%d ms)\n' \
        "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT" "$total_ms"

    if [ "$FAIL_COUNT" -gt 0 ]; then
        printf 'SUITE FAILED\n'
        exit 1
    fi

    printf 'ALL %d TESTS PASSED\n' "$total"
}

main "$@"
