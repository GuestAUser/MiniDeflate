#!/usr/bin/env bash
# ===========================================================================
# MiniDeflate v5.0 — Advanced Integration Test Suite
#
# Builds deflate.c in a disposable temp directory and exercises the binary
# through 43 test cases covering:
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

patch_archive_file_size() {
    python3 - "$1" "$2" "$3" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
target_path = sys.argv[2]
new_size = int(sys.argv[3])
d = bytearray(p.read_bytes())
file_count = int.from_bytes(d[4:8], "little")
off = 8

for _ in range(file_count):
    path_len = int.from_bytes(d[off:off + 2], "little")
    off += 2
    entry_path = d[off:off + path_len].decode("utf-8")
    off += path_len
    if entry_path == target_path:
        d[off:off + 8] = new_size.to_bytes(8, "little")
        p.write_bytes(d)
        raise SystemExit(0)
    off += 8

raise SystemExit(f"archive entry not found: {target_path}")
PY
}

patch_archive_path_by_index() {
    python3 - "$1" "$2" "$3" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
target_index = int(sys.argv[2])
rep = sys.argv[3].encode('utf-8')
d = bytearray(p.read_bytes())
file_count = int.from_bytes(d[4:8], 'little')
off = 8

if target_index < 0 or target_index >= file_count:
    raise SystemExit(f'entry index out of range: {target_index}')

for idx in range(file_count):
    path_len = int.from_bytes(d[off:off + 2], 'little')
    off += 2
    if idx == target_index:
        if len(rep) != path_len:
            raise SystemExit(
                f'replacement length {len(rep)} != stored path length {path_len}'
            )
        d[off:off + path_len] = rep
        p.write_bytes(d)
        raise SystemExit(0)
    off += path_len + 8

raise SystemExit(f'entry index not found: {target_index}')
PY
}

generate_rsa_signature_fixture() {
    python3 - "$1" "$2" "$3" "$4" <<'PY'
import base64
import hashlib
import random
import sys
from pathlib import Path

archive_path = Path(sys.argv[1])
pubkey_path = Path(sys.argv[2])
sig_path = Path(sys.argv[3])
wrong_pubkey_path = Path(sys.argv[4])

rng = random.Random(0xC0FFEE)
PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')
E = 65537

def is_probable_prime(n):
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(16):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        n = rng.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if is_probable_prime(n) and (n - 1) % E != 0:
            return n

def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def der_int(x):
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return b'\x02' + der_len(len(b)) + b

def der_seq(*parts):
    body = b''.join(parts)
    return b'\x30' + der_len(len(body)) + body

def der_bit_string(data):
    body = b'\x00' + data
    return b'\x03' + der_len(len(body)) + body

def pem_wrap(label, der):
    b64 = base64.b64encode(der).decode('ascii')
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + '\n'.join(lines) + f"\n-----END {label}-----\n"

def gen_keypair():
    p = gen_prime(512)
    q = gen_prime(512)
    while p == q:
        q = gen_prime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)
    return n, d

def write_pubkey(path, n):
    rsa_pub = der_seq(der_int(n), der_int(E))
    alg = der_seq(
        b'\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01',
        b'\x05\x00',
    )
    spki = der_seq(alg, der_bit_string(rsa_pub))
    path.write_text(pem_wrap('PUBLIC KEY', spki), encoding='ascii')

n, d = gen_keypair()
write_pubkey(pubkey_path, n)

wrong_n, _ = gen_keypair()
write_pubkey(wrong_pubkey_path, wrong_n)

archive = archive_path.read_bytes()
digest = hashlib.sha256(archive).digest()
k = (n.bit_length() + 7) // 8
em = b'\x00\x01' + b'\xFF' * (k - len(PREFIX) - len(digest) - 3) + b'\x00' + PREFIX + digest
sig = pow(int.from_bytes(em, 'big'), d, n).to_bytes(k, 'big')
sig_path.write_bytes(sig)
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

test_A08_verify_requires_sig_and_pubkey() {
    printf 'archive\n' > "$WORK_DIR/a08.txt"
    run_in_workdir a08_c "$BIN" -c ./a08.txt ./a08.proz
    assert_exit_ok

    run_in_workdir a08 "$BIN" --verify ./a08.proz
    assert_exit_fail
    assert_stderr_contains "--verify requires --sig and --pubkey"
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

test_B10_folder_all_empty_files() {
    mkdir -p "$WORK_DIR/all-empty/sub"
    : > "$WORK_DIR/all-empty/a.bin"
    : > "$WORK_DIR/all-empty/sub/b.bin"
    : > "$WORK_DIR/all-empty/sub/c.bin"

    run_in_workdir allempty_c "$BIN" -c ./all-empty ./all-empty.proz
    assert_exit_ok
    run_in_workdir allempty_d "$BIN" -d ./all-empty.proz ./all-empty-out
    assert_exit_ok

    assert_dir_eq "$WORK_DIR/all-empty" "$WORK_DIR/all-empty-out"
    assert_file_size "$WORK_DIR/all-empty-out/a.bin" 0
    assert_file_size "$WORK_DIR/all-empty-out/sub/b.bin" 0
    assert_file_size "$WORK_DIR/all-empty-out/sub/c.bin" 0
}

test_B11_absolute_file_paths_roundtrip() {
    printf 'absolute-path-roundtrip\n' > "$WORK_DIR/abs.txt"

    run_raw abs_c "$BIN" -c "$WORK_DIR/abs.txt" "$WORK_DIR/abs.proz"
    assert_exit_ok
    run_raw abs_d "$BIN" -d "$WORK_DIR/abs.proz" "$WORK_DIR/abs.out"
    assert_exit_ok

    assert_file_eq "$WORK_DIR/abs.txt" "$WORK_DIR/abs.out"
}

test_B12_absolute_folder_paths_roundtrip() {
    gen_folder_fixture "$WORK_DIR/abs-folder-src"

    run_raw absfolder_c "$BIN" -c "$WORK_DIR/abs-folder-src" "$WORK_DIR/abs-folder.proz"
    assert_exit_ok
    run_raw absfolder_d "$BIN" -d "$WORK_DIR/abs-folder.proz" "$WORK_DIR/abs-folder-out"
    assert_exit_ok

    assert_dir_eq "$WORK_DIR/abs-folder-src" "$WORK_DIR/abs-folder-out"
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

test_C06_folder_declared_size_too_large_rejected() {
    mkdir -p "$WORK_DIR/sizeplus-src"
    python3 - "$WORK_DIR/sizeplus-src/payload.txt" <<'PY'
import sys
from pathlib import Path

Path(sys.argv[1]).write_bytes(bytes((i * 17 + 3) & 0xFF for i in range(65536)))
PY

    run_in_workdir sizeplus_c "$BIN" -c ./sizeplus-src ./sizeplus.proz
    assert_exit_ok

    patch_archive_file_size "$WORK_DIR/sizeplus.proz" "payload.txt" 65540

    run_in_workdir sizeplus_d "$BIN" -d ./sizeplus.proz ./sizeplus-out
    assert_exit_fail
    assert_stderr_contains "Folder payload size mismatch"
    assert_not_exists "$WORK_DIR/sizeplus-out"
}

test_C07_folder_declared_size_too_small_rejected() {
    mkdir -p "$WORK_DIR/sizeminus-src"
    printf 'payload-data\n' > "$WORK_DIR/sizeminus-src/payload.txt"

    run_in_workdir sizeminus_c "$BIN" -c ./sizeminus-src ./sizeminus.proz
    assert_exit_ok

    patch_archive_file_size "$WORK_DIR/sizeminus.proz" "payload.txt" 4

    run_in_workdir sizeminus_d "$BIN" -d ./sizeminus.proz ./sizeminus-out
    assert_exit_fail
    assert_stderr_contains "declared file sizes"
    assert_not_exists "$WORK_DIR/sizeminus-out"
}

test_C08_trailing_data_after_footer_rejected() {
    printf 'trailing-data\n' > "$WORK_DIR/trailer-src.txt"
    run_in_workdir trailer_c "$BIN" -c ./trailer-src.txt ./trailer.proz
    assert_exit_ok

    python3 - "$WORK_DIR/trailer.proz" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
with p.open('ab') as f:
    f.write(b'TRAIL')
PY

    run_in_workdir trailer_d "$BIN" -d ./trailer.proz ./trailer.out
    assert_exit_fail
    assert_stderr_contains "Trailing data after CRC footer"
    assert_not_exists "$WORK_DIR/trailer.out"
}

test_C09_duplicate_archive_paths_rejected() {
    mkdir -p "$WORK_DIR/dup-src"
    printf 'alpha\n' > "$WORK_DIR/dup-src/filea.txt"
    printf 'beta\n' > "$WORK_DIR/dup-src/fileb.txt"

    run_in_workdir dup_c "$BIN" -c ./dup-src ./dup.proz
    assert_exit_ok

    python3 - "$WORK_DIR/dup.proz" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
d = bytearray(p.read_bytes())
file_count = int.from_bytes(d[4:8], 'little')
if file_count < 2:
    raise SystemExit('need at least two entries for duplicate-path test')

off = 8
path_len0 = int.from_bytes(d[off:off + 2], 'little')
off += 2
path0 = d[off:off + path_len0]
off += path_len0 + 8

path_len1 = int.from_bytes(d[off:off + 2], 'little')
off += 2
if path_len1 != path_len0:
    raise SystemExit('stored path lengths differ; duplicate-path test fixture invalid')
d[off:off + path_len1] = path0
p.write_bytes(d)
PY

    run_in_workdir dup_d "$BIN" -d ./dup.proz ./dup-out
    assert_exit_fail
    assert_stderr_contains "duplicate output paths"
    assert_not_exists "$WORK_DIR/dup-out"
}

test_C10_missing_eob_huffman_rejected() {
    python3 - "$WORK_DIR/noeob.proz" <<'PY'
import sys
from pathlib import Path

MAGIC = (0x50524F5A).to_bytes(4, 'little')
max_sym = 65
depths = [0] * (max_sym + 1)
depths[64] = 1
depths[65] = 1  # complete tree, but still no EOB symbol 256

bits = []

def put_bits(value, count):
    for i in range(count - 1, -1, -1):
        bits.append((value >> i) & 1)

put_bits(1, 1)          # last block
put_bits(max_sym, 16)
for i in range(0, max_sym + 1, 2):
    put_bits(depths[i], 4)
    put_bits(depths[i + 1] if i + 1 <= max_sym else 0, 4)

payload = bytearray()
for i in range(0, len(bits), 8):
    byte = 0
    for bit in bits[i:i + 8]:
        byte = (byte << 1) | bit
    byte <<= (8 - len(bits[i:i + 8]))
    payload.append(byte)

Path(sys.argv[1]).write_bytes(MAGIC + payload + (0).to_bytes(4, 'little'))
PY

    run_in_workdir noeob_d "$BIN" -d ./noeob.proz ./noeob.out
    assert_exit_fail
    assert_stderr_contains "Invalid canonical Huffman table"
    assert_not_exists "$WORK_DIR/noeob.out"
}

test_C11_mutation_fuzz_no_crash() {
    printf 'mutation-fuzz-seed\n' > "$WORK_DIR/fuzz.txt"
    run_in_workdir fuzzseed_c "$BIN" -c ./fuzz.txt ./fuzz.proz
    assert_exit_ok

    python3 - "$BIN" "$WORK_DIR/fuzz.proz" "$WORK_DIR" <<'PY'
import random
import subprocess
import sys
from pathlib import Path

bin_path = Path(sys.argv[1])
seed_archive = Path(sys.argv[2]).read_bytes()
work = Path(sys.argv[3])
rng = random.Random(123456)

for i in range(100):
    data = bytearray(seed_archive)
    flips = rng.randint(1, min(8, len(data)))
    for _ in range(flips):
        idx = rng.randrange(len(data))
        data[idx] ^= rng.randrange(1, 256)

    arc = work / f'mut-{i:03d}.proz'
    out = work / f'mut-{i:03d}.out'
    arc.write_bytes(data)
    try:
        cp = subprocess.run([str(bin_path), '-d', str(arc), str(out)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=1.0)
    except subprocess.TimeoutExpired:
        raise SystemExit(f'timeout on mutation {i}')

    if cp.returncode < 0:
        raise SystemExit(f'process terminated by signal {-cp.returncode} on mutation {i}')
PY
}

test_C12_signature_verify_success() {
    printf 'signed archive\n' > "$WORK_DIR/signed.txt"
    run_in_workdir sigok_c "$BIN" -c ./signed.txt ./signed.proz
    assert_exit_ok

    generate_rsa_signature_fixture \
        "$WORK_DIR/signed.proz" \
        "$WORK_DIR/public.pem" \
        "$WORK_DIR/signed.sig" \
        "$WORK_DIR/wrong-public.pem"

    run_in_workdir sigok_v "$BIN" --verify --sig ./signed.sig --pubkey ./public.pem ./signed.proz
    assert_exit_ok
    assert_stdout_contains "Signature Verified"
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
    assert_not_exists "$WORK_DIR/crc.out"
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

test_D03_output_root_symlink_blocked() {
    mkdir -p "$WORK_DIR/rootsym-src"
    mkdir -p "$WORK_DIR/rootsym-real"
    printf 'secret\n' > "$WORK_DIR/rootsym-src/payload.txt"
    ln -s "$WORK_DIR/rootsym-real" "$WORK_DIR/rootsym-link"

    run_in_workdir rootsym_c "$BIN" -c ./rootsym-src ./rootsym.proz
    assert_exit_ok

    run_in_workdir rootsym_d "$BIN" -d ./rootsym.proz ./rootsym-link
    assert_exit_fail
    assert_stderr_contains "Output directory is a symlink"
    assert_not_exists "$WORK_DIR/rootsym-real/payload.txt"
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

test_D05_existing_output_directory_without_conflicts_allowed() {
    mkdir -p "$WORK_DIR/nonempty-src"
    mkdir -p "$WORK_DIR/nonempty-out"
    printf 'payload\n' > "$WORK_DIR/nonempty-src/file.txt"
    printf 'keep\n' > "$WORK_DIR/nonempty-out/existing.txt"

    run_in_workdir nonempty_c "$BIN" -c ./nonempty-src ./nonempty.proz
    assert_exit_ok

    run_in_workdir nonempty_d "$BIN" -d ./nonempty.proz ./nonempty-out
    assert_exit_ok
    assert_file_size "$WORK_DIR/nonempty-out/existing.txt" 5
    assert_file_eq "$WORK_DIR/nonempty-src/file.txt" "$WORK_DIR/nonempty-out/file.txt"
}

test_D06_folder_crc_corruption_leaves_no_outputs() {
    mkdir -p "$WORK_DIR/foldercrc-src/sub"
    printf 'alpha\n' > "$WORK_DIR/foldercrc-src/a.txt"
    printf 'beta\n' > "$WORK_DIR/foldercrc-src/sub/b.txt"

    run_in_workdir foldercrc_c "$BIN" -c ./foldercrc-src ./foldercrc.proz
    assert_exit_ok

    cp "$WORK_DIR/foldercrc.proz" "$WORK_DIR/foldercrc-bad.proz"
    flip_last_byte "$WORK_DIR/foldercrc-bad.proz"

    run_in_workdir foldercrc_d "$BIN" -d ./foldercrc-bad.proz ./foldercrc-out
    assert_exit_fail
    assert_stderr_contains "CRC Mismatch"
    assert_not_exists "$WORK_DIR/foldercrc-out"
}

test_D07_existing_output_directory_conflict_rejected() {
    mkdir -p "$WORK_DIR/conflict-src"
    mkdir -p "$WORK_DIR/conflict-out"
    printf 'archive\n' > "$WORK_DIR/conflict-src/file.txt"
    printf 'preexisting\n' > "$WORK_DIR/conflict-out/file.txt"

    run_in_workdir conflict_c "$BIN" -c ./conflict-src ./conflict.proz
    assert_exit_ok

    run_in_workdir conflict_d "$BIN" -d ./conflict.proz ./conflict-out
    assert_exit_fail
    assert_stderr_contains "Error finalizing output directory"
    assert_file_size "$WORK_DIR/conflict-out/file.txt" 12
}

test_D08_signed_decompress_tampered_archive_rejected() {
    printf 'signed payload\n' > "$WORK_DIR/signed-src.txt"
    run_in_workdir signed_c "$BIN" -c ./signed-src.txt ./signed-archive.proz
    assert_exit_ok

    generate_rsa_signature_fixture \
        "$WORK_DIR/signed-archive.proz" \
        "$WORK_DIR/signed-public.pem" \
        "$WORK_DIR/signed-archive.sig" \
        "$WORK_DIR/signed-wrong-public.pem"

    flip_last_byte "$WORK_DIR/signed-archive.proz"

    run_in_workdir signed_d "$BIN" -d --sig ./signed-archive.sig --pubkey ./signed-public.pem ./signed-archive.proz ./signed.out
    assert_exit_fail
    assert_stderr_contains "Signature verification failed"
    assert_not_exists "$WORK_DIR/signed.out"
}

test_D09_signature_wrong_key_rejected() {
    printf 'signed payload\n' > "$WORK_DIR/wrongkey-src.txt"
    run_in_workdir wrongkey_c "$BIN" -c ./wrongkey-src.txt ./wrongkey.proz
    assert_exit_ok

    generate_rsa_signature_fixture \
        "$WORK_DIR/wrongkey.proz" \
        "$WORK_DIR/wrongkey-public.pem" \
        "$WORK_DIR/wrongkey.sig" \
        "$WORK_DIR/wrongkey-other.pem"

    run_in_workdir wrongkey_v "$BIN" --verify --sig ./wrongkey.sig --pubkey ./wrongkey-other.pem ./wrongkey.proz
    assert_exit_fail
    assert_stderr_contains "Signature verification failed"
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
    run_test test_A08_verify_requires_sig_and_pubkey

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
    run_test test_B10_folder_all_empty_files
    run_test test_B11_absolute_file_paths_roundtrip
    run_test test_B12_absolute_folder_paths_roundtrip

    # --- Category C: Format validation ---
    printf '\n%s\n' '--- Category C: Archive Format Validation ---'
    run_test test_C01_single_file_magic_proz
    run_test test_C02_folder_archive_magic_prof
    run_test test_C03_bad_magic_rejected
    run_test test_C04_truncated_archive_rejected
    run_test test_C05_nonexistent_input_rejected
    run_test test_C06_folder_declared_size_too_large_rejected
    run_test test_C07_folder_declared_size_too_small_rejected
    run_test test_C08_trailing_data_after_footer_rejected
    run_test test_C09_duplicate_archive_paths_rejected
    run_test test_C10_missing_eob_huffman_rejected
    run_test test_C11_mutation_fuzz_no_crash
    run_test test_C12_signature_verify_success

    # --- Category D: Security ---
    printf '\n%s\n' '--- Category D: Security Hardening ---'
    run_test test_D01_crc_corruption_detected
    run_test test_D02_path_traversal_rejected
    run_test test_D03_output_root_symlink_blocked
    run_test test_D04_output_symlink_rejected
    run_test test_D05_existing_output_directory_without_conflicts_allowed
    run_test test_D06_folder_crc_corruption_leaves_no_outputs
    run_test test_D07_existing_output_directory_conflict_rejected
    run_test test_D08_signed_decompress_tampered_archive_rejected
    run_test test_D09_signature_wrong_key_rejected

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
