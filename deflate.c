/**
 * MiniDeflate v6.0.0 - Production-Grade DEFLATE-Style Compressor
 *
 * A secure, high-performance hybrid compressor using LZSS + Canonical Huffman.
 * Implements RFC 1951 distance coding for improved compression ratios.
 *
 * Build: gcc -O3 -std=c99 -Wall -Wextra -Werror deflate.c -o deflate
 *        gcc -O3 -std=c99 -Wall -Wextra -DDEBUG deflate.c -o deflate_debug
 *
 * Creator: GuestAUser(Lk10)
 *
 * POSIX feature test macros - must be defined before any includes.
 * Required for lstat(), opendir(), readdir() visibility in strict C99 mode.
 */
#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#endif

/*
 * ============================================================================
 * SECURITY HARDENING (27 fixes):
 * ----------------------------------------------------------------------------
 * 1. Window bookkeeping: replaced ambiguous 'len' with 'bytes_in_window'
 * 2. Heap API: heap_push() returns bool; callers check for overflow
 * 3. Memory cleanup: centralized via goto cleanup labels; no double-free
 * 4. Bit I/O: documented MSB-first ordering; bs_flush handles partial bytes
 * 5. Bounds safety: hash4() guarded for MIN_MATCH bytes; window access clamped
 * 6. bs_read_bits: all callers pass non-NULL error pointer
 * 7. File size: replaced ftell(long) with uint64_t counter; portable checks
 * 8. is_safe_archive_path: allows "./" prefix while rejecting ".."
 * 9. DEBUG asserts: compile-time diagnostics under #ifdef DEBUG
 * 10. Huffman cleanup: free_tree called on all error paths; no leaks
 * 11. CRC footer: fail-closed on truncated files; incomplete CRC is fatal
 * 12. is_safe_archive_path: use 'check' consistently; reject ':' in path components
 * 13. bs_write: mode_write assertion to catch misuse in debug builds
 * 14. bytes_out: accurate tracking via BitStream counter
 * 15. heap_destroy: frees remaining HuffmanNode pointers (no leak on error)
 * 16. decode_symbol_fast: save/restore bytes_in_buf for buffer refill edge
 * 17. TOCTOU/Symlink: secure_fopen_write() refuses to follow symlinks
 * 18. Ghost buffer: bits_in_ram check + assertion prevents I/O during peek
 * ============================================================================
 * VERSION 4.0.0 ENHANCEMENTS:
 * - 4-byte hash with golden ratio multiplication for better distribution
 * - RFC 1951 distance coding (30 codes + extra bits) - improved compression
 * - Fast-path short chain search (8 entries) before full 128-entry search
 * - Adaptive block sizing (early flush on long matches or poor quality)
 * - Solid compression mode (-s/--solid) for folder archives
 * - Professional CLI with -q (quiet), -v (verbose), --version flags
 * - ~2.5% better compression ratio vs v3.0
 * ============================================================================
 * VERSION 5.0.0 ENHANCEMENTS:
 * - Increased limits: 25GB input, 50GB output (was 1GB/10GB)
 * - CRC32 slice-by-4 optimization (~3-4x faster integrity checking)
 * - 64KB I/O buffers (was 16KB) + getc_unlocked on POSIX
 * - Buffered decompression output (WriteBuf replaces per-byte fputc)
 * - O_NOFOLLOW atomic symlink rejection (closes TOCTOU gap) [FIX #19]
 * - Embedded null byte detection in archive paths [FIX #20]
 * - Huffman tree oversubscription validation [FIX #21]
 * - Filelist capacity overflow protection
 * - memset-based hash chain reset (replaces 32K-iteration loops)
 * - openat-based extraction rejects symlinks at all path levels [FIX #22]
 * - Component-wise ".." validation (allows "file..txt") [FIX #23]
 * - lstat() in traverse_directory prevents symlink following [FIX #24]
 * ============================================================================
 * VERSION 6.0.0 ENHANCEMENTS:
 * - Split parse-stage hash insertion from full match search on multi-byte advances
 * - Constant-time distance-code lookup for the active 4KiB window
 * - Allocation-free per-block Huffman build including heap metadata
 * - Inline block frequency accumulation removes encode_block() token rescans
 * - Canonical decode arrays replace O(n*t_count) slow-path with O(code_length)
 * - O(n^2) prefix validation gated behind DEBUG (Kraft check remains always-on)
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>
#include <stdarg.h>

/* Version info */
#define MINIDEFLATE_VERSION "6.0.0"
#define MINIDEFLATE_NAME "MiniDeflate"

/* FIX #17: Platform-specific includes for secure file operations */
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#define PLATFORM_WINDOWS 1
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#define PLATFORM_WINDOWS 0
#endif

#ifdef DEBUG
#include <assert.h>
#define DBG_ASSERT(x) assert(x)
#define DBG_PRINTF(...) fprintf(stderr, "[DEBUG] " __VA_ARGS__)
#else
#define DBG_ASSERT(x) ((void)0)
#define DBG_PRINTF(...) ((void)0)
#endif

/* v5.0: Lock-free stdio on POSIX — avoids per-byte mutex overhead */
#if !PLATFORM_WINDOWS && defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 1)
#define FAST_GETC(fp) getc_unlocked(fp)
#else
#define FAST_GETC(fp) fgetc(fp)
#endif

/* ==================== CONFIGURATION ==================== */

#define WINDOW_SIZE           4096
#define WINDOW_MASK           (WINDOW_SIZE - 1)
#define MAX_MATCH             258
#define MIN_MATCH             3
#define BLOCK_SIZE            32768
#define SYMBOL_COUNT          513
#define IO_BUFFER_SIZE        65536

#define HASH_BITS             15
#define HASH_SIZE             (1 << HASH_BITS)
#define HASH_MASK             (HASH_SIZE - 1)
#define MAX_CHAIN_LENGTH      128
#define FAST_CHAIN_LENGTH     8

#define FAST_DECODE_BITS      12
#define FAST_DECODE_SIZE      (1 << FAST_DECODE_BITS)

#define SIG_MAGIC             0x50524F5A  /* 'PROZ' - single file */
#define SIG_MAGIC_FOLDER      0x50524F46  /* 'PROF' - folder archive */
#define SIG_MAGIC_SOLID       0x50524F53  /* 'PROS' - solid folder archive */

#define MAX_PATH_LEN          512
#define MAX_FILES_IN_ARCHIVE  65535

/* FIX #7: Use uint64_t constants for portable 32/64-bit comparisons */
#define MAX_INPUT_SIZE        ((uint64_t)25 * 1024 * 1024 * 1024)
#define MAX_OUTPUT_SIZE       ((uint64_t)50 * 1024 * 1024 * 1024)
#define MAX_HUFFMAN_DEPTH     15
#define MAX_BLOCKS            4000000
#define RSA_MAX_BITS          4096
#define RSA_MAX_WORDS         (RSA_MAX_BITS / 32)

/* Adaptive block thresholds */
#define ADAPTIVE_MIN_TOKENS   16384
#define ADAPTIVE_LONG_MATCH   200
#define ADAPTIVE_POOR_MATCH   4
#define LAZY_MATCH_MAX_LEN    32

/* Distance coding: 30 codes per RFC 1951 */
#define NUM_DIST_CODES        30

typedef enum {
    DEFLATE_OK = 0,
    DEFLATE_ERR_IO = -1,
    DEFLATE_ERR_MEM = -2,
    DEFLATE_ERR_FORMAT = -3,
    DEFLATE_ERR_CORRUPT = -4,
    DEFLATE_ERR_LIMIT = -5,
    DEFLATE_ERR_PATH = -6,
    DEFLATE_ERR_AUTH = -7
} DeflateError;

/* Verbosity levels */
typedef enum {
    LOG_QUIET = 0,
    LOG_NORMAL = 1,
    LOG_VERBOSE = 2
} LogLevel;

static LogLevel g_log_level = LOG_NORMAL;
static bool g_solid_mode = false;

#if PLATFORM_WINDOWS
#define FDOPEN _fdopen
#else
#define FDOPEN fdopen
#endif

/* ==================== LOGGING SYSTEM ==================== */

static void log_msg(LogLevel level, const char *fmt, ...) {
    if (level > g_log_level) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

static void log_err(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

#define LOG_NORMAL_MSG(...) log_msg(LOG_NORMAL, __VA_ARGS__)
#define LOG_VERBOSE_MSG(...) log_msg(LOG_VERBOSE, __VA_ARGS__)
#define LOG_ERR(...) log_err(__VA_ARGS__)

/* ==================== DISTANCE CODE TABLES (RFC 1951) ==================== */

/* Distance code base values */
static const uint16_t dist_base[NUM_DIST_CODES] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25,
    33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};

/* Extra bits for each distance code */
static const uint8_t dist_extra_bits[NUM_DIST_CODES] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

typedef struct {
    uint8_t code;
    uint8_t extra_bits;
    uint16_t extra;
} DistCodeInfo;

static DistCodeInfo g_dist_lookup[WINDOW_SIZE + 1];
static bool g_dist_lookup_ready = false;

/* Convert distance to code + extra bits */
static void dist_to_code(uint16_t dist, uint8_t *code_out, uint16_t *extra_out, uint8_t *extra_bits_out) {
    if (dist == 0) {
        *code_out = 0;
        *extra_out = 0;
        *extra_bits_out = 0;
        return;
    }
    int lo = 0, hi = NUM_DIST_CODES - 1;
    while (lo < hi) {
        int mid = (lo + hi + 1) / 2;
        if (dist_base[mid] <= dist) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    *code_out = (uint8_t)lo;
    *extra_out = dist - dist_base[lo];
    *extra_bits_out = dist_extra_bits[lo];
}

static void init_dist_lookup(void) {
    if (g_dist_lookup_ready) return;

    for (uint16_t dist = 1; dist <= WINDOW_SIZE; dist++) {
        dist_to_code(dist,
                     &g_dist_lookup[dist].code,
                     &g_dist_lookup[dist].extra,
                     &g_dist_lookup[dist].extra_bits);
    }

    g_dist_lookup_ready = true;
}

static inline void dist_to_code_cached(uint16_t dist,
                                       uint8_t *code_out,
                                       uint16_t *extra_out,
                                       uint8_t *extra_bits_out) {
    if (dist > 0 && dist <= WINDOW_SIZE && g_dist_lookup_ready) {
        const DistCodeInfo *info = &g_dist_lookup[dist];
        *code_out = info->code;
        *extra_out = info->extra;
        *extra_bits_out = info->extra_bits;
        return;
    }

    dist_to_code(dist, code_out, extra_out, extra_bits_out);
}

/* Convert code + extra bits to distance */
static uint16_t code_to_dist(uint8_t code, uint16_t extra) {
    if (code >= NUM_DIST_CODES) return 0;
    uint32_t dist = (uint32_t)dist_base[code] + (uint32_t)extra;
    if (dist > UINT16_MAX) return 0;
    return (uint16_t)dist;
}

/* ==================== DATA STRUCTURES ==================== */

typedef struct {
    uint16_t type;       /* 0 = literal, 1 = match */
    uint16_t val;        /* literal byte or length code (257+) */
    uint8_t dist_code;   /* distance code (0-29) */
    uint8_t dist_extra_bits; /* extra bits count */
    uint16_t dist_extra; /* extra bits value */
} Token;

typedef struct HuffmanNode {
    int32_t sym;
    uint64_t freq;
    struct HuffmanNode *left, *right;
} HuffmanNode;

typedef struct {
    HuffmanNode pool[SYMBOL_COUNT * 2];
    int32_t next;
} HuffmanArena;

static void arena_init(HuffmanArena *a) { a->next = 0; }

static HuffmanNode* arena_alloc(HuffmanArena *a) {
    if (a->next >= SYMBOL_COUNT * 2) return NULL;
    HuffmanNode *n = &a->pool[a->next++];
    n->sym = -1; n->freq = 0; n->left = n->right = NULL;
    return n;
}

typedef struct {
    HuffmanNode **nodes;
    int32_t size;
    int32_t capacity;
} MinHeap;

typedef struct {
    uint16_t sym;
    uint8_t len;
    uint16_t code;
} CanonicalEntry;

typedef struct {
    uint16_t symbol;
    uint8_t bits_used;
} FastDecodeEntry;

typedef struct {
    uint32_t words[RSA_MAX_WORDS];
    size_t nwords;
} BigUint;

typedef struct {
    BigUint modulus;
    uint32_t exponent;
    size_t modulus_len;
} RsaPublicKey;

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_len;
} SHA256Ctx;

/**
 * BitStream - Buffered bit I/O with MSB-first ordering.
 *
 * Write mode: bits accumulate in bit_acc from LSB, flushed MSB-first.
 * Read mode: bits consumed from MSB of each byte.
 *
 * FIX #14: Added bytes_written counter for accurate output size tracking.
 */
typedef struct {
    FILE *fp;
    uint8_t buffer[IO_BUFFER_SIZE];
    size_t pos;
    size_t bytes_in_buf;
    uint64_t bit_acc;
    int32_t bit_count;
    bool mode_write;
    uint64_t bytes_written;  /* FIX #14: Track actual bytes written */
} BitStream;

typedef struct {
    uint16_t head[HASH_SIZE];
    uint16_t prev[WINDOW_SIZE];
} HashChain;

typedef struct { uint32_t tab[4][256]; } CRC32Tables;

/* v5.0: Buffered output for decompression — replaces per-byte fputc */
typedef struct {
    FILE *fp;
    uint8_t buf[IO_BUFFER_SIZE];
    size_t pos;
    bool error;
} WriteBuf;

static void wbuf_init(WriteBuf *wb, FILE *fp) {
    wb->fp = fp;
    wb->pos = 0;
    wb->error = false;
}

static void wbuf_put(WriteBuf *wb, uint8_t byte) {
    if (wb->error) return;
    wb->buf[wb->pos++] = byte;
    if (wb->pos >= IO_BUFFER_SIZE) {
        if (fwrite(wb->buf, 1, IO_BUFFER_SIZE, wb->fp) != IO_BUFFER_SIZE)
            wb->error = true;
        wb->pos = 0;
    }
}

static bool wbuf_flush(WriteBuf *wb) {
    if (wb->pos > 0) {
        if (fwrite(wb->buf, 1, wb->pos, wb->fp) != wb->pos)
            wb->error = true;
        wb->pos = 0;
    }
    return !wb->error;
}

typedef struct {
    CRC32Tables crc_tables;
    uint8_t window[WINDOW_SIZE * 2];  /* Doubled for safe lookahead */
    HashChain hash_chain;
    Token *token_buf;
    uint8_t *decomp_window;
    FastDecodeEntry *decode_table;
    /* v6.0: Canonical decode arrays for O(code_length) slow-path lookup.
     * Rebuilt per block alongside the fast decode table. */
    int32_t decode_bl_count[MAX_HUFFMAN_DEPTH + 2];
    uint64_t decode_first_code[MAX_HUFFMAN_DEPTH + 2];
    int32_t decode_sym_offset[MAX_HUFFMAN_DEPTH + 2];
    uint16_t decode_sorted_syms[SYMBOL_COUNT];
    int32_t decode_max_len;
    uint64_t bytes_in;   /* FIX #7: uint64_t for portable size tracking */
    uint64_t bytes_out;
} DeflateContext;

/* ==================== FOLDER ARCHIVE STRUCTURES ==================== */

typedef struct {
    char path[MAX_PATH_LEN];    /* Relative path with forward slashes */
    uint64_t size;              /* Original file size */
} FileEntry;

typedef struct {
    FileEntry *entries;
    uint32_t count;
    uint32_t capacity;
} FileList;

typedef struct {
    char **items;
    uint32_t count;
    uint32_t capacity;
} NameList;

/* ==================== MACROS ==================== */

#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); ptr = NULL; } } while(0)

/* Forward declarations removed: free_tree and heap_destroy eliminated by arena allocator */
static bool is_valid_host_path(const char *path);

/* ==================== SECURE FILE I/O ==================== */

/**
 * FIX #17: Secure file open that refuses to follow symlinks (TOCTOU mitigation).
 *
 * THREAT: Attacker creates symlink in shared directory pointing to sensitive file.
 *         Tool follows symlink and overwrites/truncates the target.
 *
 * MITIGATION:
 *   - Unix: Use lstat() to detect symlinks before opening
 *   - Windows: Check for reparse points (NTFS symlinks/junctions)
 *
 * Returns NULL if path is a symlink or on error.
 */
static FILE* secure_fopen_write(const char *path, bool *is_symlink) {
    *is_symlink = false;

#if PLATFORM_WINDOWS
    DWORD attrs = GetFileAttributesA(path);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
            *is_symlink = true;
            return NULL;
        }
    }
    return fopen(path, "wb");

#else
    /* v5.0 FIX #19: Use O_NOFOLLOW to atomically reject symlinks (closes TOCTOU gap) */
#ifdef O_NOFOLLOW
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        if (errno == ELOOP) {
            *is_symlink = true;
        }
        return NULL;
    }
    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        return NULL;
    }
    return fp;
#else
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            *is_symlink = true;
            return NULL;
        }
    }
    return fopen(path, "wb");
#endif
#endif
}

/*
 * FIX #22: openat-based secure extraction — rejects symlinks at ANY path level.
 * On POSIX, walks each component of rel_path under out_dir using openat(O_NOFOLLOW)
 * and creates intermediate directories with mkdirat(). A planted symlink at ANY
 * level (not just the leaf) triggers ELOOP and immediate rejection.
 * On Windows, falls back to best-effort reparse point checks (TOCTOU remains).
 */
#if PLATFORM_WINDOWS
static FILE* secure_extract_open(const char *out_dir, const char *rel_path, bool *is_symlink) {
    *is_symlink = false;
    char full_path[MAX_PATH_LEN * 2];
    snprintf(full_path, sizeof(full_path), "%s/%s", out_dir, rel_path);
    normalize_path(full_path);

    char *last_slash = strrchr(full_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        create_directory_recursive(full_path);
        *last_slash = '/';
    }
    return secure_fopen_write(full_path, is_symlink);
}
#else
static FILE* secure_extract_open(const char *out_dir, const char *rel_path, bool *is_symlink) {
    *is_symlink = false;

    int dir_fd = open(out_dir, O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) return NULL;

    char path_copy[MAX_PATH_LEN];
    strncpy(path_copy, rel_path, MAX_PATH_LEN - 1);
    path_copy[MAX_PATH_LEN - 1] = '\0';
    for (char *p = path_copy; *p; p++) {
        if (*p == '\\') *p = '/';
    }

    char *start = path_copy;
    char *slash;
    while ((slash = strchr(start, '/')) != NULL) {
        *slash = '\0';
        if (start[0] != '\0') {
            (void)mkdirat(dir_fd, start, 0755);
            int new_fd = openat(dir_fd, start, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            close(dir_fd);
            if (new_fd < 0) {
                if (errno == ELOOP || errno == ENOTDIR) *is_symlink = true;
                return NULL;
            }
            dir_fd = new_fd;
        }
        start = slash + 1;
    }

    if (start[0] == '\0') {
        close(dir_fd);
        return NULL;
    }

    int file_fd = openat(dir_fd, start, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    close(dir_fd);
    if (file_fd < 0) {
        if (errno == ELOOP || errno == ENOTDIR) *is_symlink = true;
        return NULL;
    }

    FILE *fp = fdopen(file_fd, "wb");
    if (!fp) {
        close(file_fd);
        return NULL;
    }
    return fp;
}
#endif

/**
 * Check if path is a directory.
 */
static bool is_directory(const char *path) {
#if PLATFORM_WINDOWS
    DWORD attrs = GetFileAttributesA(path);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    return false;
#else
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return false;
#endif
}

/**
 * Secure read-only open (less critical but consistent API).
 */
static FILE* secure_fopen_read(const char *path) {
    return fopen(path, "rb");
}

/* ==================== DIRECTORY TRAVERSAL ==================== */

static FileList* filelist_create(void) {
    FileList *fl = malloc(sizeof(FileList));
    if (!fl) return NULL;
    fl->capacity = 64;
    fl->count = 0;
    fl->entries = malloc(sizeof(FileEntry) * fl->capacity);
    if (!fl->entries) {
        free(fl);
        return NULL;
    }
    return fl;
}

static void filelist_destroy(FileList *fl) {
    if (fl) {
        free(fl->entries);
        free(fl);
    }
}

static void namelist_destroy(NameList *nl) {
    if (!nl) return;
    for (uint32_t i = 0; i < nl->count; i++) {
        free(nl->items[i]);
    }
    free(nl->items);
    nl->items = NULL;
    nl->count = 0;
    nl->capacity = 0;
}

static bool namelist_add(NameList *nl, const char *name) {
    if (!nl || !name) return false;

    if (nl->count >= nl->capacity) {
        uint32_t new_cap = (nl->capacity == 0) ? 16 : (nl->capacity * 2);
        char **new_items = realloc(nl->items, sizeof(char*) * new_cap);
        if (!new_items) return false;
        nl->items = new_items;
        nl->capacity = new_cap;
    }

    size_t len = strlen(name);
    char *copy = malloc(len + 1);
    if (!copy) return false;
    memcpy(copy, name, len + 1);
    nl->items[nl->count++] = copy;
    return true;
}

static bool filelist_add(FileList *fl, const char *path, uint64_t size) {
    if (fl->count >= MAX_FILES_IN_ARCHIVE) return false;
    size_t path_len = strlen(path);
    if (path_len >= MAX_PATH_LEN) return false;

    if (fl->count >= fl->capacity) {
        if (fl->capacity > UINT32_MAX / 2) return false;
        uint32_t new_cap = fl->capacity * 2;
        if (new_cap > MAX_FILES_IN_ARCHIVE) new_cap = MAX_FILES_IN_ARCHIVE;
        FileEntry *new_entries = realloc(fl->entries, sizeof(FileEntry) * new_cap);
        if (!new_entries) return false;
        fl->entries = new_entries;
        fl->capacity = new_cap;
    }

    memcpy(fl->entries[fl->count].path, path, path_len + 1);
    fl->entries[fl->count].size = size;
    fl->count++;
    return true;
}

#if PLATFORM_WINDOWS
static unsigned char ascii_tolower_uc(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + ('a' - 'A')) : c;
}

static unsigned char ascii_toupper_uc(unsigned char c) {
    return (c >= 'a' && c <= 'z') ? (unsigned char)(c - ('a' - 'A')) : c;
}
#endif

static int archive_path_key_compare(const char *a, const char *b) {
#if PLATFORM_WINDOWS
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        ca = ascii_tolower_uc(ca);
        cb = ascii_tolower_uc(cb);
        if (ca != cb) return (ca < cb) ? -1 : 1;
        a++;
        b++;
    }
    if (*a == *b) return 0;
    return (*a == '\0') ? -1 : 1;
#else
    return strcmp(a, b);
#endif
}

static int archive_path_ptr_compare(const void *lhs, const void *rhs) {
    const char *const *a = lhs;
    const char *const *b = rhs;
    return archive_path_key_compare(*a, *b);
}

static DeflateError ensure_unique_archive_paths(const FileList *fl) {
    if (!fl || fl->count < 2) return DEFLATE_OK;

    char **paths = malloc(sizeof(char*) * fl->count);
    if (!paths) return DEFLATE_ERR_MEM;

    for (uint32_t i = 0; i < fl->count; i++) {
        paths[i] = fl->entries[i].path;
    }

    qsort(paths, fl->count, sizeof(char*), archive_path_ptr_compare);

    DeflateError result = DEFLATE_OK;
    for (uint32_t i = 1; i < fl->count; i++) {
        if (archive_path_key_compare(paths[i - 1], paths[i]) == 0) {
            result = DEFLATE_ERR_PATH;
            break;
        }
    }

    free(paths);
    return result;
}

/* Normalize path separators to forward slashes */
static void normalize_path(char *path) {
    for (char *p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
}

static bool path_exists(const char *path) {
#if PLATFORM_WINDOWS
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#else
    struct stat st;
    return lstat(path, &st) == 0;
#endif
}

static bool path_is_symlink(const char *path) {
#if PLATFORM_WINDOWS
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    struct stat st;
    return lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
#endif
}

static bool path_is_directory_nofollow(const char *path) {
#if PLATFORM_WINDOWS
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES &&
           (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
#else
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static bool remove_path_if_exists(const char *path) {
#if PLATFORM_WINDOWS
    return DeleteFileA(path) != 0 || GetLastError() == ERROR_FILE_NOT_FOUND;
#else
    return unlink(path) == 0 || errno == ENOENT;
#endif
}

static bool rename_path_atomic(const char *src, const char *dst, bool replace_existing) {
#if PLATFORM_WINDOWS
    DWORD flags = replace_existing ? MOVEFILE_REPLACE_EXISTING : 0;
    return MoveFileExA(src, dst, flags) != 0;
#else
    if (!replace_existing && path_exists(dst)) return false;
    return rename(src, dst) == 0;
#endif
}

static bool remove_empty_directory(const char *path) {
#if PLATFORM_WINDOWS
    return RemoveDirectoryA(path) != 0;
#else
    return rmdir(path) == 0;
#endif
}

static uint32_t temp_nonce(void) {
    static uint32_t counter = 0;
    counter++;
#if PLATFORM_WINDOWS
    return (uint32_t)GetCurrentProcessId() ^ (uint32_t)GetTickCount() ^ (counter * 2654435761U);
#else
    return (uint32_t)getpid() ^ (uint32_t)time(NULL) ^ (counter * 2654435761U);
#endif
}

static bool alloc_temp_sibling_path(const char *target, const char *tag,
                                    uint32_t nonce, char **out_path) {
    size_t len = strlen(target) + strlen(tag) + 32;
    char *path = malloc(len);
    if (!path) return false;

    int written = snprintf(path, len, "%s.%s.%08X", target, tag, (unsigned)nonce);
    if (written < 0 || (size_t)written >= len) {
        free(path);
        return false;
    }

    *out_path = path;
    return true;
}

static FILE* open_unique_temp_file_sibling(const char *target, char **temp_path_out) {
    for (int attempt = 0; attempt < 128; attempt++) {
        char *candidate = NULL;
        if (!alloc_temp_sibling_path(target, "minideflate-tmp",
                                     temp_nonce() ^ (uint32_t)attempt, &candidate)) {
            return NULL;
        }

#if PLATFORM_WINDOWS
        HANDLE h = CreateFileA(candidate, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            free(candidate);
            if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) continue;
            return NULL;
        }

        int fd = _open_osfhandle((intptr_t)h, _O_WRONLY | _O_BINARY);
        if (fd < 0) {
            CloseHandle(h);
            remove_path_if_exists(candidate);
            free(candidate);
            return NULL;
        }
#else
        int fd = open(candidate, O_WRONLY | O_CREAT | O_EXCL
#ifdef O_NOFOLLOW
                      | O_NOFOLLOW
#endif
                      , 0644);
        if (fd < 0) {
            int saved_errno = errno;
            free(candidate);
            if (saved_errno == EEXIST) continue;
            errno = saved_errno;
            return NULL;
        }
#endif

        FILE *fp = FDOPEN(fd, "wb");
        if (!fp) {
#if PLATFORM_WINDOWS
            _close(fd);
#else
            close(fd);
#endif
            remove_path_if_exists(candidate);
            free(candidate);
            return NULL;
        }

        *temp_path_out = candidate;
        return fp;
    }

    return NULL;
}

static bool create_unique_temp_sibling_directory(const char *target, char **temp_path_out) {
    for (int attempt = 0; attempt < 128; attempt++) {
        char *candidate = NULL;
        if (!alloc_temp_sibling_path(target, "minideflate-stage",
                                     temp_nonce() ^ (uint32_t)attempt, &candidate)) {
            return false;
        }

#if PLATFORM_WINDOWS
        if (CreateDirectoryA(candidate, NULL)) {
            *temp_path_out = candidate;
            return true;
        }
        DWORD err = GetLastError();
        free(candidate);
        if (err == ERROR_ALREADY_EXISTS) continue;
        return false;
#else
        if (mkdir(candidate, 0700) == 0) {
            *temp_path_out = candidate;
            return true;
        }
        int saved_errno = errno;
        free(candidate);
        if (saved_errno == EEXIST) continue;
        errno = saved_errno;
        return false;
#endif
    }

    return false;
}

static bool remove_tree_recursive(const char *path) {
#if PLATFORM_WINDOWS
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) return GetLastError() == ERROR_FILE_NOT_FOUND;
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return DeleteFileA(path) != 0;
    }

    size_t search_len = strlen(path) + 4;
    char *search = malloc(search_len);
    if (!search) return false;
    snprintf(search, search_len, "%s/*", path);
    for (char *p = search; *p; p++) {
        if (*p == '/') *p = '\\';
    }

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search, &ffd);
    free(search);
    if (hFind == INVALID_HANDLE_VALUE) return false;

    bool ok = true;
    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;

        size_t child_len = strlen(path) + strlen(ffd.cFileName) + 2;
        char *child = malloc(child_len);
        if (!child) {
            ok = false;
            break;
        }
        snprintf(child, child_len, "%s/%s", path, ffd.cFileName);

        if (!remove_tree_recursive(child)) ok = false;
        free(child);
        if (!ok) break;
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
    return ok && RemoveDirectoryA(path) != 0;
#else
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT;
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        return unlink(path) == 0 || errno == ENOENT;
    }

    DIR *dir = opendir(path);
    if (!dir) return false;

    bool ok = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        size_t child_len = strlen(path) + strlen(entry->d_name) + 2;
        char *child = malloc(child_len);
        if (!child) {
            ok = false;
            break;
        }
        snprintf(child, child_len, "%s/%s", path, entry->d_name);

        if (!remove_tree_recursive(child)) ok = false;
        free(child);
        if (!ok) break;
    }

    closedir(dir);
    if (!ok) return false;
    return rmdir(path) == 0;
#endif
}

static bool create_directory_recursive(const char *path);
static bool ensure_parent_directories(const char *path);

static bool list_top_level_directory_entries(const char *dir_path, NameList *names) {
#if PLATFORM_WINDOWS
    size_t search_len = strlen(dir_path) + 4;
    char *search = malloc(search_len);
    if (!search) return false;
    snprintf(search, search_len, "%s/*", dir_path);
    for (char *p = search; *p; p++) {
        if (*p == '/') *p = '\\';
    }

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search, &ffd);
    free(search);
    if (hFind == INVALID_HANDLE_VALUE) return false;

    bool ok = true;
    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
        if (!namelist_add(names, ffd.cFileName)) {
            ok = false;
            break;
        }
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
    return ok;
#else
    DIR *dir = opendir(dir_path);
    if (!dir) return false;

    bool ok = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (!namelist_add(names, entry->d_name)) {
            ok = false;
            break;
        }
    }

    closedir(dir);
    return ok;
#endif
}

static bool commit_staged_children(const char *stage_dir, const char *out_dir) {
    NameList names = {0};
    NameList moved = {0};
    bool ok = list_top_level_directory_entries(stage_dir, &names);
    if (!ok) {
        namelist_destroy(&names);
        return false;
    }

    for (uint32_t i = 0; i < names.count; i++) {
        size_t dst_len = strlen(out_dir) + strlen(names.items[i]) + 2;
        char *dst = malloc(dst_len);
        if (!dst) {
            ok = false;
            break;
        }
        snprintf(dst, dst_len, "%s/%s", out_dir, names.items[i]);
        normalize_path(dst);

        if (path_exists(dst)) {
            free(dst);
            ok = false;
            break;
        }
        free(dst);
    }

    for (uint32_t i = 0; ok && i < names.count; i++) {
        size_t src_len = strlen(stage_dir) + strlen(names.items[i]) + 2;
        size_t dst_len = strlen(out_dir) + strlen(names.items[i]) + 2;
        char *src = malloc(src_len);
        char *dst = malloc(dst_len);
        if (!src || !dst) {
            free(src);
            free(dst);
            ok = false;
            break;
        }

        snprintf(src, src_len, "%s/%s", stage_dir, names.items[i]);
        snprintf(dst, dst_len, "%s/%s", out_dir, names.items[i]);
        normalize_path(src);
        normalize_path(dst);

        if (!rename_path_atomic(src, dst, false) || !namelist_add(&moved, names.items[i])) {
            free(src);
            free(dst);
            ok = false;
            break;
        }

        free(src);
        free(dst);
    }

    if (!ok) {
        for (uint32_t i = moved.count; i > 0; i--) {
            size_t src_len = strlen(out_dir) + strlen(moved.items[i - 1]) + 2;
            size_t dst_len = strlen(stage_dir) + strlen(moved.items[i - 1]) + 2;
            char *src = malloc(src_len);
            char *dst = malloc(dst_len);
            if (!src || !dst) {
                free(src);
                free(dst);
                break;
            }

            snprintf(src, src_len, "%s/%s", out_dir, moved.items[i - 1]);
            snprintf(dst, dst_len, "%s/%s", stage_dir, moved.items[i - 1]);
            normalize_path(src);
            normalize_path(dst);
            (void)rename_path_atomic(src, dst, false);
            free(src);
            free(dst);
        }
    }

    namelist_destroy(&moved);
    namelist_destroy(&names);
    return ok && remove_empty_directory(stage_dir);
}

static DeflateError prepare_output_stage_directory(const char *out_dir,
                                                   char **stage_dir_out,
                                                   bool *output_dir_exists) {
    *stage_dir_out = NULL;
    *output_dir_exists = false;

    if (path_is_symlink(out_dir)) {
        LOG_ERR("Error: Output directory is a symlink (security risk)\n");
        return DEFLATE_ERR_PATH;
    }

    if (path_exists(out_dir)) {
        if (!path_is_directory_nofollow(out_dir)) {
            LOG_ERR("Error: Output path exists and is not a directory\n");
            return DEFLATE_ERR_PATH;
        }
        *output_dir_exists = true;
    }

    if (!ensure_parent_directories(out_dir)) {
        LOG_ERR("Error: Cannot create parent directories for output\n");
        return DEFLATE_ERR_IO;
    }

    if (!create_unique_temp_sibling_directory(out_dir, stage_dir_out)) {
        perror("Error creating staging directory");
        return DEFLATE_ERR_IO;
    }

    return DEFLATE_OK;
}

static bool commit_output_stage_directory(const char *stage_dir, const char *out_dir,
                                          bool output_dir_exists) {
    if (path_is_symlink(out_dir)) return false;

    if (!output_dir_exists) {
        return rename_path_atomic(stage_dir, out_dir, false);
    }

    if (!path_is_directory_nofollow(out_dir)) return false;
    return commit_staged_children(stage_dir, out_dir);
}

static bool bs_has_trailing_data(BitStream *bs) {
    if (bs->bit_count != 0) return true;
    if (bs->pos < bs->bytes_in_buf) return true;

    uint8_t byte;
    size_t n = fread(&byte, 1, 1, bs->fp);
    return n != 0 || ferror(bs->fp);
}

/* Create directory (and parents if needed) */
static bool create_directory_recursive(const char *path) {
    size_t len = strlen(path);
    char *tmp = malloc(len + 1);
    if (!tmp) return false;
    memcpy(tmp, path, len + 1);

    if (len == 0) {
        free(tmp);
        return true;
    }

    /* Remove trailing slash */
    if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') {
        tmp[len - 1] = '\0';
    }
    if (tmp[0] == '\0') {
        free(tmp);
        return true;
    }

    /* Create each directory in path */
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
#if PLATFORM_WINDOWS
            CreateDirectoryA(tmp, NULL);
#else
            mkdir(tmp, 0755);
#endif
            *p = '/';
        }
    }

#if PLATFORM_WINDOWS
    bool ok = CreateDirectoryA(tmp, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    bool ok = mkdir(tmp, 0755) == 0 || errno == EEXIST;
#endif

    free(tmp);
    return ok;
}

static bool ensure_parent_directories(const char *path) {
    const char *slash1 = strrchr(path, '/');
    const char *slash2 = strrchr(path, '\\');
    const char *slash = slash1;
    if (!slash || (slash2 && slash2 > slash)) slash = slash2;
    if (!slash) return true;

    size_t parent_len = (size_t)(slash - path);
    if (parent_len == 0) return true;
    if (parent_len == 2 && path[1] == ':') return true;

    char *parent = malloc(parent_len + 1);
    if (!parent) return false;
    memcpy(parent, path, parent_len);
    parent[parent_len] = '\0';

    bool ok = create_directory_recursive(parent);
    free(parent);
    return ok;
}

static DeflateError copy_snapshot_bytes(FILE *snapshot_fp, const uint8_t *buf, size_t n,
                                        uint64_t *copied_bytes, uint64_t *total_bytes) {
    if (n == 0) return DEFLATE_OK;
    if (*total_bytes > MAX_INPUT_SIZE - (uint64_t)n) {
        LOG_ERR("Error: Total input exceeds %llu byte limit\n",
                (unsigned long long)MAX_INPUT_SIZE);
        return DEFLATE_ERR_LIMIT;
    }
    if (fwrite(buf, 1, n, snapshot_fp) != n) {
        return DEFLATE_ERR_IO;
    }
    *copied_bytes += (uint64_t)n;
    *total_bytes += (uint64_t)n;
    return DEFLATE_OK;
}

#if PLATFORM_WINDOWS
static DeflateError snapshot_file_windows(const char *full_path, FILE *snapshot_fp,
                                          uint64_t *copied_bytes, uint64_t *total_bytes) {
    HANDLE h = CreateFileA(full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return DEFLATE_ERR_IO;
    }

    uint8_t buf[IO_BUFFER_SIZE];
    DWORD got = 0;
    DeflateError result = DEFLATE_OK;
    while (ReadFile(h, buf, (DWORD)sizeof(buf), &got, NULL) && got > 0) {
        result = copy_snapshot_bytes(snapshot_fp, buf, (size_t)got, copied_bytes, total_bytes);
        if (result != DEFLATE_OK) break;
    }

    if (result == DEFLATE_OK && GetLastError() != ERROR_SUCCESS && got == 0) {
        result = DEFLATE_ERR_IO;
    }

    CloseHandle(h);
    return result;
}

static DeflateError snapshot_directory_windows(const char *base_path, const char *rel_path,
                                               FileList *fl, FILE *snapshot_fp,
                                               uint64_t *total_bytes) {
    char search_path[MAX_PATH_LEN * 2 + 4];
    char full_path[MAX_PATH_LEN * 2 + 2];
    char new_rel[MAX_PATH_LEN];
    WIN32_FIND_DATAA ffd;
    HANDLE hFind;

    if (rel_path[0]) {
        int written = snprintf(search_path, sizeof(search_path), "%s/%s/*", base_path, rel_path);
        if (written < 0 || (size_t)written >= sizeof(search_path)) return DEFLATE_ERR_PATH;
    } else {
        int written = snprintf(search_path, sizeof(search_path), "%s/*", base_path);
        if (written < 0 || (size_t)written >= sizeof(search_path)) return DEFLATE_ERR_PATH;
    }
    normalize_path(search_path);

    {
        char win_search[MAX_PATH_LEN * 2 + 4];
        strncpy(win_search, search_path, sizeof(win_search) - 1);
        win_search[sizeof(win_search) - 1] = '\0';
        for (char *p = win_search; *p; p++) {
            if (*p == '/') *p = '\\';
        }
        hFind = FindFirstFileA(win_search, &ffd);
    }
    if (hFind == INVALID_HANDLE_VALUE) return DEFLATE_ERR_IO;

    DeflateError result = DEFLATE_OK;
    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        if (rel_path[0]) {
            int written = snprintf(new_rel, sizeof(new_rel), "%s/%s", rel_path, ffd.cFileName);
            if (written < 0 || (size_t)written >= sizeof(new_rel)) {
                result = DEFLATE_ERR_PATH;
                break;
            }
        } else {
            int written = snprintf(new_rel, sizeof(new_rel), "%s", ffd.cFileName);
            if (written < 0 || (size_t)written >= sizeof(new_rel)) {
                result = DEFLATE_ERR_PATH;
                break;
            }
        }
        normalize_path(new_rel);

        {
            int written = snprintf(full_path, sizeof(full_path), "%s/%s", base_path, new_rel);
            if (written < 0 || (size_t)written >= sizeof(full_path)) {
                result = DEFLATE_ERR_PATH;
                break;
            }
        }
        normalize_path(full_path);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            result = snapshot_directory_windows(base_path, new_rel, fl, snapshot_fp, total_bytes);
            if (result != DEFLATE_OK) break;
        } else {
            uint64_t copied = 0;
            result = snapshot_file_windows(full_path, snapshot_fp, &copied, total_bytes);
            if (result != DEFLATE_OK) break;
            if (!filelist_add(fl, new_rel, copied)) {
                result = DEFLATE_ERR_LIMIT;
                break;
            }
        }
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
    return result;
}
#else
static DeflateError snapshot_file_posix(int fd, FILE *snapshot_fp,
                                        uint64_t *copied_bytes, uint64_t *total_bytes) {
    uint8_t buf[IO_BUFFER_SIZE];
    DeflateError result = DEFLATE_OK;

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) return DEFLATE_ERR_IO;
        result = copy_snapshot_bytes(snapshot_fp, buf, (size_t)n, copied_bytes, total_bytes);
        if (result != DEFLATE_OK) break;
    }

    return result;
}

static DeflateError snapshot_directory_posix(int dir_fd, const char *rel_path,
                                             FileList *fl, FILE *snapshot_fp,
                                             uint64_t *total_bytes) {
    int enum_fd = dup(dir_fd);
    if (enum_fd < 0) return DEFLATE_ERR_IO;

    DIR *dir = fdopendir(enum_fd);
    if (!dir) {
        close(enum_fd);
        return DEFLATE_ERR_IO;
    }

    struct dirent *entry;
    DeflateError result = DEFLATE_OK;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char new_rel[MAX_PATH_LEN];
        if (rel_path[0]) {
            int written = snprintf(new_rel, sizeof(new_rel), "%s/%s", rel_path, entry->d_name);
            if (written < 0 || (size_t)written >= sizeof(new_rel)) {
                result = DEFLATE_ERR_PATH;
                break;
            }
        } else {
            int written = snprintf(new_rel, sizeof(new_rel), "%s", entry->d_name);
            if (written < 0 || (size_t)written >= sizeof(new_rel)) {
                result = DEFLATE_ERR_PATH;
                break;
            }
        }

        int child_dir_fd = openat(dir_fd, entry->d_name,
                                  O_RDONLY | O_DIRECTORY
#ifdef O_NOFOLLOW
                                  | O_NOFOLLOW
#endif
                                  );
        if (child_dir_fd >= 0) {
            result = snapshot_directory_posix(child_dir_fd, new_rel, fl, snapshot_fp, total_bytes);
            close(child_dir_fd);
            if (result != DEFLATE_OK) break;
            continue;
        }
        if (errno == ELOOP) continue;
        if (errno != ENOTDIR) {
            result = DEFLATE_ERR_IO;
            break;
        }

        int file_fd = openat(dir_fd, entry->d_name,
                             O_RDONLY
#ifdef O_NOFOLLOW
                             | O_NOFOLLOW
#endif
                             );
        if (file_fd < 0) {
            if (errno == ELOOP) continue;
            result = DEFLATE_ERR_IO;
            break;
        }

        struct stat st;
        if (fstat(file_fd, &st) != 0) {
            close(file_fd);
            result = DEFLATE_ERR_IO;
            break;
        }
        if (!S_ISREG(st.st_mode)) {
            close(file_fd);
            continue;
        }

        uint64_t copied = 0;
        result = snapshot_file_posix(file_fd, snapshot_fp, &copied, total_bytes);
        close(file_fd);
        if (result != DEFLATE_OK) break;
        if (!filelist_add(fl, new_rel, copied)) {
            result = DEFLATE_ERR_LIMIT;
            break;
        }
    }

    closedir(dir);
    return result;
}
#endif

static DeflateError build_folder_snapshot(const char *folder_path, const char *outfile,
                                          FileList **fl_out, char **snapshot_path_out,
                                          uint64_t *total_bytes_out) {
    FileList *fl = filelist_create();
    FILE *snapshot_fp = NULL;
    char *snapshot_path = NULL;
    DeflateError result = DEFLATE_OK;

    *fl_out = NULL;
    *snapshot_path_out = NULL;
    *total_bytes_out = 0;

    if (!fl) return DEFLATE_ERR_MEM;

    snapshot_fp = open_unique_temp_file_sibling(outfile, &snapshot_path);
    if (!snapshot_fp) {
        filelist_destroy(fl);
        return DEFLATE_ERR_IO;
    }

#if PLATFORM_WINDOWS
    result = snapshot_directory_windows(folder_path, "", fl, snapshot_fp, total_bytes_out);
#else
    int root_fd = open(folder_path,
                       O_RDONLY | O_DIRECTORY
#ifdef O_NOFOLLOW
                       | O_NOFOLLOW
#endif
                       );
    if (root_fd < 0) {
        result = (errno == ELOOP) ? DEFLATE_ERR_PATH : DEFLATE_ERR_IO;
    } else {
        result = snapshot_directory_posix(root_fd, "", fl, snapshot_fp, total_bytes_out);
        close(root_fd);
    }
#endif

    if (fflush(snapshot_fp) != 0) result = DEFLATE_ERR_IO;
    if (fclose(snapshot_fp) != 0 && result == DEFLATE_OK) result = DEFLATE_ERR_IO;
    snapshot_fp = NULL;

    if (result == DEFLATE_OK && fl->count == 0) {
        result = DEFLATE_ERR_FORMAT;
    }

    if (result != DEFLATE_OK) {
        if (snapshot_path) remove_path_if_exists(snapshot_path);
        SAFE_FREE(snapshot_path);
        filelist_destroy(fl);
        return result;
    }

    *fl_out = fl;
    *snapshot_path_out = snapshot_path;
    return DEFLATE_OK;
}

/* ==================== PORTABLE I/O ==================== */

/* FIX #7: Little-endian serialization, no ftell dependency */
static bool write_le16(FILE *fp, uint16_t val) {
    uint8_t buf[2] = {
        (uint8_t)(val & 0xFF),
        (uint8_t)((val >> 8) & 0xFF)
    };
    return fwrite(buf, 1, 2, fp) == 2;
}

static bool read_le16(FILE *fp, uint16_t *val) {
    uint8_t buf[2];
    if (fread(buf, 1, 2, fp) != 2) return false;
    *val = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    return true;
}

static bool write_le32(FILE *fp, uint32_t val) {
    uint8_t buf[4] = {
        (uint8_t)(val & 0xFF),
        (uint8_t)((val >> 8) & 0xFF),
        (uint8_t)((val >> 16) & 0xFF),
        (uint8_t)((val >> 24) & 0xFF)
    };
    return fwrite(buf, 1, 4, fp) == 4;
}

static bool read_le32(FILE *fp, uint32_t *val) {
    uint8_t buf[4];
    if (fread(buf, 1, 4, fp) != 4) return false;
    *val = (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
    return true;
}

static bool write_le64(FILE *fp, uint64_t val) {
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
    }
    return fwrite(buf, 1, 8, fp) == 8;
}

static bool read_le64(FILE *fp, uint64_t *val) {
    uint8_t buf[8];
    if (fread(buf, 1, 8, fp) != 8) return false;
    *val = 0;
    for (int i = 0; i < 8; i++) {
        *val |= ((uint64_t)buf[i] << (i * 8));
    }
    return true;
}

/* ==================== SHA-256 ==================== */

static uint32_t sha256_rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32U - n));
}

static uint32_t sha256_load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void sha256_store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_transform(SHA256Ctx *ctx, const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
        0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
        0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
        0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
        0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
        0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
        0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
        0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
        0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
        0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
        0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
        0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
        0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
        0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
        0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
        0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = sha256_load_be32(block + (size_t)i * 4U);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = sha256_rotr(w[i - 15], 7) ^ sha256_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sha256_rotr(w[i - 2], 17) ^ sha256_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t s1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256Ctx *ctx) {
    static const uint32_t iv[8] = {
        0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
        0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
    };
    memcpy(ctx->state, iv, sizeof(iv));
    ctx->bit_count = 0;
    ctx->buffer_len = 0;
}

static void sha256_update(SHA256Ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bit_count += (uint64_t)len * 8U;
    while (len > 0) {
        size_t take = 64U - ctx->buffer_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;

        if (ctx->buffer_len == 64U) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

static void sha256_final(SHA256Ctx *ctx, uint8_t out[32]) {
    ctx->buffer[ctx->buffer_len++] = 0x80;
    if (ctx->buffer_len > 56U) {
        while (ctx->buffer_len < 64U) ctx->buffer[ctx->buffer_len++] = 0;
        sha256_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    while (ctx->buffer_len < 56U) ctx->buffer[ctx->buffer_len++] = 0;

    for (int i = 7; i >= 0; i--) {
        ctx->buffer[ctx->buffer_len++] = (uint8_t)(ctx->bit_count >> (i * 8));
    }
    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        sha256_store_be32(out + (size_t)i * 4U, ctx->state[i]);
    }
}

static DeflateError sha256_file(const char *path, uint8_t digest[32]) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return DEFLATE_ERR_IO;

    SHA256Ctx ctx;
    sha256_init(&ctx);

    uint8_t buf[IO_BUFFER_SIZE];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        sha256_update(&ctx, buf, n);
    }
    if (ferror(fp)) {
        fclose(fp);
        return DEFLATE_ERR_IO;
    }
    fclose(fp);
    sha256_final(&ctx, digest);
    return DEFLATE_OK;
}

/* ==================== SIGNATURE VERIFICATION ==================== */

static void bigint_zero(BigUint *a, size_t nwords) {
    memset(a->words, 0, sizeof(uint32_t) * nwords);
    a->nwords = nwords;
}

static void bigint_copy(BigUint *dst, const BigUint *src, size_t nwords) {
    memcpy(dst->words, src->words, sizeof(uint32_t) * nwords);
    dst->nwords = nwords;
}

static int bigint_cmp(const BigUint *a, const BigUint *b, size_t nwords) {
    for (size_t i = nwords; i > 0; i--) {
        uint32_t aw = a->words[i - 1];
        uint32_t bw = b->words[i - 1];
        if (aw < bw) return -1;
        if (aw > bw) return 1;
    }
    return 0;
}

static void bigint_add_n(BigUint *a, const BigUint *b, size_t nwords) {
    uint64_t carry = 0;
    for (size_t i = 0; i < nwords; i++) {
        uint64_t sum = (uint64_t)a->words[i] + (uint64_t)b->words[i] + carry;
        a->words[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
}

static void bigint_sub_n(BigUint *a, const BigUint *b, size_t nwords) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < nwords; i++) {
        uint64_t av = (uint64_t)a->words[i];
        uint64_t bv = (uint64_t)b->words[i] + borrow;
        if (av >= bv) {
            a->words[i] = (uint32_t)(av - bv);
            borrow = 0;
        } else {
            a->words[i] = (uint32_t)((1ULL << 32) + av - bv);
            borrow = 1;
        }
    }
}

static bool bigint_from_bytes_be(BigUint *a, const uint8_t *buf, size_t len) {
    size_t nwords = (len + 3U) / 4U;
    if (nwords == 0 || nwords > RSA_MAX_WORDS) return false;

    bigint_zero(a, nwords);
    size_t pos = len;
    for (size_t i = 0; i < nwords; i++) {
        uint32_t word = 0;
        for (size_t j = 0; j < 4 && pos > 0; j++) {
            pos--;
            word |= (uint32_t)buf[pos] << (j * 8U);
        }
        a->words[i] = word;
    }
    return true;
}

static void bigint_to_bytes_be(const BigUint *a, uint8_t *buf, size_t len) {
    memset(buf, 0, len);
    for (size_t i = 0; i < len; i++) {
        size_t byte_index = len - 1U - i;
        size_t word_index = i / 4U;
        size_t shift = (i % 4U) * 8U;
        if (word_index < a->nwords) {
            buf[byte_index] = (uint8_t)(a->words[word_index] >> shift);
        }
    }
}

static void bigint_set_u32(BigUint *a, uint32_t value, size_t nwords) {
    bigint_zero(a, nwords);
    a->words[0] = value;
}

static bool bigint_get_bit(const BigUint *a, size_t bit_index) {
    size_t word = bit_index / 32U;
    size_t bit = bit_index % 32U;
    if (word >= a->nwords) return false;
    return ((a->words[word] >> bit) & 1U) != 0;
}

static void bigint_add_mod(BigUint *acc, const BigUint *b, const BigUint *mod, size_t nwords) {
    BigUint threshold;
    bigint_copy(&threshold, mod, nwords);
    bigint_sub_n(&threshold, b, nwords);

    if (bigint_cmp(acc, &threshold, nwords) >= 0) {
        bigint_sub_n(acc, &threshold, nwords);
    } else {
        bigint_add_n(acc, b, nwords);
    }
}

static void bigint_modmul(BigUint *out, const BigUint *a, const BigUint *b,
                          const BigUint *mod, size_t nwords) {
    BigUint x, res;
    bigint_copy(&x, a, nwords);
    bigint_zero(&res, nwords);

    for (size_t bit = 0; bit < nwords * 32U; bit++) {
        if (bigint_get_bit(b, bit)) {
            bigint_add_mod(&res, &x, mod, nwords);
        }
        bigint_add_mod(&x, &x, mod, nwords);
    }

    bigint_copy(out, &res, nwords);
}

static void bigint_modexp_u32(BigUint *out, const BigUint *base, uint32_t exponent,
                              const BigUint *mod, size_t nwords) {
    BigUint result, power;
    bigint_set_u32(&result, 1U, nwords);
    bigint_copy(&power, base, nwords);

    while (exponent != 0U) {
        if ((exponent & 1U) != 0U) {
            BigUint tmp;
            bigint_modmul(&tmp, &result, &power, mod, nwords);
            bigint_copy(&result, &tmp, nwords);
        }
        exponent >>= 1U;
        if (exponent != 0U) {
            BigUint tmp;
            bigint_modmul(&tmp, &power, &power, mod, nwords);
            bigint_copy(&power, &tmp, nwords);
        }
    }

    bigint_copy(out, &result, nwords);
}

static int base64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;
    return -1;
}

static bool load_file_bytes(const char *path, uint8_t **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;

    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;
    uint8_t tmp[1024];
    size_t n;

    while ((n = fread(tmp, 1, sizeof(tmp), fp)) > 0) {
        if (len > SIZE_MAX - n) {
            free(buf);
            fclose(fp);
            return false;
        }
        if (len + n > cap) {
            size_t new_cap = cap ? cap * 2U : 2048U;
            while (new_cap < len + n) new_cap *= 2U;
            uint8_t *new_buf = realloc(buf, new_cap);
            if (!new_buf) {
                free(buf);
                fclose(fp);
                return false;
            }
            buf = new_buf;
            cap = new_cap;
        }
        memcpy(buf + len, tmp, n);
        len += n;
    }
    if (ferror(fp)) {
        free(buf);
        fclose(fp);
        return false;
    }
    fclose(fp);

    *out = buf;
    *out_len = len;
    return true;
}

static bool decode_pem_block(const uint8_t *data, size_t len,
                             const char *label, uint8_t **der, size_t *der_len) {
    size_t header_len = strlen(label) + 17U;
    size_t footer_len = strlen(label) + 15U;
    char *header = malloc(header_len + 1U);
    char *footer = malloc(footer_len + 1U);
    char *text = malloc(len + 1U);
    if (!header || !footer || !text) {
        free(header); free(footer); free(text);
        return false;
    }

    snprintf(header, header_len + 1U, "-----BEGIN %s-----", label);
    snprintf(footer, footer_len + 1U, "-----END %s-----", label);
    memcpy(text, data, len);
    text[len] = '\0';

    char *start = strstr(text, header);
    if (!start) {
        free(header); free(footer); free(text);
        return false;
    }
    start += strlen(header);
    char *end = strstr(start, footer);
    if (!end) {
        free(header); free(footer); free(text);
        return false;
    }

    size_t cap = ((size_t)(end - start) / 4U + 1U) * 3U;
    uint8_t *out = malloc(cap ? cap : 1U);
    if (!out) {
        free(header); free(footer); free(text);
        return false;
    }

    size_t out_pos = 0;
    int vals[4];
    int have = 0;
    for (char *p = start; p < end; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;

        int v = base64_value(ch);
        if (v < -1) {
            vals[have++] = v;
        } else if (v >= 0) {
            vals[have++] = v;
        } else {
            free(out); free(header); free(footer); free(text);
            return false;
        }

        if (have == 4) {
            if (vals[0] < 0 || vals[1] < 0) {
                free(out); free(header); free(footer); free(text);
                return false;
            }
            out[out_pos++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
            if (vals[2] != -2) {
                if (vals[2] < 0) {
                    free(out); free(header); free(footer); free(text);
                    return false;
                }
                out[out_pos++] = (uint8_t)(((vals[1] & 0x0F) << 4) | (vals[2] >> 2));
                if (vals[3] != -2) {
                    if (vals[3] < 0) {
                        free(out); free(header); free(footer); free(text);
                        return false;
                    }
                    out[out_pos++] = (uint8_t)(((vals[2] & 0x03) << 6) | vals[3]);
                }
            }
            have = 0;
        }
    }

    free(header); free(footer); free(text);
    if (have != 0) {
        free(out);
        return false;
    }

    *der = out;
    *der_len = out_pos;
    return true;
}

static bool der_read_length(const uint8_t *buf, size_t len, size_t *off, size_t *out_len) {
    if (*off >= len) return false;
    uint8_t first = buf[(*off)++];
    if ((first & 0x80U) == 0) {
        *out_len = first;
        return *off + *out_len <= len;
    }

    size_t count = first & 0x7FU;
    if (count == 0 || count > sizeof(size_t) || *off + count > len) return false;
    size_t v = 0;
    for (size_t i = 0; i < count; i++) {
        v = (v << 8) | buf[(*off)++];
    }
    if (*off + v > len) return false;
    *out_len = v;
    return true;
}

static bool der_expect_tag(const uint8_t *buf, size_t len, size_t *off,
                           uint8_t tag, const uint8_t **val, size_t *val_len) {
    if (*off >= len || buf[*off] != tag) return false;
    (*off)++;
    if (!der_read_length(buf, len, off, val_len)) return false;
    *val = buf + *off;
    *off += *val_len;
    return true;
}

static bool parse_rsa_public_key_pkcs1(const uint8_t *der, size_t der_len, RsaPublicKey *key) {
    size_t off = 0;
    const uint8_t *seq;
    size_t seq_len;
    if (!der_expect_tag(der, der_len, &off, 0x30, &seq, &seq_len) || off != der_len) return false;

    size_t s_off = 0;
    const uint8_t *mod_bytes, *exp_bytes;
    size_t mod_len, exp_len;
    if (!der_expect_tag(seq, seq_len, &s_off, 0x02, &mod_bytes, &mod_len)) return false;
    if (!der_expect_tag(seq, seq_len, &s_off, 0x02, &exp_bytes, &exp_len)) return false;
    if (s_off != seq_len || mod_len == 0 || exp_len == 0) return false;
    if ((mod_bytes[0] & 0x80U) != 0 || (exp_bytes[0] & 0x80U) != 0) return false;

    while (mod_len > 0 && mod_bytes[0] == 0x00) { mod_bytes++; mod_len--; }
    while (exp_len > 0 && exp_bytes[0] == 0x00) { exp_bytes++; exp_len--; }
    if (mod_len == 0 || exp_len == 0 || mod_len > (RSA_MAX_BITS / 8U)) return false;

    if (exp_len > 4U) return false;
    uint32_t exponent = 0;
    for (size_t i = 0; i < exp_len; i++) {
        exponent = (exponent << 8) | exp_bytes[i];
    }
    if (exponent < 3U || (exponent & 1U) == 0) return false;

    if (!bigint_from_bytes_be(&key->modulus, mod_bytes, mod_len)) return false;
    key->exponent = exponent;
    key->modulus_len = mod_len;
    return true;
}

static bool parse_rsa_public_key_spki(const uint8_t *der, size_t der_len, RsaPublicKey *key) {
    static const uint8_t rsa_oid[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};
    size_t off = 0;
    const uint8_t *outer;
    size_t outer_len;
    if (!der_expect_tag(der, der_len, &off, 0x30, &outer, &outer_len) || off != der_len) return false;

    size_t o_off = 0;
    const uint8_t *alg_seq, *bitstr;
    size_t alg_len, bitstr_len;
    if (!der_expect_tag(outer, outer_len, &o_off, 0x30, &alg_seq, &alg_len)) return false;
    if (!der_expect_tag(outer, outer_len, &o_off, 0x03, &bitstr, &bitstr_len)) return false;
    if (o_off != outer_len || bitstr_len < 1U || bitstr[0] != 0x00) return false;

    size_t a_off = 0;
    const uint8_t *oid;
    size_t oid_len;
    if (!der_expect_tag(alg_seq, alg_len, &a_off, 0x06, &oid, &oid_len)) return false;
    if (oid_len != sizeof(rsa_oid) || memcmp(oid, rsa_oid, sizeof(rsa_oid)) != 0) return false;
    if (a_off < alg_len) {
        const uint8_t *nullv;
        size_t null_len;
        if (!der_expect_tag(alg_seq, alg_len, &a_off, 0x05, &nullv, &null_len) || null_len != 0) {
            return false;
        }
    }
    if (a_off != alg_len) return false;

    return parse_rsa_public_key_pkcs1(bitstr + 1U, bitstr_len - 1U, key);
}

static bool load_rsa_public_key(const char *path, RsaPublicKey *key) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (!load_file_bytes(path, &raw, &raw_len)) return false;

    uint8_t *der = NULL;
    size_t der_len = 0;
    bool ok = false;

    if (raw_len > 0 && raw[0] == 0x30) {
        der = raw;
        der_len = raw_len;
        ok = parse_rsa_public_key_spki(der, der_len, key) ||
             parse_rsa_public_key_pkcs1(der, der_len, key);
        raw = NULL;
    } else {
        if (decode_pem_block(raw, raw_len, "PUBLIC KEY", &der, &der_len) ||
            decode_pem_block(raw, raw_len, "RSA PUBLIC KEY", &der, &der_len)) {
            ok = parse_rsa_public_key_spki(der, der_len, key) ||
                 parse_rsa_public_key_pkcs1(der, der_len, key);
        }
    }

    free(raw);
    free(der);
    return ok;
}

static bool verify_pkcs1_v15_sha256_em(const uint8_t *em, size_t em_len,
                                       const uint8_t digest[32]) {
    static const uint8_t prefix[] = {
        0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,
        0x04,0x02,0x01,0x05,0x00,0x04,0x20
    };
    size_t t_len = sizeof(prefix) + 32U;
    if (em_len < t_len + 11U) return false;
    if (em[0] != 0x00 || em[1] != 0x01) return false;

    size_t i = 2;
    while (i < em_len && em[i] == 0xFF) i++;
    if (i < 10U || i >= em_len || em[i] != 0x00) return false;
    i++;
    if (em_len - i != t_len) return false;
    if (memcmp(em + i, prefix, sizeof(prefix)) != 0) return false;
    return memcmp(em + i + sizeof(prefix), digest, 32U) == 0;
}

static DeflateError verify_archive_signature(const char *archive_path,
                                             const char *sig_path,
                                             const char *pubkey_path) {
    if (!is_valid_host_path(archive_path) ||
        !is_valid_host_path(sig_path) ||
        !is_valid_host_path(pubkey_path)) {
        LOG_ERR("Error: Invalid path\n");
        return DEFLATE_ERR_PATH;
    }

    RsaPublicKey key;
    memset(&key, 0, sizeof(key));
    if (!load_rsa_public_key(pubkey_path, &key)) {
        LOG_ERR("Error: Failed to parse RSA public key\n");
        return DEFLATE_ERR_AUTH;
    }

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (!load_file_bytes(sig_path, &sig, &sig_len)) {
        LOG_ERR("Error: Failed to read signature file\n");
        return DEFLATE_ERR_AUTH;
    }
    if (sig_len != key.modulus_len) {
        free(sig);
        LOG_ERR("Error: Signature length does not match RSA modulus\n");
        return DEFLATE_ERR_AUTH;
    }

    BigUint sig_int;
    if (!bigint_from_bytes_be(&sig_int, sig, sig_len) ||
        bigint_cmp(&sig_int, &key.modulus, key.modulus.nwords) >= 0) {
        free(sig);
        LOG_ERR("Error: Signature integer is out of range\n");
        return DEFLATE_ERR_AUTH;
    }
    free(sig);

    uint8_t digest[32];
    DeflateError err = sha256_file(archive_path, digest);
    if (err != DEFLATE_OK) {
        LOG_ERR("Error: Failed to hash archive for signature verification\n");
        return DEFLATE_ERR_AUTH;
    }

    BigUint em_int;
    bigint_modexp_u32(&em_int, &sig_int, key.exponent, &key.modulus, key.modulus.nwords);

    uint8_t em[(RSA_MAX_BITS / 8)];
    bigint_to_bytes_be(&em_int, em, key.modulus_len);
    if (!verify_pkcs1_v15_sha256_em(em, key.modulus_len, digest)) {
        LOG_ERR("Error: Signature verification failed\n");
        return DEFLATE_ERR_AUTH;
    }

    LOG_NORMAL_MSG("Signature Verified\n");
    return DEFLATE_OK;
}

/* ==================== CRC32 (Slice-by-4 Optimized) ==================== */

/**
 * v5.0: Slice-by-4 CRC32 — processes 4 bytes at a time for ~3-4x speedup.
 * Uses 4 lookup tables (4KB total) instead of 1 (1KB).
 * Falls back to byte-at-a-time for tail bytes and short buffers.
 */
static void init_crc32_tables(CRC32Tables *tables) {
    /* Build standard byte-at-a-time table (table 0) */
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        tables->tab[0][i] = c;
    }
    /* Build slice-by-4 extension tables (tables 1-3) */
    for (uint32_t i = 0; i < 256; i++) {
        tables->tab[1][i] = (tables->tab[0][i] >> 8) ^ tables->tab[0][tables->tab[0][i] & 0xFF];
        tables->tab[2][i] = (tables->tab[1][i] >> 8) ^ tables->tab[0][tables->tab[1][i] & 0xFF];
        tables->tab[3][i] = (tables->tab[2][i] >> 8) ^ tables->tab[0][tables->tab[2][i] & 0xFF];
    }
}

static uint32_t update_crc32(const CRC32Tables *tables, uint32_t crc,
                             const uint8_t *buf, size_t len) {
    uint32_t c = crc ^ 0xFFFFFFFF;
    const uint8_t *p = buf;

    /* Process 4 bytes at a time (slice-by-4) */
    while (len >= 4) {
        c ^= (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
             ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        c = tables->tab[3][(c      ) & 0xFF] ^
            tables->tab[2][(c >>  8) & 0xFF] ^
            tables->tab[1][(c >> 16) & 0xFF] ^
            tables->tab[0][(c >> 24) & 0xFF];
        p += 4;
        len -= 4;
    }

    /* Byte-at-a-time tail */
    while (len-- > 0) {
        c = tables->tab[0][(c ^ *p++) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

/* ==================== BIT I/O ==================== */

/**
 * FIX #4: Documented bit ordering.
 * Bits are written MSB-first: first bit written goes to bit 7 of first byte.
 * bit_acc accumulates bits; when >= 8 bits, MSB byte is flushed.
 */
static void bs_init(BitStream *bs, FILE *fp, bool write) {
    bs->fp = fp;
    bs->pos = 0;
    bs->bytes_in_buf = 0;
    bs->bit_acc = 0;
    bs->bit_count = 0;
    bs->mode_write = write;
    bs->bytes_written = 0;  /* FIX #14 */
}

/**
 * FIX #4: Flush pending bits and buffer to file.
 * Partial byte (< 8 bits) is padded with zeros in LSB positions.
 */
static DeflateError bs_flush(BitStream *bs) {
    if (!bs->mode_write) return DEFLATE_OK;

    /* Flush any remaining bits (pad with zeros) */
    while (bs->bit_count > 0) {
        uint8_t byte;
        if (bs->bit_count < 8) {
            byte = (uint8_t)(bs->bit_acc << (8 - bs->bit_count));
            bs->bit_count = 0;
        } else {
            int32_t shift = bs->bit_count - 8;
            byte = (uint8_t)((bs->bit_acc >> shift) & 0xFF);
            bs->bit_count -= 8;
        }

        if (bs->pos >= IO_BUFFER_SIZE) {
            if (fwrite(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp) != IO_BUFFER_SIZE)
                return DEFLATE_ERR_IO;
            bs->bytes_written += IO_BUFFER_SIZE;  /* FIX #14 */
            bs->pos = 0;
        }
        DBG_ASSERT(bs->pos < IO_BUFFER_SIZE);
        bs->buffer[bs->pos++] = byte;
    }

    /* Flush buffer to file */
    if (bs->pos > 0) {
        if (fwrite(bs->buffer, 1, bs->pos, bs->fp) != bs->pos)
            return DEFLATE_ERR_IO;
        bs->bytes_written += bs->pos;  /* FIX #14 */
        bs->pos = 0;
    }
    return DEFLATE_OK;
}

/**
 * Write 'bits' bits from 'val' (MSB-first).
 *
 * INVARIANT: bit_acc holds pending bits RIGHT-aligned (LSB positions).
 * New bits are shifted in from the right. When bit_count >= 8, the
 * MSB byte is extracted and flushed.
 */
static DeflateError bs_write(BitStream *bs, uint64_t val, int32_t bits) {
    DBG_ASSERT(bs->mode_write);  /* FIX #13: Catch misuse in debug builds */
    DBG_ASSERT(bits >= 0 && bits <= 64);
    if (bits < 0 || bits > 64) return DEFLATE_ERR_FORMAT;
    if (bits == 0) return DEFLATE_OK;

    uint64_t mask = (bits < 64) ? ((1ULL << bits) - 1) : UINT64_MAX;
    bs->bit_acc = (bs->bit_acc << bits) | (val & mask);
    bs->bit_count += bits;

    while (bs->bit_count >= 8) {
        bs->bit_count -= 8;
        uint8_t byte = (uint8_t)((bs->bit_acc >> bs->bit_count) & 0xFF);

        if (bs->pos >= IO_BUFFER_SIZE) {
            if (fwrite(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp) != IO_BUFFER_SIZE)
                return DEFLATE_ERR_IO;
            bs->bytes_written += IO_BUFFER_SIZE;  /* FIX #14 */
            bs->pos = 0;
        }
        DBG_ASSERT(bs->pos < IO_BUFFER_SIZE);
        bs->buffer[bs->pos++] = byte;
    }
    return DEFLATE_OK;
}

/**
 * Read single bit (MSB-first). Returns -1 on EOF.
 */
/* Refill bit_acc from buffer until we have >= 'need' bits or hit EOF.
 * bit_acc stores bits MSB-aligned: the next bit to consume is at position
 * (bit_count - 1). Returns false if EOF reached before satisfying 'need'. */
static bool bs_refill(BitStream *bs, int32_t need) {
    while (bs->bit_count < need) {
        if (bs->bit_count > 56) break;  /* prevent uint64_t overflow on shift */
        if (bs->pos >= bs->bytes_in_buf) {
            bs->bytes_in_buf = fread(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
            bs->pos = 0;
            if (bs->bytes_in_buf == 0) return false;
        }
        bs->bit_acc = (bs->bit_acc << 8) | bs->buffer[bs->pos++];
        bs->bit_count += 8;
    }
    return bs->bit_count >= need;
}

static int32_t bs_read_bit(BitStream *bs) {
    if (!bs_refill(bs, 1)) return -1;
    bs->bit_count--;
    return (int32_t)((bs->bit_acc >> bs->bit_count) & 1);
}

static uint32_t bs_read_bits(BitStream *bs, int32_t bits, bool *error) {
    DBG_ASSERT(error != NULL);
    *error = false;
    if (bits <= 0 || bits > 32) { *error = (bits != 0); return 0; }

    if (!bs_refill(bs, bits)) { *error = true; return 0; }
    bs->bit_count -= bits;
    return (uint32_t)((bs->bit_acc >> bs->bit_count) & ((1ULL << bits) - 1));
}

/* Read 32-bit LE value at byte boundary. Discards sub-byte padding bits,
 * then drains any whole bytes remaining in bit_acc before reading from
 * the I/O buffer. This is necessary because bs_refill may have pulled
 * CRC footer bytes into bit_acc ahead of time. */
static bool bs_read_aligned_uint32(BitStream *bs, uint32_t *out) {
    int32_t discard = bs->bit_count % 8;
    bs->bit_count -= discard;

    uint32_t res = 0;
    for (int i = 0; i < 4; i++) {
        if (bs->bit_count >= 8) {
            bs->bit_count -= 8;
            res |= (uint32_t)((bs->bit_acc >> bs->bit_count) & 0xFF) << (i * 8);
        } else {
            if (bs->pos >= bs->bytes_in_buf) {
                bs->bytes_in_buf = fread(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
                bs->pos = 0;
                if (bs->bytes_in_buf == 0) {
                    *out = res;
                    return false;
                }
            }
            res |= ((uint32_t)bs->buffer[bs->pos++] << (i * 8));
        }
    }
    *out = res;
    return true;
}

/* ==================== HASH CHAIN LZSS ==================== */

/**
 * 4-byte hash with good avalanche properties.
 * Uses a multiplicative hash with the golden ratio prime.
 * FIX #5: Caller must ensure data points to >= 4 bytes for best results,
 * but will work with >= MIN_MATCH (3) bytes safely.
 */
static inline uint32_t hash4(const uint8_t *data) {
    uint32_t v = ((uint32_t)data[0] << 21) |
                 ((uint32_t)data[1] << 14) |
                 ((uint32_t)data[2] << 7)  |
                 (uint32_t)data[3];
    /* Multiply by golden ratio prime for better distribution */
    v = v * 2654435761U;
    return (v >> (32 - HASH_BITS)) & HASH_MASK;
}

/* 3-byte hash for positions where we don't have 4 bytes */
static inline uint32_t hash3(const uint8_t *data) {
    return ((((uint32_t)data[0] << 10) ^ ((uint32_t)data[1] << 5) ^ data[2])) & HASH_MASK;
}

static void hash_init(HashChain *hc) {
    memset(hc->head, 0xFF, sizeof(hc->head));
    memset(hc->prev, 0xFF, sizeof(hc->prev));
}

static void hash_insert(HashChain *hc, uint32_t hash, uint16_t pos) {
    DBG_ASSERT(pos < WINDOW_SIZE);
    DBG_ASSERT(hash < HASH_SIZE);
    if (pos >= WINDOW_SIZE || hash >= HASH_SIZE) return;
    hc->prev[pos] = hc->head[hash];
    hc->head[hash] = pos;
}

/**
 * FIX #1 & #5: Clear variable naming; bounds-safe window access.
 * 'bytes_avail' = valid bytes from pos onwards in window.
 * Enhanced with fast-path short chain search.
 */
static void find_best_match(const DeflateContext *ctx, uint16_t pos,
                            int32_t bytes_avail, int32_t *match_pos,
                            int32_t *match_len) {
    *match_len = 0;
    *match_pos = 0;

    /* FIX #5: Need MIN_MATCH bytes for hash and comparison */
    if (bytes_avail < MIN_MATCH || pos >= WINDOW_SIZE) return;

    /* FIX #5: Bounds check before hash call */
    if (pos + MIN_MATCH > WINDOW_SIZE * 2) return;

    /* Use 4-byte hash if we have 4+ bytes, otherwise 3-byte */
    uint32_t hash;
    if (bytes_avail >= 4 && pos + 4 <= WINDOW_SIZE * 2) {
        hash = hash4(&ctx->window[pos]);
    } else {
        hash = hash3(&ctx->window[pos]);
    }
    DBG_ASSERT(hash < HASH_SIZE);

    uint16_t chain = ctx->hash_chain.head[hash];
    int32_t chain_count = 0;
    int32_t max_len = (bytes_avail < MAX_MATCH) ? bytes_avail : MAX_MATCH;

    /* FIX #5: Clamp max_len to stay within doubled window buffer */
    if (pos + max_len > WINDOW_SIZE * 2) {
        max_len = WINDOW_SIZE * 2 - pos;
    }
    if (max_len < MIN_MATCH) return;

    uint8_t first = ctx->window[pos];
    uint8_t second = ctx->window[pos + 1];

    int32_t chain_limit = FAST_CHAIN_LENGTH;
    for (int phase = 0; phase < 2; phase++) {
        while (chain != 0xFFFF && chain < WINDOW_SIZE && chain_count++ < chain_limit) {
            int32_t distance = (pos - chain) & WINDOW_MASK;
            if (distance == 0) break;

            if (distance > WINDOW_SIZE - MAX_MATCH) {
                chain = ctx->hash_chain.prev[chain];
                continue;
            }

            int32_t chain_max_len = max_len;
            if (chain + chain_max_len > WINDOW_SIZE * 2)
                chain_max_len = WINDOW_SIZE * 2 - chain;
            if (chain_max_len < MIN_MATCH) {
                chain = ctx->hash_chain.prev[chain];
                continue;
            }

            if (ctx->window[chain] == first && ctx->window[chain + 1] == second) {
                int32_t safe_max = (chain_max_len < max_len) ? chain_max_len : max_len;
                DBG_ASSERT(chain + safe_max <= WINDOW_SIZE * 2);
                DBG_ASSERT(pos + safe_max <= WINDOW_SIZE * 2);

                int32_t len = 2;
                while (len < safe_max && ctx->window[chain + len] == ctx->window[pos + len])
                    len++;

                if (len > *match_len) {
                    *match_len = len;
                    *match_pos = chain;
                    if (len >= MAX_MATCH) return;
                    if (phase == 0 && len >= 32) { phase = 1; break; }
                }
            }
            chain = ctx->hash_chain.prev[chain];
        }
        chain_limit = MAX_CHAIN_LENGTH;
    }
}

/* ==================== HUFFMAN CODING ==================== */

/* MinHeap storage is caller-provided so Huffman building stays allocation-free
 * in the hot per-block path. Arena storage still owns all HuffmanNode memory. */

/**
 * FIX #2: Returns false on overflow instead of silently failing.
 */
static bool heap_push(MinHeap *h, HuffmanNode *n) {
    DBG_ASSERT(h != NULL && n != NULL);
    if (!h || !n || h->size >= h->capacity) {
        DBG_PRINTF("heap_push overflow: size=%d, cap=%d\n", h ? h->size : -1, h ? h->capacity : -1);
        return false;
    }

    int32_t i = h->size++;
    while (i > 0 && n->freq < h->nodes[(i - 1) / 2]->freq) {
        h->nodes[i] = h->nodes[(i - 1) / 2];
        i = (i - 1) / 2;
    }
    h->nodes[i] = n;
    return true;
}

static HuffmanNode* heap_pop(MinHeap *h) {
    if (!h || h->size == 0) return NULL;

    HuffmanNode *res = h->nodes[0];
    HuffmanNode *last = h->nodes[--h->size];

    if (h->size == 0) return res;

    h->nodes[0] = last;
    int32_t i = 0;
    while (1) {
        int32_t smallest = i;
        int32_t l = 2 * i + 1;
        int32_t r = 2 * i + 2;

        if (l < h->size && h->nodes[l]->freq < h->nodes[smallest]->freq)
            smallest = l;
        if (r < h->size && h->nodes[r]->freq < h->nodes[smallest]->freq)
            smallest = r;
        if (smallest == i) break;

        HuffmanNode *temp = h->nodes[i];
        h->nodes[i] = h->nodes[smallest];
        h->nodes[smallest] = temp;
        i = smallest;
    }
    return res;
}

static void get_tree_depths(HuffmanNode *root, int32_t depth, uint8_t *lens) {
    if (!root) return;
    if (!root->left && !root->right) {
        if (root->sym >= 0 && root->sym < SYMBOL_COUNT) {
            lens[root->sym] = (uint8_t)((depth > MAX_HUFFMAN_DEPTH) ? MAX_HUFFMAN_DEPTH : depth);
        }
        return;
    }
    get_tree_depths(root->left, depth + 1, lens);
    get_tree_depths(root->right, depth + 1, lens);
}

/* free_tree removed: arena allocator owns all HuffmanNode memory */

static DeflateError build_huffman_codes(const uint64_t *freqs, CanonicalEntry *table,
                                         uint8_t *depths, uint16_t *max_sym_out) {
    MinHeap heap;
    HuffmanNode *heap_nodes[SYMBOL_COUNT * 2];
    MinHeap *h = &heap;
    HuffmanNode *root = NULL;
    HuffmanArena arena;
    DeflateError result = DEFLATE_OK;

    arena_init(&arena);
    h->nodes = heap_nodes;
    h->size = 0;
    h->capacity = SYMBOL_COUNT * 2;

    memset(depths, 0, SYMBOL_COUNT);
    *max_sym_out = 0;

    for (int32_t i = 0; i < SYMBOL_COUNT; i++) {
        if (freqs[i] > 0) {
            HuffmanNode *n = arena_alloc(&arena);
            if (!n) { result = DEFLATE_ERR_MEM; goto cleanup; }
            n->sym = i;
            n->freq = freqs[i];
            if (!heap_push(h, n)) { result = DEFLATE_ERR_MEM; goto cleanup; }
            *max_sym_out = (uint16_t)i;
        }
    }

    if (h->size == 0) { result = DEFLATE_ERR_FORMAT; goto cleanup; }

    if (h->size == 1) {
        HuffmanNode *n = heap_pop(h);
        HuffmanNode *dummy = arena_alloc(&arena);
        HuffmanNode *parent = arena_alloc(&arena);
        if (!dummy || !parent) { result = DEFLATE_ERR_MEM; goto cleanup; }

        dummy->sym = (n->sym == 0) ? 1 : 0;
        parent->freq = n->freq;
        parent->left = n;
        parent->right = dummy;
        if (!heap_push(h, parent)) { result = DEFLATE_ERR_MEM; goto cleanup; }
    }

    while (h->size > 1) {
        HuffmanNode *l = heap_pop(h);
        HuffmanNode *r = heap_pop(h);
        HuffmanNode *parent = arena_alloc(&arena);
        if (!parent) { result = DEFLATE_ERR_MEM; goto cleanup; }

        parent->freq = l->freq + r->freq;
        parent->left = l;
        parent->right = r;
        if (!heap_push(h, parent)) { result = DEFLATE_ERR_MEM; goto cleanup; }
    }

    root = heap_pop(h);
    get_tree_depths(root, 0, depths);

    {
        int32_t bl_count[32] = {0};
        uint64_t code = 0;
        uint64_t next_code[32];

        for (int32_t i = 0; i < SYMBOL_COUNT; i++) {
            if (depths[i] > 0) bl_count[depths[i]]++;
        }

        /* Length-limited Huffman: redistribute codes exceeding MAX_HUFFMAN_DEPTH.
         * This uses the JPEG Annex K / DEFLATE approach: move overflow codes to
         * the max legal depth, then fix Kraft inequality violations by promoting
         * codes from the deepest level upward until the tree is valid. */
        {
            int32_t overflow = 0;
            for (int32_t d = MAX_HUFFMAN_DEPTH + 1; d < 32; d++) {
                overflow += bl_count[d];
                bl_count[d] = 0;
            }
            bl_count[MAX_HUFFMAN_DEPTH] += overflow;

            /* Adjust until Kraft inequality is satisfied (left == 0) */
            int32_t left = 1;
            for (int32_t d = 1; d <= MAX_HUFFMAN_DEPTH; d++) {
                left = (left << 1) - bl_count[d];
            }
            while (left < 0) {
                for (int32_t d = MAX_HUFFMAN_DEPTH - 1; d >= 1 && left < 0; d--) {
                    if (bl_count[d] > 0) {
                        bl_count[d]--;
                        bl_count[d + 1] += 2;
                        bl_count[MAX_HUFFMAN_DEPTH]--;
                        left++;
                    }
                }
            }

            /* Reassign depths to symbols based on corrected bl_count.
             * Symbols are assigned in order of decreasing tree depth
             * (longest codes first), preserving canonical ordering. */
            int32_t sym_by_depth[SYMBOL_COUNT];
            int32_t nsyms = 0;
            for (int32_t i = 0; i < SYMBOL_COUNT; i++) {
                if (depths[i] > 0) sym_by_depth[nsyms++] = i;
            }
            /* Sort by depth descending (simple insertion sort — nsyms <= 513) */
            for (int32_t i = 1; i < nsyms; i++) {
                int32_t key = sym_by_depth[i];
                uint8_t kd = depths[key];
                int32_t j = i - 1;
                while (j >= 0 && depths[sym_by_depth[j]] < kd) {
                    sym_by_depth[j + 1] = sym_by_depth[j];
                    j--;
                }
                sym_by_depth[j + 1] = key;
            }

            int32_t si = 0;
            for (int32_t d = MAX_HUFFMAN_DEPTH; d >= 1; d--) {
                for (int32_t c2 = 0; c2 < bl_count[d] && si < nsyms; c2++) {
                    depths[sym_by_depth[si++]] = (uint8_t)d;
                }
            }
        }

        for (int32_t i = 1; i < 32; i++) {
            code = (code + (uint64_t)bl_count[i - 1]) << 1;
            next_code[i] = code;
        }

        for (int32_t i = 0; i <= *max_sym_out; i++) {
            if (depths[i] > 0) {
                table[i].sym = (uint16_t)i;
                table[i].len = depths[i];
                table[i].code = next_code[depths[i]]++;
            }
        }
    }

cleanup:
    return result;
}

static bool validate_canonical_entries(const CanonicalEntry *table, int32_t t_count,
                                       bool require_eob);

static DeflateError encode_block(DeflateContext *ctx, BitStream *bs,
                                 const uint64_t *freqs, int32_t token_count,
                                 bool is_last) {
    CanonicalEntry table[SYMBOL_COUNT] = {0};
    uint8_t depths[SYMBOL_COUNT];
    uint16_t max_sym = 0;

    DeflateError err = build_huffman_codes(freqs, table, depths, &max_sym);
    if (err != DEFLATE_OK) return err;

    {
        CanonicalEntry compact[SYMBOL_COUNT];
        int32_t t_count = 0;
        for (int32_t i = 0; i <= max_sym; i++) {
            if (table[i].len > 0) compact[t_count++] = table[i];
        }
        if (!validate_canonical_entries(compact, t_count, true)) {
            return DEFLATE_ERR_FORMAT;
        }
    }

    DBG_ASSERT(max_sym < SYMBOL_COUNT);
    if (max_sym >= SYMBOL_COUNT) return DEFLATE_ERR_FORMAT;

    /* Write block header */
    if ((err = bs_write(bs, is_last ? 1 : 0, 1)) != DEFLATE_OK) return err;
    if ((err = bs_write(bs, max_sym, 16)) != DEFLATE_OK) return err;

    /* Write code lengths (4 bits each, packed in pairs) */
    for (int32_t i = 0; i <= max_sym; i += 2) {
        uint8_t d1 = depths[i];
        uint8_t d2 = (i + 1 <= max_sym) ? depths[i + 1] : 0;
        if ((err = bs_write(bs, d1 & 0x0F, 4)) != DEFLATE_OK) return err;
        if ((err = bs_write(bs, d2 & 0x0F, 4)) != DEFLATE_OK) return err;
    }

    /* Write encoded tokens */
    for (int32_t i = 0; i < token_count; i++) {
        uint16_t val = ctx->token_buf[i].val;
        if (val >= SYMBOL_COUNT || table[val].len == 0) return DEFLATE_ERR_CORRUPT;

        if ((err = bs_write(bs, table[val].code, table[val].len)) != DEFLATE_OK)
            return err;

        if (ctx->token_buf[i].type == 1) {
            /* Write distance code (5 bits) + extra bits */
            if ((err = bs_write(bs, ctx->token_buf[i].dist_code, 5)) != DEFLATE_OK)
                return err;
            if (ctx->token_buf[i].dist_extra_bits > 0) {
                if ((err = bs_write(bs, ctx->token_buf[i].dist_extra,
                                    ctx->token_buf[i].dist_extra_bits)) != DEFLATE_OK)
                    return err;
            }
        }
    }

    /* Write EOB */
    return bs_write(bs, table[256].code, table[256].len);
}

/* ==================== FAST HUFFMAN DECODING ==================== */

static DeflateError build_fast_decode_table(FastDecodeEntry *decode_table,
                                            const CanonicalEntry *table,
                                            int32_t t_count) {
    memset(decode_table, 0, sizeof(FastDecodeEntry) * FAST_DECODE_SIZE);

    for (int32_t i = 0; i < t_count; i++) {
        uint8_t len = table[i].len;
        if (len == 0 || len > FAST_DECODE_BITS) continue;

        int32_t fill_count = 1 << (FAST_DECODE_BITS - len);
        uint32_t base = (uint32_t)(table[i].code << (FAST_DECODE_BITS - len));

        for (int32_t j = 0; j < fill_count; j++) {
            uint32_t idx = base + (uint32_t)j;
            if (idx >= FAST_DECODE_SIZE) return DEFLATE_ERR_FORMAT;
            if (decode_table[idx].bits_used != 0 &&
                (decode_table[idx].bits_used != len || decode_table[idx].symbol != table[i].sym)) {
                return DEFLATE_ERR_FORMAT;
            }
            decode_table[idx].symbol = table[i].sym;
            decode_table[idx].bits_used = len;
        }
    }
    return DEFLATE_OK;
}

static void build_canonical_decoder(DeflateContext *ctx,
                                    const CanonicalEntry *table, int32_t t_count,
                                    const int32_t *bl_count) {
    uint64_t fc = 0;
    int32_t sym_idx = 0;
    ctx->decode_max_len = 0;

    for (int32_t len = 1; len <= MAX_HUFFMAN_DEPTH; len++) {
        fc = (fc + (uint64_t)bl_count[len - 1]) << 1;
        ctx->decode_first_code[len] = fc;
        ctx->decode_bl_count[len] = bl_count[len];
        ctx->decode_sym_offset[len] = sym_idx;
        sym_idx += bl_count[len];
        if (bl_count[len] > 0) ctx->decode_max_len = len;
    }

    int32_t pos_arr[MAX_HUFFMAN_DEPTH + 2];
    memcpy(pos_arr, ctx->decode_sym_offset, sizeof(pos_arr));
    for (int32_t i = 0; i < t_count; i++) {
        ctx->decode_sorted_syms[pos_arr[table[i].len]++] = table[i].sym;
    }
}

static int32_t decode_symbol_fast(BitStream *bs, const DeflateContext *ctx) {
    if (bs_refill(bs, FAST_DECODE_BITS)) {
        uint32_t peek = (uint32_t)((bs->bit_acc >> (bs->bit_count - FAST_DECODE_BITS))
                        & (FAST_DECODE_SIZE - 1));
        FastDecodeEntry entry = ctx->decode_table[peek];
        if (entry.bits_used > 0 && entry.bits_used <= FAST_DECODE_BITS) {
            bs->bit_count -= entry.bits_used;
            return entry.symbol;
        }
    }

    uint64_t curr_code = 0;
    int32_t curr_len = 0;

    while (curr_len < ctx->decode_max_len) {
        int32_t b = bs_read_bit(bs);
        if (b == -1) return -1;

        curr_code = (curr_code << 1) | (uint64_t)b;
        curr_len++;

        if (curr_len > ctx->decode_max_len) return -1;

        if (ctx->decode_bl_count[curr_len] > 0) {
            int64_t offset = (int64_t)curr_code - (int64_t)ctx->decode_first_code[curr_len];
            if (offset >= 0 && offset < (int64_t)ctx->decode_bl_count[curr_len]) {
                return ctx->decode_sorted_syms[ctx->decode_sym_offset[curr_len] + (int32_t)offset];
            }
        }
    }
    return -1;
}

/* FIX #21: Validate Huffman code lengths form a valid prefix-free code.
 * FIX #27: Also reject undersubscribed trees (left > 0) to prevent CPU
 * amplification via undecodable bit patterns in the slow-path decoder.
 * Exception: single-symbol trees are inherently undersubscribed (left == 1). */
static bool validate_huffman_lengths(const int32_t *bl_count, int32_t max_bits) {
    int32_t left = 1;
    int32_t total_codes = 0;
    for (int32_t bits = 1; bits <= max_bits; bits++) {
        left <<= 1;
        left -= bl_count[bits];
        total_codes += bl_count[bits];
        if (left < 0) return false;
    }
    return left == 0 || (left == 1 && total_codes == 1);
}

static bool validate_canonical_entries(const CanonicalEntry *table, int32_t t_count,
                                       bool require_eob) {
    bool seen_symbols[SYMBOL_COUNT] = {false};
    bool has_eob = false;

    for (int32_t i = 0; i < t_count; i++) {
        if (table[i].sym >= SYMBOL_COUNT) return false;
        if (table[i].len == 0 || table[i].len > MAX_HUFFMAN_DEPTH) return false;
        if (table[i].code >= (1U << table[i].len)) return false;
        if (seen_symbols[table[i].sym]) return false;
        seen_symbols[table[i].sym] = true;
        if (table[i].sym == 256) has_eob = true;
    }

#ifdef DEBUG
    for (int32_t i = 0; i < t_count; i++) {
        for (int32_t j = i + 1; j < t_count; j++) {
            uint16_t code_a = table[i].code;
            uint16_t code_b = table[j].code;
            uint8_t len_a = table[i].len;
            uint8_t len_b = table[j].len;

            if (len_a == len_b && code_a == code_b) return false;

            if (len_a < len_b) {
                if ((code_b >> (len_b - len_a)) == code_a) return false;
            } else if (len_b < len_a) {
                if ((code_a >> (len_a - len_b)) == code_b) return false;
            }
        }
    }
#endif

    return !require_eob || has_eob;
}

/* ==================== PATH SECURITY ==================== */

/**
 * Host-side path policy for caller-supplied filesystem arguments.
 * Rejects control characters, absolute paths, Windows drive paths, and
 * parent-directory components while allowing relative paths rooted at ".".
 */
static bool is_valid_host_path(const char *path) {
    if (!path || !path[0]) return false;

    /* Reject absolute paths. */
    if (path[0] == '/' || path[0] == '\\') return false;
    if (strlen(path) >= 2 && path[1] == ':') return false;  /* Windows drive */

    const char *p = path;
    while (*p) {
        const char *end = p;
        while (*end && *end != '/' && *end != '\\') end++;
        size_t comp_len = (size_t)(end - p);

        if (comp_len == 2 && p[0] == '.' && p[1] == '.') return false;

        for (const unsigned char *c = (const unsigned char *)p;
             c < (const unsigned char *)end; c++) {
            if (*c < 32) return false;
        }

        p = *end ? end + 1 : end;
    }

    return true;
}

#if PLATFORM_WINDOWS
static bool is_reserved_windows_component(const char *comp, size_t comp_len) {
    char base[6];
    size_t base_len = 0;

    while (base_len < comp_len && comp[base_len] != '.' && base_len < sizeof(base) - 1) {
        base[base_len] = (char)ascii_toupper_uc((unsigned char)comp[base_len]);
        base_len++;
    }
    base[base_len] = '\0';

    if (base_len == 0) return false;
    if (strcmp(base, "CON") == 0 || strcmp(base, "PRN") == 0 ||
        strcmp(base, "AUX") == 0 || strcmp(base, "NUL") == 0) {
        return true;
    }
    if (base_len == 4 &&
        ((memcmp(base, "COM", 3) == 0) || (memcmp(base, "LPT", 3) == 0)) &&
        base[3] >= '1' && base[3] <= '9') {
        return true;
    }

    return false;
}
#endif

static bool is_safe_archive_path(const char *path) {
    if (!path || !path[0]) return false;

    /* Reject absolute paths */
    if (path[0] == '/' || path[0] == '\\') return false;
    if (strlen(path) >= 2 && path[1] == ':') return false;  /* Windows drive */

    /* FIX #8: Allow "./" prefix for explicit current directory */
    const char *check = path;
    if (check[0] == '.' && (check[1] == '/' || check[1] == '\\')) {
        check += 2;
    }
    if (*check == '\0') return false;

    /* FIX #23: Component-wise validation (rejects ".." components, allows "file..txt") */
    const char *p = check;
    while (*p) {
        const char *end = p;
        while (*end && *end != '/' && *end != '\\') end++;
        size_t comp_len = (size_t)(end - p);

        if (comp_len == 0) return false;
        if (comp_len == 1 && p[0] == '.') return false;
        if (comp_len == 2 && p[0] == '.' && p[1] == '.') return false;

        for (const char *c = p; c < end; c++) {
            if (*c < 32 || *c == '<' || *c == '>' || *c == '|' || *c == '"' || *c == ':')
                return false;
        }

#if PLATFORM_WINDOWS
        if (p[comp_len - 1] == ' ' || p[comp_len - 1] == '.') return false;
        if (is_reserved_windows_component(p, comp_len)) return false;
#endif

        p = *end ? end + 1 : end;
    }

    return strlen(path) < MAX_PATH_LEN;
}

/* ==================== COMPRESSION ==================== */

/**
 * Check if block should be flushed early (adaptive block sizing).
 * Returns true if we should end the current block.
 */
static bool should_flush_block_early(int32_t tok_count, int32_t match_len) {
    if (tok_count < ADAPTIVE_MIN_TOKENS) return false;
    if (match_len >= ADAPTIVE_LONG_MATCH) return true;
    if (match_len <= ADAPTIVE_POOR_MATCH) return true;
    return false;
}

static inline void token_set_literal(Token *tok, uint8_t value) {
    tok->type = 0;
    tok->val = value;
    tok->dist_code = 0;
    tok->dist_extra = 0;
    tok->dist_extra_bits = 0;
}

static inline void token_set_match(Token *tok, int32_t match_len, uint16_t dist) {
    uint8_t d_code;
    uint16_t d_extra;
    uint8_t d_extra_bits;

    dist_to_code_cached(dist, &d_code, &d_extra, &d_extra_bits);

    tok->type = 1;
    tok->val = (uint16_t)((match_len - MIN_MATCH) + 257);
    tok->dist_code = d_code;
    tok->dist_extra = d_extra;
    tok->dist_extra_bits = d_extra_bits;
}

static inline void hash_insert_position(DeflateContext *ctx, uint16_t pos, int32_t bytes_avail) {
    if (bytes_avail < MIN_MATCH) return;

    uint32_t h = (bytes_avail >= 4) ? hash4(&ctx->window[pos]) : hash3(&ctx->window[pos]);
    hash_insert(&ctx->hash_chain, h, pos);
}

static inline void prime_match_at_position(DeflateContext *ctx, uint16_t pos,
                                           int32_t bytes_avail, int32_t *match_pos,
                                           int32_t *match_len) {
    *match_pos = 0;
    *match_len = 0;

    if (bytes_avail < MIN_MATCH) return;

    find_best_match(ctx, pos, bytes_avail, match_pos, match_len);
    hash_insert_position(ctx, pos, bytes_avail);
}

/* Greedy parsing leaves ratio on the table for short matches. Probe the next
 * position and prefer a literal when it unlocks a longer back-reference.
 * Avoid probing across a window wrap because the hash chains are reset there. */
static bool should_emit_literal_for_better_match(const DeflateContext *ctx,
                                                 uint16_t read_pos,
                                                 int32_t bytes_in_window,
                                                 int32_t match_len) {
    if (match_len < MIN_MATCH || match_len >= LAZY_MATCH_MAX_LEN) return false;
    if (bytes_in_window <= MIN_MATCH) return false;
    if (((read_pos + 1) & WINDOW_MASK) == 0) return false;

    int32_t next_match_pos = 0;
    int32_t next_match_len = 0;
    find_best_match(ctx, (uint16_t)((read_pos + 1) & WINDOW_MASK),
                    bytes_in_window - 1, &next_match_pos, &next_match_len);
    (void)next_match_pos;

    return next_match_len > match_len;
}

static int snapshot_read_byte(FILE *fp, const FileList *fl,
                              uint32_t *current_file, uint64_t *current_file_remaining,
                              bool *boundary_crossed, bool *read_error) {
    *boundary_crossed = false;
    *read_error = false;

    while (*current_file < fl->count && *current_file_remaining == 0) {
        (*current_file)++;
        if (*current_file >= fl->count) return EOF;
        *current_file_remaining = fl->entries[*current_file].size;
        *boundary_crossed = true;
    }

    if (*current_file >= fl->count) return EOF;

    int c = FAST_GETC(fp);
    if (c == EOF) {
        *read_error = true;
        return EOF;
    }

    (*current_file_remaining)--;
    return c;
}

/**
 * FIX #1: Renamed variables for clarity.
 * - bytes_in_window: valid lookahead bytes available from current position
 * - write_pos (s): next position to write incoming data
 * - read_pos (r): current position being encoded
 */
static DeflateError compress_file(const char *infile, const char *outfile) {
    FILE *in = NULL;
    FILE *out = NULL;
    DeflateContext *ctx = NULL;
    DeflateError result = DEFLATE_OK;

    if (!is_valid_host_path(infile) || !is_valid_host_path(outfile)) {
        LOG_ERR("Error: Invalid path\n");
        return DEFLATE_ERR_PATH;
    }

    /* Check if input is a directory */
    if (is_directory(infile)) {
        LOG_ERR("Error: '%s' is a directory. This tool compresses single files only.\n", infile);
        LOG_ERR("Hint: Use 'tar' to archive the folder first, then compress the archive.\n");
        return DEFLATE_ERR_PATH;
    }

    in = secure_fopen_read(infile);
    if (!in) {
        perror("Error opening input");
        return DEFLATE_ERR_IO;
    }

    /* FIX #17: Secure file open - refuse to follow symlinks */
    bool is_symlink = false;
    out = secure_fopen_write(outfile, &is_symlink);
    if (!out) {
        if (is_symlink) {
            LOG_ERR("Error: Output path is a symlink (security risk)\n");
            fclose(in);
            return DEFLATE_ERR_PATH;
        }
        perror("Error opening output");
        fclose(in);
        return DEFLATE_ERR_IO;
    }

    if (!write_le32(out, SIG_MAGIC)) {
        result = DEFLATE_ERR_IO;
        goto compress_cleanup;
    }

    ctx = calloc(1, sizeof(DeflateContext));
    if (!ctx) {
        LOG_ERR("Error: Allocation failed\n");
        result = DEFLATE_ERR_MEM;
        goto compress_cleanup;
    }

    init_crc32_tables(&ctx->crc_tables);
    init_dist_lookup();
    hash_init(&ctx->hash_chain);

    ctx->token_buf = calloc(BLOCK_SIZE, sizeof(Token));
    if (!ctx->token_buf) {
        result = DEFLATE_ERR_MEM;
        goto compress_cleanup;
    }

    BitStream bs;
    bs_init(&bs, out, true);
    memset(ctx->window, 0, sizeof(ctx->window));

    /* FIX #1: Clear variable names */
    uint16_t read_pos = 0;       /* Current encoding position in window */
    uint16_t write_pos = 0;      /* Next write position for incoming data */
    int32_t bytes_in_window = 0; /* Valid lookahead bytes from read_pos */

    /* Initial fill: read up to MAX_MATCH bytes */
    for (int i = 0; i < MAX_MATCH; i++) {
        int c = FAST_GETC(in);
        if (c == EOF) break;

        ctx->window[write_pos] = (uint8_t)c;
        ctx->window[write_pos + WINDOW_SIZE] = (uint8_t)c;  /* Mirror for wraparound */
        write_pos = (write_pos + 1) & WINDOW_MASK;
        bytes_in_window++;
        ctx->bytes_in++;

        /* FIX #7: Check input size limit during streaming */
        if (ctx->bytes_in > MAX_INPUT_SIZE) {
            LOG_ERR("Error: Input exceeds %llu byte limit\n",
                    (unsigned long long)MAX_INPUT_SIZE);
            result = DEFLATE_ERR_LIMIT;
            goto compress_cleanup;
        }
    }

    int32_t match_pos = 0, match_len = 0;

    prime_match_at_position(ctx, read_pos, bytes_in_window, &match_pos, &match_len);

    uint32_t crc = 0;
    ctx->bytes_out = 4;  /* Magic header */

    /* FIX #25: Empty file — emit a single block with only EOB so decompressor
     * sees a valid last-block instead of reading CRC bytes as block data. */
    if (bytes_in_window == 0) {
        uint64_t block_freqs[SYMBOL_COUNT] = {0};
        block_freqs[256] = 1;
        result = encode_block(ctx, &bs, block_freqs, 0, true);
        if (result != DEFLATE_OK) goto compress_cleanup;
    }

    /* Main compression loop */
    while (bytes_in_window > 0) {
        int32_t tok_count = 0;
        uint64_t block_freqs[SYMBOL_COUNT] = {0};

        while (tok_count < BLOCK_SIZE && bytes_in_window > 0) {
            /* Clamp match length to available data */
            if (match_len > bytes_in_window) match_len = bytes_in_window;

            if (match_len < MIN_MATCH ||
                should_emit_literal_for_better_match(ctx, read_pos, bytes_in_window, match_len)) {
                /* Emit literal */
                match_len = 1;
                token_set_literal(&ctx->token_buf[tok_count], ctx->window[read_pos]);
                block_freqs[ctx->token_buf[tok_count].val]++;

                uint8_t b = ctx->window[read_pos];
                crc = update_crc32(&ctx->crc_tables, crc, &b, 1);
            } else {
                /* Emit match with RFC 1951 distance coding */
                uint16_t dist = (read_pos - match_pos) & WINDOW_MASK;
                token_set_match(&ctx->token_buf[tok_count], match_len, dist);
                block_freqs[ctx->token_buf[tok_count].val]++;

                crc = update_crc32(&ctx->crc_tables, crc, &ctx->window[read_pos], (size_t)match_len);
            }
            tok_count++;

            /* Advance by match_len bytes */
            int32_t advance = match_len;
            for (int32_t i = 0; i < advance; i++) {
                int c = FAST_GETC(in);

                if (c != EOF) {
                    ctx->window[write_pos] = (uint8_t)c;
                    ctx->window[write_pos + WINDOW_SIZE] = (uint8_t)c;
                    write_pos = (write_pos + 1) & WINDOW_MASK;
                    ctx->bytes_in++;

                    /* FIX #7: Check input size limit */
                    if (ctx->bytes_in > MAX_INPUT_SIZE) {
                        LOG_ERR("Error: Input exceeds %llu byte limit\n",
                                (unsigned long long)MAX_INPUT_SIZE);
                        result = DEFLATE_ERR_LIMIT;
                        goto compress_cleanup;
                    }
                } else {
                    bytes_in_window--;
                }

                read_pos = (read_pos + 1) & WINDOW_MASK;

                /* Reset hash table on window wrap to prevent stale matches */
                if (read_pos == 0) {
                    memset(ctx->hash_chain.head, 0xFF, sizeof(ctx->hash_chain.head));
                }

                if (i + 1 < advance) {
                    hash_insert_position(ctx, read_pos, bytes_in_window);
                } else {
                    /* Find next match only for the next actual parse position. */
                    int32_t new_pos = 0, new_len = 0;
                    prime_match_at_position(ctx, read_pos, bytes_in_window, &new_pos, &new_len);
                    match_pos = new_pos;
                    match_len = new_len;
                }
            }

            /* Check for adaptive early block flush (after advancing) */
            if (should_flush_block_early(tok_count, match_len)) {
                LOG_VERBOSE_MSG("  [Adaptive flush at %d tokens, match_len=%d]\n", tok_count, match_len);
                break;
            }
        }

        /* Encode block */
        block_freqs[256] = 1;
        result = encode_block(ctx, &bs, block_freqs, tok_count, bytes_in_window <= 0);
        if (result != DEFLATE_OK) goto compress_cleanup;
    }

    /* Finalize */
    result = bs_flush(&bs);
    if (result != DEFLATE_OK) goto compress_cleanup;

    if (!write_le32(out, crc)) {
        result = DEFLATE_ERR_IO;
        goto compress_cleanup;
    }

    /* FIX #14: Accurate output size = magic(4) + bitstream + crc(4) */
    ctx->bytes_out = 4 + bs.bytes_written + 4;

    LOG_NORMAL_MSG("Compression Complete\n");
    LOG_NORMAL_MSG("Input:  %llu bytes\n", (unsigned long long)ctx->bytes_in);
    LOG_NORMAL_MSG("Output: %llu bytes\n", (unsigned long long)ctx->bytes_out);
    LOG_NORMAL_MSG("Ratio:  %.2f%%\n", ctx->bytes_in > 0 ?
           (100.0 * (double)ctx->bytes_out / (double)ctx->bytes_in) : 0.0);
    LOG_VERBOSE_MSG("CRC32:  0x%08X\n", crc);

compress_cleanup:
    if (ctx) {
        SAFE_FREE(ctx->token_buf);
        free(ctx);
    }
    if (in) fclose(in);
    if (out) fclose(out);
    return result;
}

/* ==================== FOLDER COMPRESSION ==================== */

/**
 * Compress a directory and all its contents into a single archive.
 * Supports solid mode (-s) where LZ window is NOT reset between files.
 *
 * Archive Format:
 *   [4 bytes]  Magic: 0x50524F46 ('PROF') or 0x50524F53 ('PROS' for solid)
 *   [4 bytes]  File count (uint32_t)
 *   For each file:
 *     [2 bytes]  Path length (uint16_t)
 *     [N bytes]  Path (UTF-8, forward slashes)
 *     [8 bytes]  Original file size (uint64_t)
 *   [Compressed stream - all file contents concatenated]
 *   [4 bytes]  CRC32 of all original data
 */
static DeflateError compress_folder(const char *folder_path, const char *outfile) {
    FILE *out = NULL;
    FILE *in = NULL;
    DeflateContext *ctx = NULL;
    FileList *fl = NULL;
    DeflateError result = DEFLATE_OK;
    char *snapshot_path = NULL;
    uint64_t total_bytes_in = 0;

    if (!is_valid_host_path(folder_path) || !is_valid_host_path(outfile)) {
        LOG_ERR("Error: Invalid path\n");
        return DEFLATE_ERR_PATH;
    }

    LOG_NORMAL_MSG("Snapshotting directory '%s'...\n", folder_path);
    result = build_folder_snapshot(folder_path, outfile, &fl, &snapshot_path, &total_bytes_in);
    if (result != DEFLATE_OK) {
        if (result == DEFLATE_ERR_FORMAT) {
            LOG_ERR("Error: No files found in directory\n");
        } else if (result == DEFLATE_ERR_PATH) {
            LOG_ERR("Error: Failed to snapshot directory safely\n");
        } else if (result == DEFLATE_ERR_LIMIT) {
            /* message already emitted */
        } else {
            LOG_ERR("Error: Failed to snapshot directory\n");
        }
        return result;
    }

    LOG_NORMAL_MSG("Found %u files to compress%s\n", fl->count,
                   g_solid_mode ? " (solid mode)" : "");

    in = secure_fopen_read(snapshot_path);
    if (!in) {
        perror("Error opening snapshot input");
        result = DEFLATE_ERR_IO;
        goto folder_compress_cleanup;
    }

    /* Open output file */
    bool is_symlink = false;
    out = secure_fopen_write(outfile, &is_symlink);
    if (!out) {
        if (is_symlink) {
            LOG_ERR("Error: Output path is a symlink (security risk)\n");
        } else {
            perror("Error opening output");
        }
        filelist_destroy(fl);
        return is_symlink ? DEFLATE_ERR_PATH : DEFLATE_ERR_IO;
    }

    /* Write archive header - use different magic for solid mode */
    uint32_t magic = g_solid_mode ? SIG_MAGIC_SOLID : SIG_MAGIC_FOLDER;
    if (!write_le32(out, magic) || !write_le32(out, fl->count)) {
        result = DEFLATE_ERR_IO;
        goto folder_compress_cleanup;
    }

    /* Write file table */
    for (uint32_t i = 0; i < fl->count; i++) {
        uint16_t path_len = (uint16_t)strlen(fl->entries[i].path);
        if (!write_le16(out, path_len) ||
            fwrite(fl->entries[i].path, 1, path_len, out) != path_len ||
            !write_le64(out, fl->entries[i].size)) {
            result = DEFLATE_ERR_IO;
            goto folder_compress_cleanup;
        }
    }

    /* Initialize compression context */
    ctx = calloc(1, sizeof(DeflateContext));
    if (!ctx) {
        result = DEFLATE_ERR_MEM;
        goto folder_compress_cleanup;
    }

    init_crc32_tables(&ctx->crc_tables);
    init_dist_lookup();
    hash_init(&ctx->hash_chain);

    ctx->token_buf = calloc(BLOCK_SIZE, sizeof(Token));
    if (!ctx->token_buf) {
        result = DEFLATE_ERR_MEM;
        goto folder_compress_cleanup;
    }

    BitStream bs;
    bs_init(&bs, out, true);
    memset(ctx->window, 0, sizeof(ctx->window));

    uint16_t read_pos = 0;
    uint16_t write_pos = 0;
    int32_t bytes_in_window = 0;
    int32_t match_pos = 0, match_len = 0;
    uint32_t crc = 0;
    uint32_t current_file = 0;
    uint64_t current_file_remaining = fl->entries[0].size;

    LOG_VERBOSE_MSG("  Compressing: %s (%llu bytes)\n",
                    fl->entries[0].path,
                    (unsigned long long)fl->entries[0].size);

    /* Process snapshot stream across file boundaries */
    while (current_file < fl->count || bytes_in_window > 0) {
        /* Fill window with data from current/next files */
        while (bytes_in_window < MAX_MATCH && current_file < fl->count) {
            bool read_error = false;
            bool crossed = false;
            int c = snapshot_read_byte(in, fl, &current_file, &current_file_remaining,
                                       &crossed, &read_error);

            if (crossed) {
                LOG_VERBOSE_MSG("  Compressing: %s (%llu bytes)\n",
                                fl->entries[current_file].path,
                                (unsigned long long)fl->entries[current_file].size);
                if (!g_solid_mode) {
                    memset(ctx->hash_chain.head, 0xFF, sizeof(ctx->hash_chain.head));
                }
            }

            if (c == EOF) {
                if (read_error) {
                    LOG_ERR("Error: Snapshot stream truncated unexpectedly\n");
                    result = DEFLATE_ERR_IO;
                    goto folder_compress_cleanup;
                }
                break;
            }

            ctx->window[write_pos] = (uint8_t)c;
            ctx->window[write_pos + WINDOW_SIZE] = (uint8_t)c;
            write_pos = (write_pos + 1) & WINDOW_MASK;
            bytes_in_window++;
        }

        if (bytes_in_window == 0) break;

        /* Find initial match */
        prime_match_at_position(ctx, read_pos, bytes_in_window, &match_pos, &match_len);

        /* Build token block */
        int32_t tok_count = 0;
        uint64_t block_freqs[SYMBOL_COUNT] = {0};
        while (tok_count < BLOCK_SIZE && bytes_in_window > 0) {
            if (match_len > bytes_in_window) match_len = bytes_in_window;

            if (match_len < MIN_MATCH ||
                should_emit_literal_for_better_match(ctx, read_pos, bytes_in_window, match_len)) {
                match_len = 1;
                token_set_literal(&ctx->token_buf[tok_count], ctx->window[read_pos]);
                block_freqs[ctx->token_buf[tok_count].val]++;

                uint8_t b = ctx->window[read_pos];
                crc = update_crc32(&ctx->crc_tables, crc, &b, 1);
            } else {
                uint16_t dist = (read_pos - match_pos) & WINDOW_MASK;
                token_set_match(&ctx->token_buf[tok_count], match_len, dist);
                block_freqs[ctx->token_buf[tok_count].val]++;

                crc = update_crc32(&ctx->crc_tables, crc, &ctx->window[read_pos], (size_t)match_len);
            }
            tok_count++;

            /* Advance by match_len bytes, refilling from files */
            int32_t advance = match_len;
            for (int32_t i = 0; i < advance; i++) {
                bool read_error = false;
                bool crossed = false;
                int c = snapshot_read_byte(in, fl, &current_file, &current_file_remaining,
                                           &crossed, &read_error);

                if (crossed) {
                    LOG_VERBOSE_MSG("  Compressing: %s (%llu bytes)\n",
                                    fl->entries[current_file].path,
                                    (unsigned long long)fl->entries[current_file].size);
                    if (!g_solid_mode) {
                        memset(ctx->hash_chain.head, 0xFF, sizeof(ctx->hash_chain.head));
                    }
                }

                if (c != EOF) {
                    ctx->window[write_pos] = (uint8_t)c;
                    ctx->window[write_pos + WINDOW_SIZE] = (uint8_t)c;
                    write_pos = (write_pos + 1) & WINDOW_MASK;
                } else {
                    if (read_error) {
                        LOG_ERR("Error: Snapshot stream truncated unexpectedly\n");
                        result = DEFLATE_ERR_IO;
                        goto folder_compress_cleanup;
                    }
                    bytes_in_window--;
                }

                read_pos = (read_pos + 1) & WINDOW_MASK;

                if (read_pos == 0) {
                    memset(ctx->hash_chain.head, 0xFF, sizeof(ctx->hash_chain.head));
                }

                if (i + 1 < advance) {
                    hash_insert_position(ctx, read_pos, bytes_in_window);
                } else {
                    int32_t new_pos = 0, new_len = 0;
                    prime_match_at_position(ctx, read_pos, bytes_in_window, &new_pos, &new_len);
                    match_pos = new_pos;
                    match_len = new_len;
                }
            }

            /* Check for adaptive early block flush (after advancing) */
            if (should_flush_block_early(tok_count, match_len)) {
                break;
            }
        }

        /* Encode block */
        bool is_last = (bytes_in_window == 0 && current_file >= fl->count);
        block_freqs[256] = 1;
        result = encode_block(ctx, &bs, block_freqs, tok_count, is_last);
        if (result != DEFLATE_OK) goto folder_compress_cleanup;
    }

    /* FIX #25: If all files were empty, no blocks were emitted — write one */
    if (bs.bytes_written == 0 && bs.bit_count == 0) {
        uint64_t block_freqs[SYMBOL_COUNT] = {0};
        block_freqs[256] = 1;
        result = encode_block(ctx, &bs, block_freqs, 0, true);
        if (result != DEFLATE_OK) goto folder_compress_cleanup;
    }

    /* Finalize */
    result = bs_flush(&bs);
    if (result != DEFLATE_OK) goto folder_compress_cleanup;

    if (!write_le32(out, crc)) {
        result = DEFLATE_ERR_IO;
        goto folder_compress_cleanup;
    }

    uint64_t file_table_size = 0;
    for (uint32_t fi = 0; fi < fl->count; fi++) {
        file_table_size += 2 + strlen(fl->entries[fi].path) + 8;
    }
    ctx->bytes_out = 4 + 4 + file_table_size + bs.bytes_written + 4;

    LOG_NORMAL_MSG("\nFolder Compression Complete%s\n", g_solid_mode ? " (solid)" : "");
    LOG_NORMAL_MSG("Files:  %u\n", fl->count);
    LOG_NORMAL_MSG("Input:  %llu bytes\n", (unsigned long long)total_bytes_in);
    LOG_NORMAL_MSG("Output: %llu bytes\n", (unsigned long long)ctx->bytes_out);
    LOG_NORMAL_MSG("Ratio:  %.2f%%\n", total_bytes_in > 0 ?
           (100.0 * (double)ctx->bytes_out / (double)total_bytes_in) : 0.0);
    LOG_VERBOSE_MSG("CRC32:  0x%08X\n", crc);

folder_compress_cleanup:
    if (ctx) {
        SAFE_FREE(ctx->token_buf);
        free(ctx);
    }
    if (in) fclose(in);
    if (out) fclose(out);
    if (snapshot_path) {
        remove_path_if_exists(snapshot_path);
        SAFE_FREE(snapshot_path);
    }
    filelist_destroy(fl);
    return result;
}

/* ==================== DECOMPRESSION ==================== */

static DeflateError decompress_file(const char *infile, const char *outfile) {
    FILE *in = NULL;
    FILE *out = NULL;
    DeflateContext *ctx = NULL;
    DeflateError result = DEFLATE_OK;
    char *temp_out = NULL;
    bool output_committed = false;

    if (!is_valid_host_path(infile) || !is_valid_host_path(outfile)) {
        LOG_ERR("Error: Invalid path\n");
        return DEFLATE_ERR_PATH;
    }

    /* Check if input is a directory */
    if (is_directory(infile)) {
        LOG_ERR("Error: '%s' is a directory. Cannot decompress a directory.\n", infile);
        return DEFLATE_ERR_PATH;
    }

    in = secure_fopen_read(infile);
    if (!in) {
        perror("Error opening input");
        return DEFLATE_ERR_IO;
    }

    uint32_t magic;
    if (!read_le32(in, &magic) || magic != SIG_MAGIC) {
        LOG_ERR("Error: Invalid file format\n");
        result = DEFLATE_ERR_FORMAT;
        goto decompress_cleanup;
    }

    if (path_is_symlink(outfile)) {
        LOG_ERR("Error: Output path is a symlink (security risk)\n");
        result = DEFLATE_ERR_PATH;
        goto decompress_cleanup;
    }
    if (path_exists(outfile) && path_is_directory_nofollow(outfile)) {
        LOG_ERR("Error: Output path is a directory\n");
        result = DEFLATE_ERR_PATH;
        goto decompress_cleanup;
    }

    out = open_unique_temp_file_sibling(outfile, &temp_out);
    if (!out) {
        perror("Error opening output");
        result = DEFLATE_ERR_IO;
        goto decompress_cleanup;
    }

    ctx = calloc(1, sizeof(DeflateContext));
    if (!ctx) {
        LOG_ERR("Error: Allocation failed\n");
        result = DEFLATE_ERR_MEM;
        goto decompress_cleanup;
    }

    init_crc32_tables(&ctx->crc_tables);
    ctx->decomp_window = calloc(WINDOW_SIZE, 1);
    ctx->decode_table = calloc(FAST_DECODE_SIZE, sizeof(FastDecodeEntry));

    if (!ctx->decomp_window || !ctx->decode_table) {
        result = DEFLATE_ERR_MEM;
        goto decompress_cleanup;
    }

    BitStream bs;
    bs_init(&bs, in, false);
    WriteBuf wb;
    wbuf_init(&wb, out);

    uint16_t window_pos = 0;
    uint32_t calc_crc = 0;
    uint64_t total_output = 0;
    bool last_block = false;
    uint32_t block_count = 0;

    while (!last_block) {
        if (++block_count > MAX_BLOCKS) {
            LOG_ERR("Error: Block count exceeds %u limit\n", (unsigned)MAX_BLOCKS);
            result = DEFLATE_ERR_LIMIT;
            goto decompress_cleanup;
        }

        bool read_err = false;

        int32_t last_bit = bs_read_bit(&bs);
        if (last_bit == -1) {
            LOG_ERR("Error: Unexpected EOF reading block header\n");
            result = DEFLATE_ERR_CORRUPT;
            goto decompress_cleanup;
        }
        last_block = (last_bit != 0);

        uint16_t max_sym = (uint16_t)bs_read_bits(&bs, 16, &read_err);
        if (read_err || max_sym >= SYMBOL_COUNT) {
            LOG_ERR("Error: Invalid symbol count (%u)\n", max_sym);
            result = DEFLATE_ERR_CORRUPT;
            goto decompress_cleanup;
        }

        uint8_t depths[SYMBOL_COUNT] = {0};
        for (int32_t i = 0; i <= max_sym; i += 2) {
            bool err1 = false, err2 = false;
            uint32_t d1 = bs_read_bits(&bs, 4, &err1);
            uint32_t d2 = bs_read_bits(&bs, 4, &err2);

            if (err1 || err2 || d1 > MAX_HUFFMAN_DEPTH || d2 > MAX_HUFFMAN_DEPTH) {
                LOG_ERR("Error: Invalid Huffman depth\n");
                result = DEFLATE_ERR_CORRUPT;
                goto decompress_cleanup;
            }
            depths[i] = (uint8_t)d1;
            if (i + 1 <= max_sym) depths[i + 1] = (uint8_t)d2;
        }

        CanonicalEntry table[SYMBOL_COUNT] = {0};
        int32_t t_count = 0;
        int32_t bl_count[32] = {0};
        uint64_t code = 0;
        uint64_t next_code[32];

        for (int32_t i = 0; i <= max_sym; i++) {
            if (depths[i] > 0) bl_count[depths[i]]++;
        }

        if (!validate_huffman_lengths(bl_count, MAX_HUFFMAN_DEPTH)) {
            LOG_ERR("Error: Oversubscribed Huffman tree\n");
            result = DEFLATE_ERR_CORRUPT;
            goto decompress_cleanup;
        }

        for (int32_t i = 1; i < 32; i++) {
            code = (code + (uint64_t)bl_count[i - 1]) << 1;
            next_code[i] = code;
        }

        for (int32_t i = 0; i <= max_sym; i++) {
            if (depths[i] > 0) {
                table[t_count].sym = (uint16_t)i;
                table[t_count].len = depths[i];
                table[t_count].code = next_code[depths[i]]++;
                t_count++;
            }
        }

        if (!validate_canonical_entries(table, t_count, true)) {
            LOG_ERR("Error: Invalid canonical Huffman table\n");
            result = DEFLATE_ERR_CORRUPT;
            goto decompress_cleanup;
        }

        if (build_fast_decode_table(ctx->decode_table, table, t_count) != DEFLATE_OK) {
            result = DEFLATE_ERR_CORRUPT;
            goto decompress_cleanup;
        }
        build_canonical_decoder(ctx, table, t_count, bl_count);

        /* Decode symbols */
        while (1) {
            int32_t sym = decode_symbol_fast(&bs, ctx);
            if (sym == -1) {
                LOG_ERR("Error: Invalid Huffman symbol\n");
                result = DEFLATE_ERR_CORRUPT;
                goto decompress_cleanup;
            }
            if (sym == 256) break;  /* EOB */

            if (sym < 257) {
                /* Literal byte */
                if (++total_output > MAX_OUTPUT_SIZE) {
                    LOG_ERR("Error: Output limit exceeded\n");
                    result = DEFLATE_ERR_LIMIT;
                    goto decompress_cleanup;
                }

                uint8_t b = (uint8_t)sym;
                wbuf_put(&wb, b);
                if (wb.error) {
                    LOG_ERR("Error: Write failed during decompression\n");
                    result = DEFLATE_ERR_IO;
                    goto decompress_cleanup;
                }
                calc_crc = update_crc32(&ctx->crc_tables, calc_crc, &b, 1);
                ctx->decomp_window[window_pos] = b;
                window_pos = (window_pos + 1) & WINDOW_MASK;
            } else {
                int32_t len = (sym - 257) + 3;

                bool dist_code_err = false;
                uint8_t dist_code = (uint8_t)bs_read_bits(&bs, 5, &dist_code_err);

                if (dist_code_err || dist_code >= NUM_DIST_CODES) {
                    LOG_ERR("Error: Invalid distance code (%u)\n", dist_code);
                    result = DEFLATE_ERR_CORRUPT;
                    goto decompress_cleanup;
                }

                uint16_t dist_extra = 0;
                if (dist_extra_bits[dist_code] > 0) {
                    bool extra_err = false;
                    dist_extra = (uint16_t)bs_read_bits(&bs, dist_extra_bits[dist_code], &extra_err);
                    if (extra_err) {
                        LOG_ERR("Error: Failed to read distance extra bits\n");
                        result = DEFLATE_ERR_CORRUPT;
                        goto decompress_cleanup;
                    }
                }

                int32_t dist = code_to_dist(dist_code, dist_extra);

                if (len < MIN_MATCH || len > MAX_MATCH ||
                    dist == 0 || dist > WINDOW_SIZE || (uint64_t)dist > total_output) {
                    LOG_ERR("Error: Invalid match (len=%d, dist=%d)\n", len, dist);
                    result = DEFLATE_ERR_CORRUPT;
                    goto decompress_cleanup;
                }

                if (total_output + (uint64_t)len > MAX_OUTPUT_SIZE) {
                    LOG_ERR("Error: Output limit exceeded\n");
                    result = DEFLATE_ERR_LIMIT;
                    goto decompress_cleanup;
                }
                total_output += (uint64_t)len;

                uint16_t src = (window_pos - (uint16_t)dist) & WINDOW_MASK;
                uint16_t crc_start = window_pos;
                for (int32_t i = 0; i < len; i++) {
                    uint8_t c = ctx->decomp_window[(src + i) & WINDOW_MASK];
                    wbuf_put(&wb, c);
                    if (wb.error) {
                        LOG_ERR("Error: Write failed during decompression\n");
                        result = DEFLATE_ERR_IO;
                        goto decompress_cleanup;
                    }
                    ctx->decomp_window[window_pos] = c;
                    window_pos = (window_pos + 1) & WINDOW_MASK;
                }
                if (crc_start + len <= WINDOW_SIZE) {
                    calc_crc = update_crc32(&ctx->crc_tables, calc_crc,
                                            &ctx->decomp_window[crc_start], (size_t)len);
                } else {
                    uint16_t first = WINDOW_SIZE - crc_start;
                    calc_crc = update_crc32(&ctx->crc_tables, calc_crc,
                                            &ctx->decomp_window[crc_start], first);
                    calc_crc = update_crc32(&ctx->crc_tables, calc_crc,
                                            &ctx->decomp_window[0], (size_t)len - first);
                }
            }
        }
    }

    if (!wbuf_flush(&wb)) {
        LOG_ERR("Error: Write failed during decompression\n");
        result = DEFLATE_ERR_IO;
        goto decompress_cleanup;
    }

    uint32_t file_crc;
    if (!bs_read_aligned_uint32(&bs, &file_crc)) {
        LOG_ERR("Error: Unexpected EOF reading CRC footer\n");
        result = DEFLATE_ERR_CORRUPT;
        goto decompress_cleanup;
    }

    LOG_NORMAL_MSG("Decompression Complete\n");
    LOG_NORMAL_MSG("Output:       %llu bytes\n", (unsigned long long)total_output);
    LOG_VERBOSE_MSG("Computed CRC: 0x%08X\n", calc_crc);
    LOG_VERBOSE_MSG("File CRC:     0x%08X\n", file_crc);

    if (calc_crc != file_crc) {
        LOG_ERR("FATAL: CRC Mismatch - Data Corrupted!\n");
        result = DEFLATE_ERR_CORRUPT;
        goto decompress_cleanup;
    }

    if (bs_has_trailing_data(&bs)) {
        LOG_ERR("Error: Trailing data after CRC footer\n");
        result = DEFLATE_ERR_CORRUPT;
        goto decompress_cleanup;
    }

    if (fclose(out) != 0) {
        out = NULL;
        LOG_ERR("Error: Failed to finalize output file\n");
        result = DEFLATE_ERR_IO;
        goto decompress_cleanup;
    }
    out = NULL;

    if (!rename_path_atomic(temp_out, outfile, true)) {
        perror("Error finalizing output");
        result = DEFLATE_ERR_IO;
        goto decompress_cleanup;
    }
    output_committed = true;

    LOG_VERBOSE_MSG("Integrity Verified: OK\n");

decompress_cleanup:
    if (ctx) {
        SAFE_FREE(ctx->decode_table);
        SAFE_FREE(ctx->decomp_window);
        free(ctx);
    }
    if (in) fclose(in);
    if (out) fclose(out);
    if (temp_out && !output_committed) {
        remove_path_if_exists(temp_out);
    }
    SAFE_FREE(temp_out);
    return result;
}

/* ==================== FOLDER DECOMPRESSION ==================== */

static DeflateError folder_advance_output_file(FILE **out, WriteBuf *wb,
                                               const char *out_dir, const FileList *fl,
                                               uint32_t *current_file,
                                               uint64_t *current_file_written) {
    while (*current_file < fl->count &&
           *current_file_written >= fl->entries[*current_file].size) {
        if (*out) {
            if (!wbuf_flush(wb)) {
                LOG_ERR("Error: Write failed during decompression\n");
                return DEFLATE_ERR_IO;
            }
            fclose(*out);
            *out = NULL;
        }

        (*current_file)++;
        *current_file_written = 0;

        if (*current_file < fl->count) {
            bool is_symlink = false;
            *out = secure_extract_open(out_dir, fl->entries[*current_file].path, &is_symlink);
            if (!*out) {
                LOG_ERR("Error: Cannot create '%s'%s\n", fl->entries[*current_file].path,
                        is_symlink ? " (symlink in path)" : "");
                return is_symlink ? DEFLATE_ERR_PATH : DEFLATE_ERR_IO;
            }
            wbuf_init(wb, *out);
            LOG_VERBOSE_MSG("  Extracting: %s\n", fl->entries[*current_file].path);
        }
    }

    return DEFLATE_OK;
}

static DeflateError folder_emit_decoded_byte(DeflateContext *ctx, FILE **out, WriteBuf *wb,
                                             const char *out_dir, const FileList *fl,
                                             uint32_t *current_file,
                                             uint64_t *current_file_written,
                                             uint16_t *window_pos, uint32_t *calc_crc,
                                             uint64_t *total_output,
                                             uint64_t expected_total, uint8_t byte) {
    DeflateError result = folder_advance_output_file(out, wb, out_dir, fl,
                                                     current_file, current_file_written);
    if (result != DEFLATE_OK) return result;

    if (*current_file >= fl->count || *total_output >= expected_total) {
        LOG_ERR("Error: Archive contains decoded data beyond declared file sizes\n");
        return DEFLATE_ERR_CORRUPT;
    }

    if (*out) {
        wbuf_put(wb, byte);
        if (wb->error) {
            LOG_ERR("Error: Write failed during decompression\n");
            return DEFLATE_ERR_IO;
        }
        (*current_file_written)++;
    }

    *calc_crc = update_crc32(&ctx->crc_tables, *calc_crc, &byte, 1);
    ctx->decomp_window[*window_pos] = byte;
    *window_pos = (uint16_t)((*window_pos + 1) & WINDOW_MASK);
    (*total_output)++;

    if (*total_output > MAX_OUTPUT_SIZE) {
        LOG_ERR("Error: Output limit exceeded\n");
        return DEFLATE_ERR_LIMIT;
    }

    return DEFLATE_OK;
}

/**
 * Decompress a folder archive into a directory.
 * Supports both solid and non-solid modes (detected from magic).
 */
static DeflateError decompress_folder(const char *infile, const char *out_dir, bool is_solid) {
    FILE *in = NULL;
    FILE *out = NULL;
    DeflateContext *ctx = NULL;
    FileList *fl = NULL;
    DeflateError result = DEFLATE_OK;
    char *stage_dir = NULL;
    bool output_dir_exists = false;
    bool stage_committed = false;

    if (!is_valid_host_path(infile) || !is_valid_host_path(out_dir)) {
        LOG_ERR("Error: Invalid path\n");
        return DEFLATE_ERR_PATH;
    }

    in = secure_fopen_read(infile);
    if (!in) {
        perror("Error opening input");
        return DEFLATE_ERR_IO;
    }

    /* Read and verify magic (already confirmed by caller, but double-check) */
    uint32_t magic;
    if (!read_le32(in, &magic) || (magic != SIG_MAGIC_FOLDER && magic != SIG_MAGIC_SOLID)) {
        LOG_ERR("Error: Not a folder archive\n");
        fclose(in);
        return DEFLATE_ERR_FORMAT;
    }

    /* Read file count */
    uint32_t file_count;
    if (!read_le32(in, &file_count) || file_count > MAX_FILES_IN_ARCHIVE) {
        LOG_ERR("Error: Invalid file count\n");
        fclose(in);
        return DEFLATE_ERR_FORMAT;
    }

    LOG_NORMAL_MSG("Folder Archive: %u files%s\n", file_count, is_solid ? " (solid)" : "");

    /* Create file list and read entries */
    fl = filelist_create();
    if (!fl) {
        fclose(in);
        return DEFLATE_ERR_MEM;
    }

    uint64_t expected_total = 0;
    for (uint32_t i = 0; i < file_count; i++) {
        uint16_t path_len;
        char path[MAX_PATH_LEN];
        uint64_t size;

        if (!read_le16(in, &path_len) || path_len >= MAX_PATH_LEN) {
            LOG_ERR("Error: Invalid path length\n");
            result = DEFLATE_ERR_FORMAT;
            goto folder_decompress_cleanup;
        }

        if (fread(path, 1, path_len, in) != path_len) {
            LOG_ERR("Error: Failed to read path\n");
            result = DEFLATE_ERR_IO;
            goto folder_decompress_cleanup;
        }
        path[path_len] = '\0';

        /* FIX #20: Reject embedded null bytes (path truncation attack) */
        if (strlen(path) != path_len) {
            LOG_ERR("Error: Embedded null byte in archive path\n");
            result = DEFLATE_ERR_PATH;
            goto folder_decompress_cleanup;
        }

        if (!read_le64(in, &size)) {
            LOG_ERR("Error: Failed to read file size\n");
            result = DEFLATE_ERR_IO;
            goto folder_decompress_cleanup;
        }

        if (!is_safe_archive_path(path)) {
            LOG_ERR("Error: Unsafe path in archive: %s\n", path);
            result = DEFLATE_ERR_PATH;
            goto folder_decompress_cleanup;
        }

        normalize_path(path);

        if (size > MAX_OUTPUT_SIZE || expected_total > MAX_OUTPUT_SIZE - size) {
            LOG_ERR("Error: Declared output exceeds %llu byte limit\n",
                    (unsigned long long)MAX_OUTPUT_SIZE);
            result = DEFLATE_ERR_LIMIT;
            goto folder_decompress_cleanup;
        }
        expected_total += size;

        if (!filelist_add(fl, path, size)) {
            LOG_ERR("Error: Too many files in archive\n");
            result = DEFLATE_ERR_LIMIT;
            goto folder_decompress_cleanup;
        }
    }

    result = ensure_unique_archive_paths(fl);
    if (result != DEFLATE_OK) {
        LOG_ERR("Error: Archive contains duplicate output paths\n");
        goto folder_decompress_cleanup;
    }

    result = prepare_output_stage_directory(out_dir, &stage_dir, &output_dir_exists);
    if (result != DEFLATE_OK) {
        goto folder_decompress_cleanup;
    }

    /* Initialize decompression context */
    ctx = calloc(1, sizeof(DeflateContext));
    if (!ctx) {
        result = DEFLATE_ERR_MEM;
        goto folder_decompress_cleanup;
    }

    init_crc32_tables(&ctx->crc_tables);
    ctx->decomp_window = calloc(WINDOW_SIZE, 1);
    ctx->decode_table = calloc(FAST_DECODE_SIZE, sizeof(FastDecodeEntry));

    if (!ctx->decomp_window || !ctx->decode_table) {
        result = DEFLATE_ERR_MEM;
        goto folder_decompress_cleanup;
    }

    BitStream bs;
    bs_init(&bs, in, false);

    uint16_t window_pos = 0;
    uint32_t calc_crc = 0;
    uint64_t total_output = 0;
    bool last_block = false;
    uint32_t block_count = 0;
    WriteBuf wb;
    memset(&wb, 0, sizeof(wb));

    uint32_t current_file = 0;
    uint64_t current_file_written = 0;

    if (file_count > 0) {
        bool is_symlink = false;
        out = secure_extract_open(stage_dir, fl->entries[0].path, &is_symlink);
        if (!out) {
            LOG_ERR("Error: Cannot create '%s'%s\n", fl->entries[0].path,
                    is_symlink ? " (symlink in path)" : "");
            result = is_symlink ? DEFLATE_ERR_PATH : DEFLATE_ERR_IO;
            goto folder_decompress_cleanup;
        }
        wbuf_init(&wb, out);
        LOG_VERBOSE_MSG("  Extracting: %s\n", fl->entries[0].path);
    }

    while (!last_block) {
        if (++block_count > MAX_BLOCKS) {
            LOG_ERR("Error: Block count exceeds limit\n");
            result = DEFLATE_ERR_LIMIT;
            goto folder_decompress_cleanup;
        }

        bool read_err = false;

        int32_t last_bit = bs_read_bit(&bs);
        if (last_bit == -1) {
            LOG_ERR("Error: Unexpected EOF reading block header\n");
            result = DEFLATE_ERR_CORRUPT;
            goto folder_decompress_cleanup;
        }
        last_block = (last_bit != 0);

        uint16_t max_sym = (uint16_t)bs_read_bits(&bs, 16, &read_err);
        if (read_err || max_sym >= SYMBOL_COUNT) {
            LOG_ERR("Error: Invalid symbol count\n");
            result = DEFLATE_ERR_CORRUPT;
            goto folder_decompress_cleanup;
        }

        /* Read code lengths */
        uint8_t depths[SYMBOL_COUNT] = {0};
        for (int32_t i = 0; i <= max_sym; i += 2) {
            bool err1 = false, err2 = false;
            uint32_t d1 = bs_read_bits(&bs, 4, &err1);
            uint32_t d2 = bs_read_bits(&bs, 4, &err2);

            if (err1 || err2 || d1 > MAX_HUFFMAN_DEPTH || d2 > MAX_HUFFMAN_DEPTH) {
                result = DEFLATE_ERR_CORRUPT;
                goto folder_decompress_cleanup;
            }
            depths[i] = (uint8_t)d1;
            if (i + 1 <= max_sym) depths[i + 1] = (uint8_t)d2;
        }

        /* Build Huffman table */
        CanonicalEntry table[SYMBOL_COUNT] = {0};
        int32_t t_count = 0;
        int32_t bl_count[32] = {0};
        uint64_t code = 0;
        uint64_t next_code[32];

        for (int32_t i = 0; i <= max_sym; i++) {
            if (depths[i] > 0) bl_count[depths[i]]++;
        }

        if (!validate_huffman_lengths(bl_count, MAX_HUFFMAN_DEPTH)) {
            result = DEFLATE_ERR_CORRUPT;
            goto folder_decompress_cleanup;
        }

        for (int32_t i = 1; i < 32; i++) {
            code = (code + (uint64_t)bl_count[i - 1]) << 1;
            next_code[i] = code;
        }

        for (int32_t i = 0; i <= max_sym; i++) {
            if (depths[i] > 0) {
                table[t_count].sym = (uint16_t)i;
                table[t_count].len = depths[i];
                table[t_count].code = next_code[depths[i]]++;
                t_count++;
            }
        }

        if (!validate_canonical_entries(table, t_count, true)) {
            result = DEFLATE_ERR_CORRUPT;
            goto folder_decompress_cleanup;
        }

        if (build_fast_decode_table(ctx->decode_table, table, t_count) != DEFLATE_OK) {
            result = DEFLATE_ERR_CORRUPT;
            goto folder_decompress_cleanup;
        }
        build_canonical_decoder(ctx, table, t_count, bl_count);

        /* Decode symbols */
        while (1) {
            int32_t sym = decode_symbol_fast(&bs, ctx);
            if (sym == -1) {
                result = DEFLATE_ERR_CORRUPT;
                goto folder_decompress_cleanup;
            }
            if (sym == 256) break;  /* EOB */

            if (sym < 257) {
                uint8_t b = (uint8_t)sym;
                result = folder_emit_decoded_byte(ctx, &out, &wb, stage_dir, fl,
                                                  &current_file, &current_file_written,
                                                  &window_pos, &calc_crc, &total_output,
                                                  expected_total, b);
                if (result != DEFLATE_OK) goto folder_decompress_cleanup;
            } else {
                int32_t len = (sym - 257) + 3;

                bool dist_code_err = false;
                uint8_t dist_code = (uint8_t)bs_read_bits(&bs, 5, &dist_code_err);

                if (dist_code_err || dist_code >= NUM_DIST_CODES) {
                    result = DEFLATE_ERR_CORRUPT;
                    goto folder_decompress_cleanup;
                }

                uint16_t dist_extra = 0;
                if (dist_extra_bits[dist_code] > 0) {
                    bool extra_err = false;
                    dist_extra = (uint16_t)bs_read_bits(&bs, dist_extra_bits[dist_code], &extra_err);
                    if (extra_err) {
                        result = DEFLATE_ERR_CORRUPT;
                        goto folder_decompress_cleanup;
                    }
                }

                int32_t dist = code_to_dist(dist_code, dist_extra);

                if (len < MIN_MATCH || len > MAX_MATCH ||
                    dist == 0 || dist > WINDOW_SIZE || (uint64_t)dist > total_output) {
                    LOG_ERR("Error: Invalid match (len=%d, dist=%d)\n", len, dist);
                    result = DEFLATE_ERR_CORRUPT;
                    goto folder_decompress_cleanup;
                }

                if (total_output + (uint64_t)len > MAX_OUTPUT_SIZE) {
                    LOG_ERR("Error: Output limit exceeded\n");
                    result = DEFLATE_ERR_LIMIT;
                    goto folder_decompress_cleanup;
                }

                if (total_output > expected_total || (uint64_t)len > expected_total - total_output) {
                    LOG_ERR("Error: Match exceeds declared folder size\n");
                    result = DEFLATE_ERR_CORRUPT;
                    goto folder_decompress_cleanup;
                }

                uint16_t src = (window_pos - (uint16_t)dist) & WINDOW_MASK;
                for (int32_t i = 0; i < len; i++) {
                    uint8_t c = ctx->decomp_window[(src + i) & WINDOW_MASK];

                    result = folder_emit_decoded_byte(ctx, &out, &wb, stage_dir, fl,
                                                      &current_file, &current_file_written,
                                                      &window_pos, &calc_crc, &total_output,
                                                      expected_total, c);
                    if (result != DEFLATE_OK) goto folder_decompress_cleanup;
                }
            }
        }
    }

    result = folder_advance_output_file(&out, &wb, stage_dir, fl,
                                        &current_file, &current_file_written);
    if (result != DEFLATE_OK) goto folder_decompress_cleanup;

    if (total_output != expected_total) {
        LOG_ERR("Error: Folder payload size mismatch (expected %llu, got %llu)\n",
                (unsigned long long)expected_total,
                (unsigned long long)total_output);
        result = DEFLATE_ERR_CORRUPT;
        goto folder_decompress_cleanup;
    }

    uint32_t file_crc;
    if (!bs_read_aligned_uint32(&bs, &file_crc)) {
        LOG_ERR("Error: Unexpected EOF reading CRC footer\n");
        result = DEFLATE_ERR_CORRUPT;
        goto folder_decompress_cleanup;
    }

    LOG_NORMAL_MSG("\nFolder Decompression Complete\n");
    LOG_NORMAL_MSG("Files:        %u\n", file_count);
    LOG_NORMAL_MSG("Output:       %llu bytes\n", (unsigned long long)total_output);
    LOG_VERBOSE_MSG("Computed CRC: 0x%08X\n", calc_crc);
    LOG_VERBOSE_MSG("File CRC:     0x%08X\n", file_crc);

    if (calc_crc != file_crc) {
        LOG_ERR("FATAL: CRC Mismatch - Data Corrupted!\n");
        result = DEFLATE_ERR_CORRUPT;
        goto folder_decompress_cleanup;
    }

    if (bs_has_trailing_data(&bs)) {
        LOG_ERR("Error: Trailing data after CRC footer\n");
        result = DEFLATE_ERR_CORRUPT;
        goto folder_decompress_cleanup;
    }

    if (out) {
        if (!wbuf_flush(&wb)) {
            LOG_ERR("Error: Write failed during decompression\n");
            result = DEFLATE_ERR_IO;
            goto folder_decompress_cleanup;
        }
        fclose(out);
        out = NULL;
    }

    if (!commit_output_stage_directory(stage_dir, out_dir, output_dir_exists)) {
        perror("Error finalizing output directory");
        result = DEFLATE_ERR_IO;
        goto folder_decompress_cleanup;
    }
    stage_committed = true;

    LOG_VERBOSE_MSG("Integrity Verified: OK\n");

folder_decompress_cleanup:
    if (ctx) {
        SAFE_FREE(ctx->decode_table);
        SAFE_FREE(ctx->decomp_window);
        free(ctx);
    }
    if (in) fclose(in);
    if (out) fclose(out);
    if (stage_dir && !stage_committed) {
        remove_tree_recursive(stage_dir);
    }
    SAFE_FREE(stage_dir);
    filelist_destroy(fl);
    return result;
}

/**
 * Auto-detect archive type and decompress accordingly.
 */
static DeflateError decompress_auto(const char *infile, const char *output) {
    FILE *fp = secure_fopen_read(infile);
    if (!fp) {
        perror("Error opening input");
        return DEFLATE_ERR_IO;
    }

    uint32_t magic;
    if (!read_le32(fp, &magic)) {
        fclose(fp);
        LOG_ERR("Error: Cannot read file header\n");
        return DEFLATE_ERR_FORMAT;
    }
    fclose(fp);

    if (magic == SIG_MAGIC) {
        return decompress_file(infile, output);
    } else if (magic == SIG_MAGIC_FOLDER) {
        return decompress_folder(infile, output, false);
    } else if (magic == SIG_MAGIC_SOLID) {
        return decompress_folder(infile, output, true);
    } else {
        LOG_ERR("Error: Unknown archive format (magic: 0x%08X)\n", magic);
        return DEFLATE_ERR_FORMAT;
    }
}

/* ==================== USAGE AND VERSION ==================== */

static void print_version(void) {
    printf("%s version %s\n", MINIDEFLATE_NAME, MINIDEFLATE_VERSION);
    printf("Single-file DEFLATE-style compressor with defensive extraction checks.\n");
    printf("Features: RFC 1951 distance coding, solid archive mode, adaptive blocks, RSA signature verification.\n");
}

static void print_usage(const char *prog) {
    printf("%s - Single-File DEFLATE Compressor v%s\n\n", MINIDEFLATE_NAME, MINIDEFLATE_VERSION);
    printf("Usage: %s [OPTIONS] -c|-d <input> <output>\n", prog);
    printf("       %s [OPTIONS] --verify --sig <signature> --pubkey <public.pem> <archive>\n\n", prog);
    printf("Options:\n");
    printf("  -c, --compress    Compress file or folder\n");
    printf("  -d, --decompress  Decompress to file or folder (auto-detected)\n");
    printf("      --verify      Verify detached RSA/SHA-256 archive signature\n");
    printf("      --sig FILE    Detached signature file (raw PKCS#1 v1.5 signature bytes)\n");
    printf("      --pubkey FILE RSA public key in PEM/DER SubjectPublicKeyInfo or PKCS#1 format\n");
    printf("  -s, --solid       Enable solid compression for folders (better ratio)\n");
    printf("  -q, --quiet       Suppress non-error output\n");
    printf("  -v, --verbose     Enable verbose output\n");
    printf("  -V, --version     Show version information\n");
    printf("  -h, --help        Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -c myfile.txt myfile.proz         # Compress file\n", prog);
    printf("  %s -c myfolder/ archive.proz         # Compress folder\n", prog);
    printf("  %s -c -s myfolder/ archive.proz      # Compress folder (solid mode)\n", prog);
    printf("  %s -d archive.proz output/           # Decompress (existing output dirs allowed if names do not collide)\n", prog);
    printf("  %s -d --sig archive.sig --pubkey public.pem archive.proz output/\n", prog);
    printf("  %s --verify --sig archive.sig --pubkey public.pem archive.proz\n", prog);
    printf("  %s -v -c large.bin large.proz        # Compress with verbose output\n", prog);
    printf("\nLimits: %lluGB input, %lluGB output\n",
           (unsigned long long)(MAX_INPUT_SIZE / (1024ULL * 1024 * 1024)),
           (unsigned long long)(MAX_OUTPUT_SIZE / (1024ULL * 1024 * 1024)));
}

/* ==================== MAIN ==================== */

int main(int argc, char *argv[]) {
    g_log_level = LOG_NORMAL;
    g_solid_mode = false;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    bool do_compress = false;
    bool do_decompress = false;
    bool do_verify = false;
    const char *input_path = NULL;
    const char *output_path = NULL;
    const char *sig_path = NULL;
    const char *pubkey_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--compress") == 0) {
            do_compress = true;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--decompress") == 0) {
            do_decompress = true;
        } else if (strcmp(argv[i], "--verify") == 0) {
            do_verify = true;
        } else if (strcmp(argv[i], "--sig") == 0) {
            if (i + 1 >= argc) {
                LOG_ERR("Error: --sig requires a file path\n");
                return 1;
            }
            sig_path = argv[++i];
        } else if (strcmp(argv[i], "--pubkey") == 0) {
            if (i + 1 >= argc) {
                LOG_ERR("Error: --pubkey requires a file path\n");
                return 1;
            }
            pubkey_path = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--solid") == 0) {
            g_solid_mode = true;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            g_log_level = LOG_QUIET;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_log_level = LOG_VERBOSE;
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            if (!input_path) {
                input_path = argv[i];
            } else if (!output_path) {
                output_path = argv[i];
            } else {
                LOG_ERR("Error: Too many arguments\n");
                return 1;
            }
        } else {
            LOG_ERR("Error: Unknown option '%s'\n", argv[i]);
            return 1;
        }
    }

    if ((sig_path != NULL) != (pubkey_path != NULL)) {
        LOG_ERR("Error: --sig and --pubkey must be used together\n");
        return 1;
    }

    if (do_verify) {
        if (do_compress || do_decompress) {
            LOG_ERR("Error: --verify cannot be combined with -c or -d\n");
            return 1;
        }
        if (!sig_path || !pubkey_path) {
            LOG_ERR("Error: --verify requires --sig and --pubkey\n");
            return 1;
        }
        if (!input_path || output_path) {
            LOG_ERR("Error: --verify requires exactly one archive path\n");
            print_usage(argv[0]);
            return 1;
        }

        DeflateError verify_result = verify_archive_signature(input_path, sig_path, pubkey_path);
        if (verify_result != DEFLATE_OK) {
            LOG_ERR("Error code: %d\n", verify_result);
            return (verify_result < 0) ? -(int)verify_result : (int)verify_result;
        }
        return 0;
    }

    /* Validate arguments */
    if (!do_compress && !do_decompress) {
        LOG_ERR("Error: Must specify -c (compress) or -d (decompress)\n");
        print_usage(argv[0]);
        return 1;
    }

    if (do_compress && do_decompress) {
        LOG_ERR("Error: Cannot specify both -c and -d\n");
        return 1;
    }

    if (!input_path || !output_path) {
        LOG_ERR("Error: Must specify input and output paths\n");
        print_usage(argv[0]);
        return 1;
    }

    if (do_compress && sig_path) {
        LOG_ERR("Error: --sig/--pubkey are only supported with -d or --verify\n");
        return 1;
    }

    DeflateError result;
    if (do_compress) {
        /* Check if input is a directory */
        if (is_directory(input_path)) {
            result = compress_folder(input_path, output_path);
        } else {
            if (g_solid_mode) {
                LOG_VERBOSE_MSG("Note: Solid mode only applies to folder compression\n");
            }
            result = compress_file(input_path, output_path);
        }
    } else {
        if (sig_path) {
            result = verify_archive_signature(input_path, sig_path, pubkey_path);
            if (result != DEFLATE_OK) {
                LOG_ERR("Error code: %d\n", result);
                return (result < 0) ? -(int)result : (int)result;
            }
        }
        /* Auto-detect archive type */
        result = decompress_auto(input_path, output_path);
    }

    if (result != DEFLATE_OK) {
        LOG_ERR("Error code: %d\n", result);
        return (result < 0) ? -(int)result : (int)result;
    }
    return 0;
}
