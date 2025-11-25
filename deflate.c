/**
 * deflate.c - Production-Grade DEFLATE-Style Compressor
 *
 * A secure, high-performance hybrid compressor using LZSS + Canonical Huffman.
 *
 * Build: gcc -O3 -std=c99 -Wall -Wextra deflate.c -o deflate
 *        gcc -O3 -std=c99 -Wall -Wextra -DDEBUG deflate.c -o deflate_debug
 *
 * ============================================================================
 * CORRECTIONS APPLIED (2025-01-24):
 * ----------------------------------------------------------------------------
 * 1. Window bookkeeping: replaced ambiguous 'len' with 'bytes_in_window' for clarity
 * 2. Heap API: heap_push() now returns bool; callers check for overflow
 * 3. Memory cleanup: centralized via goto cleanup labels; no double-free
 * 4. Bit I/O: documented MSB-first ordering; bs_flush handles partial bytes correctly
 * 5. Bounds safety: hash4() guarded for MIN_MATCH bytes; window access clamped
 * 6. bs_read_bits: all callers now pass non-NULL error pointer
 * 7. File size: replaced ftell(long) with uint64_t counter; portable size checks
 * 8. is_safe_path: now allows "./" prefix while still rejecting ".."
 * 9. DEBUG asserts: added compile-time diagnostics under #ifdef DEBUG
 * 10. Huffman cleanup: free_tree called on all error paths; no leaks
 * 11. CRC footer: fail-closed on truncated files; incomplete CRC is fatal error
 * 12. is_safe_path: use 'check' consistently; also reject ':' in path components
 * 13. bs_write: added mode_write assertion to catch misuse in debug builds
 * 14. bytes_out: accurate tracking via BitStream counter (was misleading)
 * 15. heap_destroy: now frees remaining HuffmanNode pointers (was leaking on error)
 * 16. decode_symbol_fast: save/restore bytes_in_buf to handle buffer refill edge case
 * 17. TOCTOU/Symlink: secure_fopen_write() refuses to follow symlinks (lstat/reparse)
 * 18. Ghost buffer: explicit bits_in_ram check + assertion prevents I/O during peek
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/* FIX #17: Platform-specific includes for secure file operations */
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#define PLATFORM_WINDOWS 1
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
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

/* ==================== CONFIGURATION ==================== */

#define WINDOW_SIZE           4096
#define WINDOW_MASK           (WINDOW_SIZE - 1)
#define MAX_MATCH             258
#define MIN_MATCH             3
#define BLOCK_SIZE            32768
#define SYMBOL_COUNT          513
#define IO_BUFFER_SIZE        16384

#define HASH_BITS             15
#define HASH_SIZE             (1 << HASH_BITS)
#define HASH_MASK             (HASH_SIZE - 1)
#define MAX_CHAIN_LENGTH      128

#define FAST_DECODE_BITS      12
#define FAST_DECODE_SIZE      (1 << FAST_DECODE_BITS)

#define SIG_MAGIC             0x50524F5A  /* 'PROZ' - single file */
#define SIG_MAGIC_FOLDER      0x50524F46  /* 'PROF' - folder archive */

#define MAX_PATH_LEN          512
#define MAX_FILES_IN_ARCHIVE  65535

/* FIX #7: Use uint64_t constants for portable 32/64-bit comparisons */
#define MAX_INPUT_SIZE        ((uint64_t)1024 * 1024 * 1024)
#define MAX_OUTPUT_SIZE       ((uint64_t)10 * 1024 * 1024 * 1024)
#define MAX_HUFFMAN_DEPTH     15
#define MAX_DECODE_ITERATIONS 64

typedef enum {
    DEFLATE_OK = 0,
    DEFLATE_ERR_IO = -1,
    DEFLATE_ERR_MEM = -2,
    DEFLATE_ERR_FORMAT = -3,
    DEFLATE_ERR_CORRUPT = -4,
    DEFLATE_ERR_LIMIT = -5,
    DEFLATE_ERR_PATH = -6
} DeflateError;

/* ==================== DATA STRUCTURES ==================== */

typedef struct {
    uint16_t type;   /* 0 = literal, 1 = match */
    uint16_t val;    /* literal byte or length code (257+) */
    uint16_t dist;   /* distance for matches */
} Token;

typedef struct HuffmanNode {
    int32_t sym;
    uint64_t freq;
    struct HuffmanNode *left, *right;
} HuffmanNode;

typedef struct {
    HuffmanNode **nodes;
    int32_t size;
    int32_t capacity;
} MinHeap;

typedef struct {
    uint16_t sym;
    uint8_t len;
    uint64_t code;
} CanonicalEntry;

typedef struct {
    uint16_t symbol;
    uint8_t bits_used;
} FastDecodeEntry;

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

typedef struct {
    uint32_t crc_table[256];
    uint8_t window[WINDOW_SIZE * 2];  /* Doubled for safe lookahead */
    HashChain hash_chain;
    Token *token_buf;
    uint8_t *decomp_window;
    FastDecodeEntry *decode_table;
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

/* ==================== MACROS ==================== */

#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); ptr = NULL; } } while(0)

/* Forward declaration for heap_destroy */
static void free_tree(HuffmanNode *root);

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
    /* Windows: Check for reparse point (symlink/junction) */
    DWORD attrs = GetFileAttributesA(path);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
            *is_symlink = true;
            return NULL;  /* Refuse to follow symlink */
        }
    }
    /* File doesn't exist or is regular - safe to open */
    return fopen(path, "wb");

#else
    /* Unix: Use lstat to detect symlinks (doesn't follow them) */
    struct stat st;
    if (lstat(path, &st) == 0) {
        /* Path exists - check if it's a symlink */
        if (S_ISLNK(st.st_mode)) {
            *is_symlink = true;
            return NULL;  /* Refuse to follow symlink */
        }
        /* Regular file - safe to overwrite */
    }
    /* Either doesn't exist or is regular file - safe to open */
    return fopen(path, "wb");
#endif
}

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

static bool filelist_add(FileList *fl, const char *path, uint64_t size) {
    if (fl->count >= MAX_FILES_IN_ARCHIVE) return false;
    if (strlen(path) >= MAX_PATH_LEN) return false;

    if (fl->count >= fl->capacity) {
        uint32_t new_cap = fl->capacity * 2;
        FileEntry *new_entries = realloc(fl->entries, sizeof(FileEntry) * new_cap);
        if (!new_entries) return false;
        fl->entries = new_entries;
        fl->capacity = new_cap;
    }

    strncpy(fl->entries[fl->count].path, path, MAX_PATH_LEN - 1);
    fl->entries[fl->count].path[MAX_PATH_LEN - 1] = '\0';
    fl->entries[fl->count].size = size;
    fl->count++;
    return true;
}

/* Normalize path separators to forward slashes */
static void normalize_path(char *path) {
    for (char *p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
}

/* Get file size */
static uint64_t get_file_size(const char *path) {
#if PLATFORM_WINDOWS
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
        return ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    }
    return 0;
#else
    struct stat st;
    if (stat(path, &st) == 0) {
        return (uint64_t)st.st_size;
    }
    return 0;
#endif
}

/* Create directory (and parents if needed) */
static bool create_directory_recursive(const char *path) {
    char tmp[MAX_PATH_LEN];
    strncpy(tmp, path, MAX_PATH_LEN - 1);
    tmp[MAX_PATH_LEN - 1] = '\0';

    size_t len = strlen(tmp);
    if (len == 0) return true;

    /* Remove trailing slash */
    if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') {
        tmp[len - 1] = '\0';
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
    return CreateDirectoryA(tmp, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
#endif
}

/* Recursive directory traversal */
#if PLATFORM_WINDOWS
static bool traverse_directory(const char *base_path, const char *rel_path, FileList *fl) {
    char search_path[MAX_PATH_LEN];
    char full_path[MAX_PATH_LEN];
    char new_rel[MAX_PATH_LEN];
    WIN32_FIND_DATAA ffd;
    HANDLE hFind;

    if (rel_path[0]) {
        snprintf(search_path, MAX_PATH_LEN, "%s/%s/*", base_path, rel_path);
    } else {
        snprintf(search_path, MAX_PATH_LEN, "%s/*", base_path);
    }
    normalize_path(search_path);

    /* Convert back to backslash for Windows API */
    char win_search[MAX_PATH_LEN];
    strncpy(win_search, search_path, MAX_PATH_LEN);
    for (char *p = win_search; *p; p++) {
        if (*p == '/') *p = '\\';
    }

    hFind = FindFirstFileA(win_search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }

    do {
        /* Skip . and .. */
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) {
            continue;
        }

        /* Build relative path */
        if (rel_path[0]) {
            snprintf(new_rel, MAX_PATH_LEN, "%s/%s", rel_path, ffd.cFileName);
        } else {
            snprintf(new_rel, MAX_PATH_LEN, "%s", ffd.cFileName);
        }
        normalize_path(new_rel);

        /* Build full path */
        snprintf(full_path, MAX_PATH_LEN, "%s/%s", base_path, new_rel);
        normalize_path(full_path);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into subdirectory */
            if (!traverse_directory(base_path, new_rel, fl)) {
                FindClose(hFind);
                return false;
            }
        } else {
            /* Add file to list */
            uint64_t size = ((uint64_t)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
            if (!filelist_add(fl, new_rel, size)) {
                FindClose(hFind);
                return false;
            }
        }
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
    return true;
}
#else
#include <dirent.h>
#include <errno.h>

static bool traverse_directory(const char *base_path, const char *rel_path, FileList *fl) {
    char dir_path[MAX_PATH_LEN];
    char full_path[MAX_PATH_LEN];
    char new_rel[MAX_PATH_LEN];
    DIR *dir;
    struct dirent *entry;
    struct stat st;

    if (rel_path[0]) {
        snprintf(dir_path, MAX_PATH_LEN, "%s/%s", base_path, rel_path);
    } else {
        snprintf(dir_path, MAX_PATH_LEN, "%s", base_path);
    }

    dir = opendir(dir_path);
    if (!dir) return false;

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build relative path */
        if (rel_path[0]) {
            snprintf(new_rel, MAX_PATH_LEN, "%s/%s", rel_path, entry->d_name);
        } else {
            snprintf(new_rel, MAX_PATH_LEN, "%s", entry->d_name);
        }

        /* Build full path */
        snprintf(full_path, MAX_PATH_LEN, "%s/%s", base_path, new_rel);

        if (stat(full_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            /* Recurse into subdirectory */
            if (!traverse_directory(base_path, new_rel, fl)) {
                closedir(dir);
                return false;
            }
        } else if (S_ISREG(st.st_mode)) {
            /* Add file to list */
            if (!filelist_add(fl, new_rel, (uint64_t)st.st_size)) {
                closedir(dir);
                return false;
            }
        }
    }

    closedir(dir);
    return true;
}
#endif

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

/* ==================== CRC32 ==================== */

static void init_crc32_table(uint32_t *table) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
}

static uint32_t update_crc32(const uint32_t *table, uint32_t crc,
                             const uint8_t *buf, size_t len) {
    uint32_t c = crc ^ 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        c = table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
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
    memset(bs->buffer, 0, IO_BUFFER_SIZE);
}

/**
 * FIX #4: Flush pending bits and buffer to file.
 * Partial byte (< 8 bits) is padded with zeros in LSB positions.
 */
static DeflateError bs_flush(BitStream *bs) {
    if (!bs->mode_write) return DEFLATE_OK;

    /* Flush any remaining bits (pad with zeros) */
    while (bs->bit_count > 0) {
        int32_t bits_to_write = (bs->bit_count >= 8) ? 8 : bs->bit_count;
        int32_t shift = bs->bit_count - bits_to_write;
        uint8_t byte;

        if (bs->bit_count < 8) {
            /* Partial byte: shift left to align MSB, pad LSB with zeros */
            byte = (uint8_t)(bs->bit_acc << (8 - bs->bit_count));
            bs->bit_count = 0;
        } else {
            byte = (uint8_t)((bs->bit_acc >> shift) & 0xFF);
            bs->bit_count -= 8;
        }

        DBG_ASSERT(bs->pos < IO_BUFFER_SIZE);
        if (bs->pos >= IO_BUFFER_SIZE) {
            if (fwrite(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp) != IO_BUFFER_SIZE)
                return DEFLATE_ERR_IO;
            bs->bytes_written += IO_BUFFER_SIZE;  /* FIX #14 */
            bs->pos = 0;
        }
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

    bs->bit_acc = (bs->bit_acc << bits) | (val & ((1ULL << bits) - 1));
    bs->bit_count += bits;

    while (bs->bit_count >= 8) {
        bs->bit_count -= 8;
        uint8_t byte = (uint8_t)((bs->bit_acc >> bs->bit_count) & 0xFF);

        DBG_ASSERT(bs->pos < IO_BUFFER_SIZE);
        if (bs->pos >= IO_BUFFER_SIZE) {
            if (fwrite(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp) != IO_BUFFER_SIZE)
                return DEFLATE_ERR_IO;
            bs->bytes_written += IO_BUFFER_SIZE;  /* FIX #14 */
            bs->pos = 0;
        }
        bs->buffer[bs->pos++] = byte;
    }
    return DEFLATE_OK;
}

/**
 * Read single bit (MSB-first). Returns -1 on EOF.
 */
static int32_t bs_read_bit(BitStream *bs) {
    if (bs->bit_count == 0) {
        if (bs->pos >= bs->bytes_in_buf) {
            bs->bytes_in_buf = fread(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
            bs->pos = 0;
            if (bs->bytes_in_buf == 0) return -1;
        }
        bs->bit_acc = bs->buffer[bs->pos++];
        bs->bit_count = 8;
    }
    int32_t bit = (bs->bit_acc >> 7) & 1;
    bs->bit_acc <<= 1;
    bs->bit_count--;
    return bit;
}

/**
 * FIX #6: Read multiple bits with mandatory error reporting.
 * Caller MUST provide non-NULL error pointer.
 */
static uint32_t bs_read_bits(BitStream *bs, int32_t bits, bool *error) {
    DBG_ASSERT(error != NULL);  /* FIX #6: error must not be NULL */
    *error = false;

    if (bits < 0 || bits > 32) {
        *error = true;
        return 0;
    }

    uint32_t val = 0;
    for (int32_t i = 0; i < bits; i++) {
        int32_t b = bs_read_bit(bs);
        if (b == -1) {
            *error = true;
            return 0;
        }
        val = (val << 1) | (uint32_t)b;
    }
    return val;
}

/**
 * Read 32-bit value at byte boundary (little-endian).
 *
 * INVARIANT: Discards any pending partial byte by setting bit_count = 0.
 * This is correct because the encoder pads to byte boundary in bs_flush
 * before writing the CRC footer. Caller must ensure the stream is at a
 * known byte-aligned position (e.g., after EOB symbol).
 */
static bool bs_read_aligned_uint32(BitStream *bs, uint32_t *out) {
    bs->bit_count = 0;  /* Discard partial byte - see invariant above */
    uint32_t res = 0;
    for (int i = 0; i < 4; i++) {
        if (bs->pos >= bs->bytes_in_buf) {
            bs->bytes_in_buf = fread(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
            bs->pos = 0;
            if (bs->bytes_in_buf == 0) {
                *out = res;
                return false;  /* Incomplete read */
            }
        }
        res |= ((uint32_t)bs->buffer[bs->pos++] << (i * 8));
    }
    *out = res;
    return true;
}

/* ==================== HASH CHAIN LZSS ==================== */

/**
 * FIX #5: hash4 requires at least MIN_MATCH (3) valid bytes.
 * Caller must ensure data points to >= 3 bytes.
 */
static inline uint32_t hash4(const uint8_t *data) {
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
 */
static void find_best_match(const DeflateContext *ctx, uint16_t pos,
                            int32_t bytes_avail, int32_t *match_pos,
                            int32_t *match_len) {
    *match_len = 0;
    *match_pos = 0;

    /* FIX #5: Need MIN_MATCH bytes for hash and comparison */
    if (bytes_avail < MIN_MATCH || pos >= WINDOW_SIZE) return;

    /* FIX #5: Bounds check before hash4 call */
    if (pos + MIN_MATCH > WINDOW_SIZE * 2) return;

    uint32_t hash = hash4(&ctx->window[pos]);
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

    while (chain != 0xFFFF && chain < WINDOW_SIZE && chain_count++ < MAX_CHAIN_LENGTH) {
        int32_t distance = (pos - chain) & WINDOW_MASK;
        if (distance == 0) break;

        /* Skip stale entries */
        if (distance > WINDOW_SIZE - MAX_MATCH) {
            chain = ctx->hash_chain.prev[chain];
            continue;
        }

        /* FIX #5: Bounds check for chain position */
        int32_t chain_max_len = max_len;
        if (chain + chain_max_len > WINDOW_SIZE * 2) {
            chain_max_len = WINDOW_SIZE * 2 - chain;
        }
        if (chain_max_len < MIN_MATCH) {
            chain = ctx->hash_chain.prev[chain];
            continue;
        }

        /* Quick rejection test */
        if (ctx->window[chain] == first && ctx->window[chain + 1] == second) {
            int32_t len = 2;
            int32_t safe_max = (chain_max_len < max_len) ? chain_max_len : max_len;

            /* FIX #5: Additional bounds assertion in debug mode */
            DBG_ASSERT(chain + safe_max <= WINDOW_SIZE * 2);
            DBG_ASSERT(pos + safe_max <= WINDOW_SIZE * 2);

            while (len < safe_max && ctx->window[chain + len] == ctx->window[pos + len]) {
                len++;
            }

            if (len > *match_len) {
                *match_len = len;
                *match_pos = chain;
                if (len >= MAX_MATCH) break;
            }
        }
        chain = ctx->hash_chain.prev[chain];
    }
}

/* ==================== HUFFMAN CODING ==================== */

static MinHeap* heap_create(int32_t cap) {
    MinHeap *h = malloc(sizeof(MinHeap));
    if (!h) return NULL;
    h->nodes = malloc(sizeof(HuffmanNode*) * (size_t)cap);
    if (!h->nodes) {
        free(h);
        return NULL;
    }
    h->size = 0;
    h->capacity = cap;
    return h;
}

/**
 * FIX #15: Free any HuffmanNode pointers still in heap on error cleanup.
 * Previously only freed the array, leaking nodes on early exit.
 */
static void heap_destroy(MinHeap *h) {
    if (!h) return;
    /* Free any nodes remaining in heap (e.g., after allocation failure) */
    for (int32_t i = 0; i < h->size; i++) {
        free_tree(h->nodes[i]);  /* Recursively frees subtrees if any */
    }
    free(h->nodes);
    free(h);
}

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

static void free_tree(HuffmanNode *root) {
    if (!root) return;
    free_tree(root->left);
    free_tree(root->right);
    free(root);
}

/**
 * FIX #3 & #10: Centralized cleanup via goto; no memory leaks.
 */
static DeflateError build_huffman_codes(const uint64_t *freqs, CanonicalEntry *table,
                                        uint8_t *depths, uint16_t *max_sym_out) {
    MinHeap *h = NULL;
    HuffmanNode *root = NULL;
    DeflateError result = DEFLATE_OK;

    h = heap_create(SYMBOL_COUNT * 2);
    if (!h) return DEFLATE_ERR_MEM;

    memset(depths, 0, SYMBOL_COUNT);
    *max_sym_out = 0;

    /* Build initial leaf nodes */
    for (int32_t i = 0; i < SYMBOL_COUNT; i++) {
        if (freqs[i] > 0) {
            HuffmanNode *n = malloc(sizeof(HuffmanNode));
            if (!n) {
                result = DEFLATE_ERR_MEM;
                goto cleanup;
            }
            n->sym = i;
            n->freq = freqs[i];
            n->left = n->right = NULL;

            /* FIX #2: Check heap_push return value */
            if (!heap_push(h, n)) {
                free(n);
                result = DEFLATE_ERR_MEM;
                goto cleanup;
            }
            *max_sym_out = (uint16_t)i;
        }
    }

    if (h->size == 0) {
        result = DEFLATE_ERR_FORMAT;
        goto cleanup;
    }

    /* Handle single-symbol case */
    if (h->size == 1) {
        HuffmanNode *n = heap_pop(h);
        HuffmanNode *dummy = malloc(sizeof(HuffmanNode));
        HuffmanNode *parent = malloc(sizeof(HuffmanNode));

        if (!dummy || !parent) {
            free_tree(n);
            free(dummy);
            free(parent);
            result = DEFLATE_ERR_MEM;
            goto cleanup;
        }

        dummy->sym = (n->sym == 0) ? 1 : 0;
        dummy->freq = 0;
        dummy->left = dummy->right = NULL;

        parent->sym = -1;
        parent->freq = n->freq;
        parent->left = n;
        parent->right = dummy;

        if (!heap_push(h, parent)) {
            free_tree(parent);  /* Frees n and dummy too */
            result = DEFLATE_ERR_MEM;
            goto cleanup;
        }
    }

    /* Build Huffman tree */
    while (h->size > 1) {
        HuffmanNode *l = heap_pop(h);
        HuffmanNode *r = heap_pop(h);
        HuffmanNode *parent = malloc(sizeof(HuffmanNode));

        if (!parent) {
            free_tree(l);
            free_tree(r);
            result = DEFLATE_ERR_MEM;
            goto cleanup;
        }

        parent->sym = -1;
        parent->freq = l->freq + r->freq;
        parent->left = l;
        parent->right = r;

        if (!heap_push(h, parent)) {
            free_tree(parent);
            result = DEFLATE_ERR_MEM;
            goto cleanup;
        }
    }

    root = heap_pop(h);
    get_tree_depths(root, 0, depths);

    /* Build canonical codes */
    {
        int32_t bl_count[32] = {0};
        uint64_t code = 0;
        uint64_t next_code[32];

        for (int32_t i = 0; i < SYMBOL_COUNT; i++) {
            if (depths[i] > 0) {
                if (depths[i] > MAX_HUFFMAN_DEPTH) {
                    result = DEFLATE_ERR_FORMAT;
                    goto cleanup;
                }
                bl_count[depths[i]]++;
            }
        }

        for (int32_t i = 1; i < 32; i++) {
            code = (code + bl_count[i - 1]) << 1;
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
    free_tree(root);
    heap_destroy(h);
    return result;
}

static DeflateError encode_block(DeflateContext *ctx, BitStream *bs,
                                 int32_t token_count, bool is_last) {
    uint64_t freqs[SYMBOL_COUNT] = {0};

    for (int32_t i = 0; i < token_count; i++) {
        if (ctx->token_buf[i].val >= SYMBOL_COUNT) return DEFLATE_ERR_CORRUPT;
        freqs[ctx->token_buf[i].val]++;
    }
    freqs[256] = 1;  /* EOB marker */

    CanonicalEntry table[SYMBOL_COUNT] = {0};
    uint8_t depths[SYMBOL_COUNT];
    uint16_t max_sym = 0;

    DeflateError err = build_huffman_codes(freqs, table, depths, &max_sym);
    if (err != DEFLATE_OK) return err;

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
            if ((err = bs_write(bs, ctx->token_buf[i].dist, 12)) != DEFLATE_OK)
                return err;
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
            decode_table[idx].symbol = table[i].sym;
            decode_table[idx].bits_used = len;
        }
    }
    return DEFLATE_OK;
}

/**
 * FIX #16: Save/restore bytes_in_buf along with other state during peek.
 * FIX #18: Explicit guard to ensure NO buffer refill occurs during peek.
 *
 * SECURITY NOTE (Ghost Buffer Prevention):
 * The fast-path peek reads bits speculatively then restores state. If a buffer
 * refill (fread) occurred during peek, the buffer contents change and restoration
 * would leave us reading from wrong data. The available_bits check ensures we
 * have enough bits IN RAM to complete the peek without I/O.
 */
static int32_t decode_symbol_fast(BitStream *bs, const FastDecodeEntry *decode_table,
                                  const CanonicalEntry *table, int32_t t_count) {
    /*
     * FIX #18: Calculate bits available WITHOUT triggering I/O.
     * This is the critical security invariant: we only enter fast path
     * if all required bits are already in memory (bit_acc + buffer).
     */
    int32_t bits_in_ram = bs->bit_count + 8 * (int32_t)(bs->bytes_in_buf - bs->pos);

    /* SECURITY: Only proceed if we can peek without disk I/O */
    if (bits_in_ram >= FAST_DECODE_BITS) {
        uint32_t peek = 0;

        /* FIX #16: Save ALL mutable state that bs_read_bit can modify */
        uint32_t orig_bit_count = (uint32_t)bs->bit_count;
        uint64_t orig_bit_acc = bs->bit_acc;
        size_t orig_pos = bs->pos;
        size_t orig_bytes_in_buf = bs->bytes_in_buf;

        for (int32_t i = 0; i < FAST_DECODE_BITS; i++) {
            int32_t b = bs_read_bit(bs);
            /*
             * FIX #18: If we get EOF here, something is wrong - we calculated
             * that we had enough bits. This indicates buffer corruption.
             */
            if (b == -1) {
                DBG_PRINTF("Ghost buffer: unexpected EOF during peek\n");
                return -1;
            }
            peek = (peek << 1) | (uint32_t)b;
        }

        /*
         * FIX #18: Verify no buffer refill occurred (defense in depth).
         * If bytes_in_buf changed, a refill happened and our state is corrupt.
         */
        DBG_ASSERT(bs->bytes_in_buf == orig_bytes_in_buf &&
                   "Ghost buffer detected: refill during peek!");

        if (peek < FAST_DECODE_SIZE) {
            FastDecodeEntry entry = decode_table[peek];
            if (entry.bits_used > 0 && entry.bits_used <= FAST_DECODE_BITS) {
                /* Restore state and consume only needed bits */
                bs->bit_count = (int32_t)orig_bit_count;
                bs->bit_acc = orig_bit_acc;
                bs->pos = orig_pos;
                bs->bytes_in_buf = orig_bytes_in_buf;
                for (int32_t i = 0; i < entry.bits_used; i++) bs_read_bit(bs);
                return entry.symbol;
            }
        }

        /* Restore state for slow path */
        bs->bit_count = (int32_t)orig_bit_count;
        bs->bit_acc = orig_bit_acc;
        bs->pos = orig_pos;
        bs->bytes_in_buf = orig_bytes_in_buf;
    }

    /* Slow path: bit-by-bit decoding */
    uint64_t curr_code = 0;
    int32_t curr_len = 0;

    for (int32_t iter = 0; iter < MAX_DECODE_ITERATIONS; iter++) {
        int32_t b = bs_read_bit(bs);
        if (b == -1) return -1;

        curr_code = (curr_code << 1) | (uint64_t)b;
        curr_len++;

        if (curr_len > MAX_HUFFMAN_DEPTH) return -1;

        for (int32_t k = 0; k < t_count; k++) {
            if (table[k].len == curr_len && table[k].code == curr_code) {
                return table[k].sym;
            }
        }
    }
    return -1;
}

/* ==================== PATH SECURITY ==================== */

/**
 * FIX #8: Allows "./" prefix (current directory) but rejects "..".
 * FIX #12: Use 'check' consistently after skipping "./" prefix.
 */
static bool is_safe_path(const char *path) {
    if (!path || !path[0]) return false;

    /* Reject absolute paths */
    if (path[0] == '/' || path[0] == '\\') return false;
    if (strlen(path) >= 2 && path[1] == ':') return false;  /* Windows drive */

    /* FIX #8: Allow "./" prefix for explicit current directory */
    const char *check = path;
    if (check[0] == '.' && (check[1] == '/' || check[1] == '\\')) {
        check += 2;
    }

    /* FIX #12: Reject parent directory traversal - use 'check' not 'path' */
    if (strstr(check, "..") != NULL) return false;

    /* Reject dangerous characters (including ':' for non-drive contexts) */
    for (const char *p = check; *p; p++) {
        if (*p < 32 || *p == '<' || *p == '>' || *p == '|' || *p == '"' || *p == ':')
            return false;
    }

    return strlen(path) <= 255;
}

/* ==================== COMPRESSION ==================== */

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

    if (!is_safe_path(infile) || !is_safe_path(outfile)) {
        fprintf(stderr, "Error: Invalid file path\n");
        return DEFLATE_ERR_PATH;
    }

    /* Check if input is a directory */
    if (is_directory(infile)) {
        fprintf(stderr, "Error: '%s' is a directory. This tool compresses single files only.\n", infile);
        fprintf(stderr, "Hint: Use 'tar' to archive the folder first, then compress the archive.\n");
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
            fprintf(stderr, "Error: Output path is a symlink (security risk)\n");
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
        fprintf(stderr, "Error: Allocation failed\n");
        result = DEFLATE_ERR_MEM;
        goto compress_cleanup;
    }

    init_crc32_table(ctx->crc_table);
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
        int c = fgetc(in);
        if (c == EOF) break;

        ctx->window[write_pos] = (uint8_t)c;
        ctx->window[write_pos + WINDOW_SIZE] = (uint8_t)c;  /* Mirror for wraparound */
        write_pos = (write_pos + 1) & WINDOW_MASK;
        bytes_in_window++;
        ctx->bytes_in++;

        /* FIX #7: Check input size limit during streaming */
        if (ctx->bytes_in > MAX_INPUT_SIZE) {
            fprintf(stderr, "Error: Input exceeds %llu byte limit\n",
                    (unsigned long long)MAX_INPUT_SIZE);
            result = DEFLATE_ERR_LIMIT;
            goto compress_cleanup;
        }
    }

    int32_t match_pos = 0, match_len = 0;

    /* FIX #5: Only call find_best_match if we have enough bytes */
    if (bytes_in_window >= MIN_MATCH) {
        find_best_match(ctx, read_pos, bytes_in_window, &match_pos, &match_len);
        hash_insert(&ctx->hash_chain, hash4(&ctx->window[read_pos]), read_pos);
    }

    uint32_t crc = 0;
    ctx->bytes_out = 4;  /* Magic header */

    /* Main compression loop */
    while (bytes_in_window > 0) {
        int32_t tok_count = 0;

        while (tok_count < BLOCK_SIZE && bytes_in_window > 0) {
            /* Clamp match length to available data */
            if (match_len > bytes_in_window) match_len = bytes_in_window;

            if (match_len < MIN_MATCH) {
                /* Emit literal */
                match_len = 1;
                ctx->token_buf[tok_count].type = 0;
                ctx->token_buf[tok_count].val = ctx->window[read_pos];
                ctx->token_buf[tok_count].dist = 0;

                uint8_t b = ctx->window[read_pos];
                crc = update_crc32(ctx->crc_table, crc, &b, 1);
            } else {
                /* Emit match */
                ctx->token_buf[tok_count].type = 1;
                ctx->token_buf[tok_count].val = (uint16_t)((match_len - 3) + 257);
                ctx->token_buf[tok_count].dist = (read_pos - match_pos) & WINDOW_MASK;

                crc = update_crc32(ctx->crc_table, crc, &ctx->window[read_pos], (size_t)match_len);
            }
            tok_count++;

            /* Advance by match_len bytes */
            int32_t advance = match_len;
            for (int32_t i = 0; i < advance; i++) {
                int c = fgetc(in);

                if (c != EOF) {
                    ctx->window[write_pos] = (uint8_t)c;
                    ctx->window[write_pos + WINDOW_SIZE] = (uint8_t)c;
                    write_pos = (write_pos + 1) & WINDOW_MASK;
                    ctx->bytes_in++;

                    /* FIX #7: Check input size limit */
                    if (ctx->bytes_in > MAX_INPUT_SIZE) {
                        fprintf(stderr, "Error: Input exceeds %llu byte limit\n",
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
                    for (int32_t j = 0; j < HASH_SIZE; j++) {
                        ctx->hash_chain.head[j] = 0xFFFF;
                    }
                }

                /* Find next match */
                int32_t new_pos = 0, new_len = 0;
                if (bytes_in_window >= MIN_MATCH) {
                    find_best_match(ctx, read_pos, bytes_in_window, &new_pos, &new_len);
                    hash_insert(&ctx->hash_chain, hash4(&ctx->window[read_pos]), read_pos);
                }
                match_pos = new_pos;
                match_len = new_len;
            }
        }

        /* Encode block */
        result = encode_block(ctx, &bs, tok_count, bytes_in_window <= 0);
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

    printf("Compression Complete\n");
    printf("Input:  %llu bytes\n", (unsigned long long)ctx->bytes_in);
    printf("Output: %llu bytes\n", (unsigned long long)ctx->bytes_out);
    printf("Ratio:  %.2f%%\n", ctx->bytes_in > 0 ?
           (100.0 * (double)ctx->bytes_out / (double)ctx->bytes_in) : 0.0);
    printf("CRC32:  0x%08X\n", crc);

compress_cleanup:
    SAFE_FREE(ctx->token_buf);
    if (ctx) free(ctx);
    if (in) fclose(in);
    if (out) fclose(out);
    return result;
}

/* ==================== FOLDER COMPRESSION ==================== */

/**
 * Compress a directory and all its contents into a single archive.
 *
 * Archive Format:
 *   [4 bytes]  Magic: 0x50524F46 ('PROF')
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

    if (!is_safe_path(outfile)) {
        fprintf(stderr, "Error: Invalid output path\n");
        return DEFLATE_ERR_PATH;
    }

    /* Traverse directory and collect files */
    fl = filelist_create();
    if (!fl) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return DEFLATE_ERR_MEM;
    }

    printf("Scanning directory '%s'...\n", folder_path);
    if (!traverse_directory(folder_path, "", fl)) {
        fprintf(stderr, "Error: Failed to traverse directory\n");
        filelist_destroy(fl);
        return DEFLATE_ERR_IO;
    }

    if (fl->count == 0) {
        fprintf(stderr, "Error: No files found in directory\n");
        filelist_destroy(fl);
        return DEFLATE_ERR_FORMAT;
    }

    printf("Found %u files to compress\n", fl->count);

    /* Open output file */
    bool is_symlink = false;
    out = secure_fopen_write(outfile, &is_symlink);
    if (!out) {
        if (is_symlink) {
            fprintf(stderr, "Error: Output path is a symlink (security risk)\n");
        } else {
            perror("Error opening output");
        }
        filelist_destroy(fl);
        return DEFLATE_ERR_IO;
    }

    /* Write archive header */
    if (!write_le32(out, SIG_MAGIC_FOLDER) || !write_le32(out, fl->count)) {
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

    init_crc32_table(ctx->crc_table);
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
    uint64_t total_bytes_in = 0;
    uint32_t current_file = 0;
    uint64_t current_file_remaining = 0;
    char full_path[MAX_PATH_LEN];

    /* Process all files */
    while (current_file < fl->count || bytes_in_window > 0) {
        /* Open next file if needed */
        if (!in && current_file < fl->count) {
            snprintf(full_path, MAX_PATH_LEN, "%s/%s", folder_path, fl->entries[current_file].path);
            normalize_path(full_path);

            in = secure_fopen_read(full_path);
            if (!in) {
                fprintf(stderr, "Error: Cannot open file '%s'\n", full_path);
                result = DEFLATE_ERR_IO;
                goto folder_compress_cleanup;
            }
            current_file_remaining = fl->entries[current_file].size;
            printf("  Compressing: %s (%llu bytes)\n",
                   fl->entries[current_file].path,
                   (unsigned long long)current_file_remaining);
        }

        /* Fill window with data from current/next files */
        while (bytes_in_window < MAX_MATCH && (in || current_file < fl->count)) {
            int c = EOF;

            if (in) {
                c = fgetc(in);
                if (c != EOF) {
                    current_file_remaining--;
                }
            }

            if (c == EOF) {
                /* End of current file, move to next */
                if (in) {
                    fclose(in);
                    in = NULL;
                    current_file++;
                }

                /* Open next file */
                if (current_file < fl->count) {
                    snprintf(full_path, MAX_PATH_LEN, "%s/%s", folder_path, fl->entries[current_file].path);
                    normalize_path(full_path);

                    in = secure_fopen_read(full_path);
                    if (!in) {
                        fprintf(stderr, "Error: Cannot open file '%s'\n", full_path);
                        result = DEFLATE_ERR_IO;
                        goto folder_compress_cleanup;
                    }
                    current_file_remaining = fl->entries[current_file].size;
                    printf("  Compressing: %s (%llu bytes)\n",
                           fl->entries[current_file].path,
                           (unsigned long long)current_file_remaining);
                    continue;
                } else {
                    break;
                }
            }

            ctx->window[write_pos] = (uint8_t)c;
            ctx->window[write_pos + WINDOW_SIZE] = (uint8_t)c;
            write_pos = (write_pos + 1) & WINDOW_MASK;
            bytes_in_window++;
            total_bytes_in++;

            if (total_bytes_in > MAX_INPUT_SIZE) {
                fprintf(stderr, "Error: Total input exceeds %llu byte limit\n",
                        (unsigned long long)MAX_INPUT_SIZE);
                result = DEFLATE_ERR_LIMIT;
                goto folder_compress_cleanup;
            }
        }

        if (bytes_in_window == 0) break;

        /* Find initial match */
        if (bytes_in_window >= MIN_MATCH) {
            find_best_match(ctx, read_pos, bytes_in_window, &match_pos, &match_len);
            hash_insert(&ctx->hash_chain, hash4(&ctx->window[read_pos]), read_pos);
        }

        /* Build token block */
        int32_t tok_count = 0;
        while (tok_count < BLOCK_SIZE && bytes_in_window > 0) {
            if (match_len > bytes_in_window) match_len = bytes_in_window;

            if (match_len < MIN_MATCH) {
                match_len = 1;
                ctx->token_buf[tok_count].type = 0;
                ctx->token_buf[tok_count].val = ctx->window[read_pos];
                ctx->token_buf[tok_count].dist = 0;

                uint8_t b = ctx->window[read_pos];
                crc = update_crc32(ctx->crc_table, crc, &b, 1);
            } else {
                ctx->token_buf[tok_count].type = 1;
                ctx->token_buf[tok_count].val = (uint16_t)((match_len - 3) + 257);
                ctx->token_buf[tok_count].dist = (read_pos - match_pos) & WINDOW_MASK;

                crc = update_crc32(ctx->crc_table, crc, &ctx->window[read_pos], (size_t)match_len);
            }
            tok_count++;

            /* Advance by match_len bytes, refilling from files */
            int32_t advance = match_len;
            for (int32_t i = 0; i < advance; i++) {
                int c = EOF;

                /* Try to read from current file */
                if (in) {
                    c = fgetc(in);
                    if (c != EOF) current_file_remaining--;
                }

                if (c == EOF && in) {
                    fclose(in);
                    in = NULL;
                    current_file++;

                    /* Open next file */
                    if (current_file < fl->count) {
                        snprintf(full_path, MAX_PATH_LEN, "%s/%s", folder_path, fl->entries[current_file].path);
                        normalize_path(full_path);
                        in = secure_fopen_read(full_path);
                        if (in) {
                            current_file_remaining = fl->entries[current_file].size;
                            printf("  Compressing: %s (%llu bytes)\n",
                                   fl->entries[current_file].path,
                                   (unsigned long long)current_file_remaining);
                            c = fgetc(in);
                            if (c != EOF) current_file_remaining--;
                        }
                    }
                }

                if (c != EOF) {
                    ctx->window[write_pos] = (uint8_t)c;
                    ctx->window[write_pos + WINDOW_SIZE] = (uint8_t)c;
                    write_pos = (write_pos + 1) & WINDOW_MASK;
                    total_bytes_in++;
                } else {
                    bytes_in_window--;
                }

                read_pos = (read_pos + 1) & WINDOW_MASK;

                if (read_pos == 0) {
                    for (int32_t j = 0; j < HASH_SIZE; j++) {
                        ctx->hash_chain.head[j] = 0xFFFF;
                    }
                }

                int32_t new_pos = 0, new_len = 0;
                if (bytes_in_window >= MIN_MATCH) {
                    find_best_match(ctx, read_pos, bytes_in_window, &new_pos, &new_len);
                    hash_insert(&ctx->hash_chain, hash4(&ctx->window[read_pos]), read_pos);
                }
                match_pos = new_pos;
                match_len = new_len;
            }
        }

        /* Encode block */
        bool is_last = (bytes_in_window == 0 && current_file >= fl->count);
        result = encode_block(ctx, &bs, tok_count, is_last);
        if (result != DEFLATE_OK) goto folder_compress_cleanup;
    }

    /* Finalize */
    result = bs_flush(&bs);
    if (result != DEFLATE_OK) goto folder_compress_cleanup;

    if (!write_le32(out, crc)) {
        result = DEFLATE_ERR_IO;
        goto folder_compress_cleanup;
    }

    ctx->bytes_out = 8 + bs.bytes_written + 4;  /* Header + data + CRC */

    printf("\nFolder Compression Complete\n");
    printf("Files:  %u\n", fl->count);
    printf("Input:  %llu bytes\n", (unsigned long long)total_bytes_in);
    printf("Output: %llu bytes\n", (unsigned long long)ctx->bytes_out);
    printf("Ratio:  %.2f%%\n", total_bytes_in > 0 ?
           (100.0 * (double)ctx->bytes_out / (double)total_bytes_in) : 0.0);
    printf("CRC32:  0x%08X\n", crc);

folder_compress_cleanup:
    SAFE_FREE(ctx->token_buf);
    if (ctx) free(ctx);
    if (in) fclose(in);
    if (out) fclose(out);
    filelist_destroy(fl);
    return result;
}

/* ==================== DECOMPRESSION ==================== */

static DeflateError decompress_file(const char *infile, const char *outfile) {
    FILE *in = NULL;
    FILE *out = NULL;
    DeflateContext *ctx = NULL;
    DeflateError result = DEFLATE_OK;

    if (!is_safe_path(infile) || !is_safe_path(outfile)) {
        fprintf(stderr, "Error: Invalid file path\n");
        return DEFLATE_ERR_PATH;
    }

    /* Check if input is a directory */
    if (is_directory(infile)) {
        fprintf(stderr, "Error: '%s' is a directory. Cannot decompress a directory.\n", infile);
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
            fprintf(stderr, "Error: Output path is a symlink (security risk)\n");
            fclose(in);
            return DEFLATE_ERR_PATH;
        }
        perror("Error opening output");
        fclose(in);
        return DEFLATE_ERR_IO;
    }

    uint32_t magic;
    if (!read_le32(in, &magic) || magic != SIG_MAGIC) {
        fprintf(stderr, "Error: Invalid file format\n");
        result = DEFLATE_ERR_FORMAT;
        goto decompress_cleanup;
    }

    ctx = calloc(1, sizeof(DeflateContext));
    if (!ctx) {
        fprintf(stderr, "Error: Allocation failed\n");
        result = DEFLATE_ERR_MEM;
        goto decompress_cleanup;
    }

    init_crc32_table(ctx->crc_table);
    ctx->decomp_window = calloc(WINDOW_SIZE, 1);
    ctx->decode_table = calloc(FAST_DECODE_SIZE, sizeof(FastDecodeEntry));

    if (!ctx->decomp_window || !ctx->decode_table) {
        result = DEFLATE_ERR_MEM;
        goto decompress_cleanup;
    }

    BitStream bs;
    bs_init(&bs, in, false);

    uint16_t window_pos = 0;
    uint32_t calc_crc = 0;
    uint64_t total_output = 0;
    bool last_block = false;

    while (!last_block) {
        /* FIX #6: All bs_read_bits calls use non-NULL error pointer */
        bool read_err = false;

        int32_t last_bit = bs_read_bit(&bs);
        if (last_bit == -1) {
            fprintf(stderr, "Error: Unexpected EOF reading block header\n");
            result = DEFLATE_ERR_CORRUPT;
            goto decompress_cleanup;
        }
        last_block = (last_bit != 0);

        uint16_t max_sym = (uint16_t)bs_read_bits(&bs, 16, &read_err);
        if (read_err || max_sym >= SYMBOL_COUNT) {
            fprintf(stderr, "Error: Invalid symbol count (%u)\n", max_sym);
            result = DEFLATE_ERR_CORRUPT;
            goto decompress_cleanup;
        }

        /* Read code lengths */
        uint8_t depths[SYMBOL_COUNT] = {0};
        for (int32_t i = 0; i <= max_sym; i += 2) {
            bool err1 = false, err2 = false;
            uint32_t d1 = bs_read_bits(&bs, 4, &err1);
            uint32_t d2 = bs_read_bits(&bs, 4, &err2);

            if (err1 || err2 || d1 > MAX_HUFFMAN_DEPTH || d2 > MAX_HUFFMAN_DEPTH) {
                fprintf(stderr, "Error: Invalid Huffman depth\n");
                result = DEFLATE_ERR_CORRUPT;
                goto decompress_cleanup;
            }
            depths[i] = (uint8_t)d1;
            if (i + 1 <= max_sym) depths[i + 1] = (uint8_t)d2;
        }

        /* Build canonical Huffman table */
        CanonicalEntry table[SYMBOL_COUNT] = {0};
        int32_t t_count = 0;
        int32_t bl_count[32] = {0};
        uint64_t code = 0;
        uint64_t next_code[32];

        for (int32_t i = 0; i <= max_sym; i++) {
            if (depths[i] > 0) bl_count[depths[i]]++;
        }

        for (int32_t i = 1; i < 32; i++) {
            code = (code + bl_count[i - 1]) << 1;
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

        if (build_fast_decode_table(ctx->decode_table, table, t_count) != DEFLATE_OK) {
            result = DEFLATE_ERR_CORRUPT;
            goto decompress_cleanup;
        }

        /* Decode symbols */
        while (1) {
            int32_t sym = decode_symbol_fast(&bs, ctx->decode_table, table, t_count);
            if (sym == -1) {
                fprintf(stderr, "Error: Invalid Huffman symbol\n");
                result = DEFLATE_ERR_CORRUPT;
                goto decompress_cleanup;
            }
            if (sym == 256) break;  /* EOB */

            if (sym < 257) {
                /* Literal byte */
                if (++total_output > MAX_OUTPUT_SIZE) {
                    fprintf(stderr, "Error: Output limit exceeded\n");
                    result = DEFLATE_ERR_LIMIT;
                    goto decompress_cleanup;
                }

                uint8_t b = (uint8_t)sym;
                fputc(b, out);
                calc_crc = update_crc32(ctx->crc_table, calc_crc, &b, 1);
                ctx->decomp_window[window_pos] = b;
                window_pos = (window_pos + 1) & WINDOW_MASK;
            } else {
                /* Length-distance pair */
                int32_t len = (sym - 257) + 3;

                bool dist_err = false;
                int32_t dist = (int32_t)bs_read_bits(&bs, 12, &dist_err);

                if (dist_err || len < MIN_MATCH || len > MAX_MATCH ||
                    dist == 0 || dist > WINDOW_SIZE || (uint64_t)dist > total_output) {
                    fprintf(stderr, "Error: Invalid match (len=%d, dist=%d)\n", len, dist);
                    result = DEFLATE_ERR_CORRUPT;
                    goto decompress_cleanup;
                }

                if (total_output + (uint64_t)len > MAX_OUTPUT_SIZE) {
                    fprintf(stderr, "Error: Output limit exceeded\n");
                    result = DEFLATE_ERR_LIMIT;
                    goto decompress_cleanup;
                }
                total_output += (uint64_t)len;

                uint16_t src = (window_pos - (uint16_t)dist) & WINDOW_MASK;
                for (int32_t i = 0; i < len; i++) {
                    uint8_t c = ctx->decomp_window[(src + i) & WINDOW_MASK];
                    fputc(c, out);
                    calc_crc = update_crc32(ctx->crc_table, calc_crc, &c, 1);
                    ctx->decomp_window[window_pos] = c;
                    window_pos = (window_pos + 1) & WINDOW_MASK;
                }
            }
        }
    }

    /* Verify CRC - FIX: Treat missing/incomplete CRC as fatal (fail-closed) */
    uint32_t file_crc;
    if (!bs_read_aligned_uint32(&bs, &file_crc)) {
        fprintf(stderr, "Error: Unexpected EOF reading CRC footer\n");
        result = DEFLATE_ERR_CORRUPT;
        goto decompress_cleanup;
    }

    printf("Decompression Complete\n");
    printf("Output:       %llu bytes\n", (unsigned long long)total_output);
    printf("Computed CRC: 0x%08X\n", calc_crc);
    printf("File CRC:     0x%08X\n", file_crc);

    if (calc_crc != file_crc) {
        fprintf(stderr, "FATAL: CRC Mismatch - Data Corrupted!\n");
        result = DEFLATE_ERR_CORRUPT;
        goto decompress_cleanup;
    }

    printf("Integrity Verified: OK\n");

decompress_cleanup:
    SAFE_FREE(ctx->decode_table);
    SAFE_FREE(ctx->decomp_window);
    if (ctx) free(ctx);
    if (in) fclose(in);
    if (out) fclose(out);
    return result;
}

/* ==================== FOLDER DECOMPRESSION ==================== */

/**
 * Decompress a folder archive into a directory.
 */
static DeflateError decompress_folder(const char *infile, const char *out_dir) {
    FILE *in = NULL;
    FILE *out = NULL;
    DeflateContext *ctx = NULL;
    FileList *fl = NULL;
    DeflateError result = DEFLATE_OK;

    in = secure_fopen_read(infile);
    if (!in) {
        perror("Error opening input");
        return DEFLATE_ERR_IO;
    }

    /* Read and verify magic (already confirmed by caller, but double-check) */
    uint32_t magic;
    if (!read_le32(in, &magic) || magic != SIG_MAGIC_FOLDER) {
        fprintf(stderr, "Error: Not a folder archive\n");
        fclose(in);
        return DEFLATE_ERR_FORMAT;
    }

    /* Read file count */
    uint32_t file_count;
    if (!read_le32(in, &file_count) || file_count > MAX_FILES_IN_ARCHIVE) {
        fprintf(stderr, "Error: Invalid file count\n");
        fclose(in);
        return DEFLATE_ERR_FORMAT;
    }

    printf("Folder Archive: %u files\n", file_count);

    /* Create file list and read entries */
    fl = filelist_create();
    if (!fl) {
        fclose(in);
        return DEFLATE_ERR_MEM;
    }

    for (uint32_t i = 0; i < file_count; i++) {
        uint16_t path_len;
        char path[MAX_PATH_LEN];
        uint64_t size;

        if (!read_le16(in, &path_len) || path_len >= MAX_PATH_LEN) {
            fprintf(stderr, "Error: Invalid path length\n");
            result = DEFLATE_ERR_FORMAT;
            goto folder_decompress_cleanup;
        }

        if (fread(path, 1, path_len, in) != path_len) {
            fprintf(stderr, "Error: Failed to read path\n");
            result = DEFLATE_ERR_IO;
            goto folder_decompress_cleanup;
        }
        path[path_len] = '\0';

        if (!read_le64(in, &size)) {
            fprintf(stderr, "Error: Failed to read file size\n");
            result = DEFLATE_ERR_IO;
            goto folder_decompress_cleanup;
        }

        /* Security check on path */
        if (strstr(path, "..") != NULL || path[0] == '/' || path[0] == '\\') {
            fprintf(stderr, "Error: Unsafe path in archive: %s\n", path);
            result = DEFLATE_ERR_PATH;
            goto folder_decompress_cleanup;
        }

        if (!filelist_add(fl, path, size)) {
            fprintf(stderr, "Error: Too many files in archive\n");
            result = DEFLATE_ERR_LIMIT;
            goto folder_decompress_cleanup;
        }
    }

    /* Create output directory */
    if (!create_directory_recursive(out_dir)) {
        fprintf(stderr, "Warning: Could not create output directory (may already exist)\n");
    }

    /* Initialize decompression context */
    ctx = calloc(1, sizeof(DeflateContext));
    if (!ctx) {
        result = DEFLATE_ERR_MEM;
        goto folder_decompress_cleanup;
    }

    init_crc32_table(ctx->crc_table);
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

    /* State for splitting output into files */
    uint32_t current_file = 0;
    uint64_t current_file_written = 0;
    char out_path[MAX_PATH_LEN * 2];

    /* Open first output file */
    if (file_count > 0) {
        snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, fl->entries[0].path);
        normalize_path(out_path);

        /* Create parent directories */
        char *last_slash = strrchr(out_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            create_directory_recursive(out_path);
            *last_slash = '/';
        }

        bool is_symlink = false;
        out = secure_fopen_write(out_path, &is_symlink);
        if (!out) {
            fprintf(stderr, "Error: Cannot create file '%s'\n", out_path);
            result = DEFLATE_ERR_IO;
            goto folder_decompress_cleanup;
        }
        printf("  Extracting: %s\n", fl->entries[0].path);
    }

    while (!last_block) {
        bool read_err = false;

        int32_t last_bit = bs_read_bit(&bs);
        if (last_bit == -1) {
            fprintf(stderr, "Error: Unexpected EOF reading block header\n");
            result = DEFLATE_ERR_CORRUPT;
            goto folder_decompress_cleanup;
        }
        last_block = (last_bit != 0);

        uint16_t max_sym = (uint16_t)bs_read_bits(&bs, 16, &read_err);
        if (read_err || max_sym >= SYMBOL_COUNT) {
            fprintf(stderr, "Error: Invalid symbol count\n");
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

        for (int32_t i = 1; i < 32; i++) {
            code = (code + bl_count[i - 1]) << 1;
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

        if (build_fast_decode_table(ctx->decode_table, table, t_count) != DEFLATE_OK) {
            result = DEFLATE_ERR_CORRUPT;
            goto folder_decompress_cleanup;
        }

        /* Decode symbols */
        while (1) {
            int32_t sym = decode_symbol_fast(&bs, ctx->decode_table, table, t_count);
            if (sym == -1) {
                result = DEFLATE_ERR_CORRUPT;
                goto folder_decompress_cleanup;
            }
            if (sym == 256) break;  /* EOB */

            if (sym < 257) {
                /* Literal byte */
                uint8_t b = (uint8_t)sym;

                /* Write to current file, advance to next if needed */
                while (current_file < file_count &&
                       current_file_written >= fl->entries[current_file].size) {
                    /* Close current file, open next */
                    if (out) {
                        fclose(out);
                        out = NULL;
                    }
                    current_file++;
                    current_file_written = 0;

                    if (current_file < file_count) {
                        snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, fl->entries[current_file].path);
                        normalize_path(out_path);

                        char *last_slash = strrchr(out_path, '/');
                        if (last_slash) {
                            *last_slash = '\0';
                            create_directory_recursive(out_path);
                            *last_slash = '/';
                        }

                        bool is_symlink = false;
                        out = secure_fopen_write(out_path, &is_symlink);
                        if (!out) {
                            fprintf(stderr, "Error: Cannot create file '%s'\n", out_path);
                            result = DEFLATE_ERR_IO;
                            goto folder_decompress_cleanup;
                        }
                        printf("  Extracting: %s\n", fl->entries[current_file].path);
                    }
                }

                if (out) {
                    fputc(b, out);
                    current_file_written++;
                }

                calc_crc = update_crc32(ctx->crc_table, calc_crc, &b, 1);
                ctx->decomp_window[window_pos] = b;
                window_pos = (window_pos + 1) & WINDOW_MASK;
                total_output++;

                if (total_output > MAX_OUTPUT_SIZE) {
                    result = DEFLATE_ERR_LIMIT;
                    goto folder_decompress_cleanup;
                }
            } else {
                /* Length-distance pair */
                int32_t len = (sym - 257) + 3;
                bool dist_err = false;
                int32_t dist = (int32_t)bs_read_bits(&bs, 12, &dist_err);

                if (dist_err || len < MIN_MATCH || len > MAX_MATCH ||
                    dist == 0 || dist > WINDOW_SIZE) {
                    result = DEFLATE_ERR_CORRUPT;
                    goto folder_decompress_cleanup;
                }

                uint16_t src = (window_pos - (uint16_t)dist) & WINDOW_MASK;
                for (int32_t i = 0; i < len; i++) {
                    uint8_t c = ctx->decomp_window[(src + i) & WINDOW_MASK];

                    /* Check if need to switch to next file */
                    while (current_file < file_count &&
                           current_file_written >= fl->entries[current_file].size) {
                        if (out) {
                            fclose(out);
                            out = NULL;
                        }
                        current_file++;
                        current_file_written = 0;

                        if (current_file < file_count) {
                            snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, fl->entries[current_file].path);
                            normalize_path(out_path);

                            char *last_slash = strrchr(out_path, '/');
                            if (last_slash) {
                                *last_slash = '\0';
                                create_directory_recursive(out_path);
                                *last_slash = '/';
                            }

                            bool is_symlink = false;
                            out = secure_fopen_write(out_path, &is_symlink);
                            if (!out) {
                                result = DEFLATE_ERR_IO;
                                goto folder_decompress_cleanup;
                            }
                            printf("  Extracting: %s\n", fl->entries[current_file].path);
                        }
                    }

                    if (out) {
                        fputc(c, out);
                        current_file_written++;
                    }

                    calc_crc = update_crc32(ctx->crc_table, calc_crc, &c, 1);
                    ctx->decomp_window[window_pos] = c;
                    window_pos = (window_pos + 1) & WINDOW_MASK;
                    total_output++;
                }
            }
        }
    }

    /* Verify CRC */
    uint32_t file_crc;
    if (!bs_read_aligned_uint32(&bs, &file_crc)) {
        fprintf(stderr, "Error: Unexpected EOF reading CRC footer\n");
        result = DEFLATE_ERR_CORRUPT;
        goto folder_decompress_cleanup;
    }

    printf("\nFolder Decompression Complete\n");
    printf("Files:        %u\n", file_count);
    printf("Output:       %llu bytes\n", (unsigned long long)total_output);
    printf("Computed CRC: 0x%08X\n", calc_crc);
    printf("File CRC:     0x%08X\n", file_crc);

    if (calc_crc != file_crc) {
        fprintf(stderr, "FATAL: CRC Mismatch - Data Corrupted!\n");
        result = DEFLATE_ERR_CORRUPT;
        goto folder_decompress_cleanup;
    }

    printf("Integrity Verified: OK\n");

folder_decompress_cleanup:
    SAFE_FREE(ctx->decode_table);
    SAFE_FREE(ctx->decomp_window);
    if (ctx) free(ctx);
    if (in) fclose(in);
    if (out) fclose(out);
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
        fprintf(stderr, "Error: Cannot read file header\n");
        return DEFLATE_ERR_FORMAT;
    }
    fclose(fp);

    if (magic == SIG_MAGIC) {
        return decompress_file(infile, output);
    } else if (magic == SIG_MAGIC_FOLDER) {
        return decompress_folder(infile, output);
    } else {
        fprintf(stderr, "Error: Unknown archive format (magic: 0x%08X)\n", magic);
        return DEFLATE_ERR_FORMAT;
    }
}

/* ==================== MAIN ==================== */

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("DEFLATE Compressor v3.0 (with folder support)\n\n");
        printf("Usage: %s -c|-d <input> <output>\n\n", argv[0]);
        printf("Options:\n");
        printf("  -c    Compress file or folder\n");
        printf("  -d    Decompress to file or folder (auto-detected)\n\n");
        printf("Examples:\n");
        printf("  %s -c myfile.txt myfile.proz       # Compress file\n", argv[0]);
        printf("  %s -c myfolder/ archive.proz       # Compress folder\n", argv[0]);
        printf("  %s -d archive.proz output/         # Decompress (auto-detect)\n", argv[0]);
        printf("\nLimits: %lluMB input, %lluGB output\n",
               (unsigned long long)(MAX_INPUT_SIZE / (1024 * 1024)),
               (unsigned long long)(MAX_OUTPUT_SIZE / (1024ULL * 1024 * 1024)));
        return 1;
    }

    DeflateError result;
    if (strcmp(argv[1], "-c") == 0) {
        /* Check if input is a directory */
        if (is_directory(argv[2])) {
            result = compress_folder(argv[2], argv[3]);
        } else {
            result = compress_file(argv[2], argv[3]);
        }
    } else if (strcmp(argv[1], "-d") == 0) {
        /* Auto-detect archive type */
        result = decompress_auto(argv[2], argv[3]);
    } else {
        fprintf(stderr, "Error: Use -c or -d\n");
        return 1;
    }

    if (result != DEFLATE_OK) {
        fprintf(stderr, "Error code: %d\n", result);
        return (result < 0) ? -(int)result : (int)result;
    }
    return 0;
}
