/**
 * deflate.c - Production-Grade DEFLATE-Style Compressor
 *
 * A secure, high-performance hybrid compressor using LZSS + Canonical Huffman.
 *
 * Features:
 *   - Hash chain LZSS with 4KB sliding window
 *   - O(1) Huffman decoding via 12-bit lookup tables
 *   - CRC32 integrity verification
 *   - Security hardening (path traversal, zip bomb, size limits)
 *
 * Build: gcc -O3 -march=native -Wall -Wextra -std=c99 deflate.c -o deflate
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

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

#define SIG_MAGIC             0x50524F5A

#define MAX_INPUT_SIZE        (1024LL * 1024LL * 1024LL)
#define MAX_OUTPUT_SIZE       (10LL * 1024LL * 1024LL * 1024LL)
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
    uint16_t type;
    uint16_t val;
    uint16_t dist;
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

typedef struct {
    FILE *fp;
    uint8_t buffer[IO_BUFFER_SIZE];
    size_t pos;
    size_t bytes_in_buf;
    uint64_t bit_acc;
    int32_t bit_count;
    bool mode_write;
} BitStream;

typedef struct {
    uint16_t head[HASH_SIZE];
    uint16_t prev[WINDOW_SIZE];
} HashChain;

typedef struct {
    uint32_t crc_table[256];
    uint8_t window[WINDOW_SIZE * 2];
    HashChain hash_chain;
    Token *token_buf;
    uint8_t *decomp_window;
    FastDecodeEntry *decode_table;
    size_t bytes_in;
    size_t bytes_out;
} DeflateContext;

/* ==================== MACROS ==================== */

#define CHECK_NULL(ptr, msg) \
    if (!(ptr)) { \
        fprintf(stderr, "Error: %s\n", msg); \
        return DEFLATE_ERR_MEM; \
    }

#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); ptr = NULL; } } while(0)

/* ==================== PORTABLE I/O ==================== */

static bool write_le32(FILE *fp, uint32_t val) {
    uint8_t buf[4] = { val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF };
    return fwrite(buf, 1, 4, fp) == 4;
}

static bool read_le32(FILE *fp, uint32_t *val) {
    uint8_t buf[4];
    if (fread(buf, 1, 4, fp) != 4) return false;
    *val = buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return true;
}

/* ==================== CRC32 ==================== */

static void init_crc32_table(uint32_t *table) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int32_t j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
}

static uint32_t update_crc32(const uint32_t *table, uint32_t crc, const uint8_t *buf, size_t len) {
    uint32_t c = crc ^ 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        c = table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

/* ==================== BIT I/O ==================== */

static void bs_init(BitStream *bs, FILE *fp, bool write) {
    bs->fp = fp;
    bs->pos = 0;
    bs->bytes_in_buf = 0;
    bs->bit_acc = 0;
    bs->bit_count = 0;
    bs->mode_write = write;
    memset(bs->buffer, 0, IO_BUFFER_SIZE);
}

static DeflateError bs_flush(BitStream *bs) {
    if (!bs->mode_write) return DEFLATE_OK;

    while (bs->bit_count > 0) {
        int32_t shift = (bs->bit_count >= 8) ? (bs->bit_count - 8) : 0;
        uint8_t byte = (bs->bit_count < 8)
            ? (uint8_t)(bs->bit_acc << (8 - bs->bit_count))
            : (uint8_t)(bs->bit_acc >> shift);

        bs->bit_count = (bs->bit_count < 8) ? 0 : bs->bit_count - 8;
        if (bs->pos >= IO_BUFFER_SIZE) return DEFLATE_ERR_MEM;
        bs->buffer[bs->pos++] = byte;

        if (bs->pos == IO_BUFFER_SIZE) {
            if (fwrite(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp) != IO_BUFFER_SIZE)
                return DEFLATE_ERR_IO;
            bs->pos = 0;
        }
    }

    if (bs->pos > 0) {
        if (fwrite(bs->buffer, 1, bs->pos, bs->fp) != bs->pos)
            return DEFLATE_ERR_IO;
        bs->pos = 0;
    }
    return DEFLATE_OK;
}

static DeflateError bs_write(BitStream *bs, uint64_t val, int32_t bits) {
    if (bits < 0 || bits > 64) return DEFLATE_ERR_FORMAT;

    bs->bit_acc = (bs->bit_acc << bits) | (val & ((1ULL << bits) - 1));
    bs->bit_count += bits;

    while (bs->bit_count >= 8) {
        bs->bit_count -= 8;
        uint8_t byte = (uint8_t)((bs->bit_acc >> bs->bit_count) & 0xFF);
        if (bs->pos >= IO_BUFFER_SIZE) return DEFLATE_ERR_MEM;
        bs->buffer[bs->pos++] = byte;

        if (bs->pos == IO_BUFFER_SIZE) {
            if (fwrite(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp) != IO_BUFFER_SIZE)
                return DEFLATE_ERR_IO;
            bs->pos = 0;
        }
    }
    return DEFLATE_OK;
}

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

static uint32_t bs_read_bits(BitStream *bs, int32_t bits, bool *error) {
    if (error) *error = false;
    if (bits < 0 || bits > 32) { if (error) *error = true; return 0; }
    uint32_t val = 0;
    for (int32_t i = 0; i < bits; i++) {
        int32_t b = bs_read_bit(bs);
        if (b == -1) { if (error) *error = true; return 0; }
        val = (val << 1) | b;
    }
    return val;
}

static uint32_t bs_read_aligned_uint32(BitStream *bs) {
    bs->bit_count = 0;
    uint32_t res = 0;
    for (int32_t i = 0; i < 4; i++) {
        if (bs->pos >= bs->bytes_in_buf) {
            bs->bytes_in_buf = fread(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
            bs->pos = 0;
            if (bs->bytes_in_buf == 0) break;
        }
        res |= ((uint32_t)bs->buffer[bs->pos++] << (i * 8));
    }
    return res;
}

/* ==================== HASH CHAIN LZSS ==================== */

static inline uint32_t hash4(const uint8_t *data) {
    return ((((uint32_t)data[0] << 10) ^ ((uint32_t)data[1] << 5) ^ data[2])) & HASH_MASK;
}

static void hash_init(HashChain *hc) {
    memset(hc->head, 0xFF, sizeof(hc->head));
    memset(hc->prev, 0xFF, sizeof(hc->prev));
}

static void hash_insert(HashChain *hc, uint32_t hash, uint16_t pos) {
    if (pos >= WINDOW_SIZE || hash >= HASH_SIZE) return;
    hc->prev[pos] = hc->head[hash];
    hc->head[hash] = pos;
}

static void find_best_match(const DeflateContext *ctx, uint16_t pos, int32_t available,
                           int32_t *match_pos, int32_t *match_len) {
    *match_len = 0;
    *match_pos = 0;
    if (available < MIN_MATCH || pos >= WINDOW_SIZE) return;

    uint32_t hash = hash4(&ctx->window[pos]);
    if (hash >= HASH_SIZE) return;

    uint16_t chain = ctx->hash_chain.head[hash];
    int32_t chain_count = 0;
    int32_t max_len = (available < MAX_MATCH) ? available : MAX_MATCH;

    /* Ensure bounds safety for doubled window buffer */
    if (pos + max_len > WINDOW_SIZE * 2) max_len = WINDOW_SIZE * 2 - pos;
    if (max_len < MIN_MATCH) return;

    uint8_t first = ctx->window[pos];
    uint8_t second = ctx->window[pos + 1];

    while (chain != 0xFFFF && chain < WINDOW_SIZE && chain_count++ < MAX_CHAIN_LENGTH) {
        int32_t distance = (pos - chain) & WINDOW_MASK;
        if (distance == 0) break;

        if (distance > WINDOW_SIZE - MAX_MATCH) {
            chain = ctx->hash_chain.prev[chain];
            continue;
        }

        /* Bounds safety for chain access */
        int32_t chain_max = (chain + max_len > WINDOW_SIZE * 2) ? (WINDOW_SIZE * 2 - chain) : max_len;
        if (chain_max < MIN_MATCH) { chain = ctx->hash_chain.prev[chain]; continue; }

        if (ctx->window[chain + *match_len] == ctx->window[pos + *match_len] &&
            ctx->window[chain] == first && ctx->window[chain + 1] == second) {
            int32_t len = 2;
            int32_t safe_max = (chain_max < max_len) ? chain_max : max_len;
            while (len < safe_max && ctx->window[chain + len] == ctx->window[pos + len])
                len++;
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
    h->nodes = malloc(sizeof(HuffmanNode*) * cap);
    if (!h->nodes) { free(h); return NULL; }
    h->size = 0;
    h->capacity = cap;
    return h;
}

static void heap_push(MinHeap *h, HuffmanNode *n) {
    if (h->size >= h->capacity) return;
    int32_t i = h->size++;
    while (i > 0 && n->freq < h->nodes[(i - 1) / 2]->freq) {
        h->nodes[i] = h->nodes[(i - 1) / 2];
        i = (i - 1) / 2;
    }
    h->nodes[i] = n;
}

static HuffmanNode* heap_pop(MinHeap *h) {
    if (h->size == 0) return NULL;
    HuffmanNode *res = h->nodes[0];
    h->nodes[0] = h->nodes[--h->size];

    int32_t i = 0;
    while (1) {
        int32_t smallest = i, l = 2*i + 1, r = 2*i + 2;
        if (l < h->size && h->nodes[l]->freq < h->nodes[smallest]->freq) smallest = l;
        if (r < h->size && h->nodes[r]->freq < h->nodes[smallest]->freq) smallest = r;
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
        if (root->sym >= 0 && root->sym < SYMBOL_COUNT)
            lens[root->sym] = (depth > MAX_HUFFMAN_DEPTH) ? MAX_HUFFMAN_DEPTH : depth;
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

static DeflateError build_huffman_codes(const uint64_t *freqs, CanonicalEntry *table,
                                        uint8_t *depths, uint16_t *max_sym_out) {
    MinHeap *h = heap_create(SYMBOL_COUNT * 2);
    if (!h) return DEFLATE_ERR_MEM;
    memset(depths, 0, SYMBOL_COUNT);

    for (int32_t i = 0; i < SYMBOL_COUNT; i++) {
        if (freqs[i] > 0) {
            HuffmanNode *n = malloc(sizeof(HuffmanNode));
            if (!n) { free(h->nodes); free(h); return DEFLATE_ERR_MEM; }
            n->sym = i; n->freq = freqs[i]; n->left = n->right = NULL;
            heap_push(h, n);
            *max_sym_out = i;
        }
    }

    if (h->size == 0) { free(h->nodes); free(h); return DEFLATE_ERR_FORMAT; }

    if (h->size == 1) {
        HuffmanNode *n = heap_pop(h);
        HuffmanNode *dummy = malloc(sizeof(HuffmanNode));
        HuffmanNode *parent = malloc(sizeof(HuffmanNode));
        if (!dummy || !parent) {
            free(n); free(dummy); free(parent); free(h->nodes); free(h);
            return DEFLATE_ERR_MEM;
        }
        dummy->sym = (n->sym == 0) ? 1 : 0;
        dummy->freq = 0; dummy->left = dummy->right = NULL;
        parent->sym = -1; parent->freq = n->freq;
        parent->left = n; parent->right = dummy;
        heap_push(h, parent);
    }

    while (h->size > 1) {
        HuffmanNode *l = heap_pop(h), *r = heap_pop(h);
        HuffmanNode *parent = malloc(sizeof(HuffmanNode));
        if (!parent) { free_tree(l); free_tree(r); free(h->nodes); free(h); return DEFLATE_ERR_MEM; }
        parent->sym = -1; parent->freq = l->freq + r->freq;
        parent->left = l; parent->right = r;
        heap_push(h, parent);
    }

    HuffmanNode *root = heap_pop(h);
    get_tree_depths(root, 0, depths);

    int32_t bl_count[32] = {0};
    uint64_t code = 0, next_code[32];

    for (int32_t i = 0; i < SYMBOL_COUNT; i++) {
        if (depths[i] > 0) {
            if (depths[i] > MAX_HUFFMAN_DEPTH) {
                free_tree(root); free(h->nodes); free(h);
                return DEFLATE_ERR_FORMAT;
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
            table[i].sym = i;
            table[i].len = depths[i];
            table[i].code = next_code[depths[i]]++;
        }
    }

    free_tree(root);
    free(h->nodes);
    free(h);
    return DEFLATE_OK;
}

static DeflateError encode_block(DeflateContext *ctx, BitStream *bs, int32_t token_count, bool is_last) {
    uint64_t freqs[SYMBOL_COUNT] = {0};

    for (int32_t i = 0; i < token_count; i++) {
        if (ctx->token_buf[i].val >= SYMBOL_COUNT) return DEFLATE_ERR_CORRUPT;
        freqs[ctx->token_buf[i].val]++;
    }
    freqs[256] = 1;

    CanonicalEntry table[SYMBOL_COUNT];
    uint8_t depths[SYMBOL_COUNT];
    uint16_t max_sym = 0;

    DeflateError err = build_huffman_codes(freqs, table, depths, &max_sym);
    if (err != DEFLATE_OK) return err;
    if (max_sym >= SYMBOL_COUNT) return DEFLATE_ERR_FORMAT;

    if ((err = bs_write(bs, is_last ? 1 : 0, 1)) != DEFLATE_OK) return err;
    if ((err = bs_write(bs, max_sym, 16)) != DEFLATE_OK) return err;

    for (int32_t i = 0; i <= max_sym; i += 2) {
        uint8_t d1 = depths[i], d2 = (i + 1 <= max_sym) ? depths[i + 1] : 0;
        if ((err = bs_write(bs, d1 & 0x0F, 4)) != DEFLATE_OK) return err;
        if ((err = bs_write(bs, d2 & 0x0F, 4)) != DEFLATE_OK) return err;
    }

    for (int32_t i = 0; i < token_count; i++) {
        uint16_t val = ctx->token_buf[i].val;
        if (val >= SYMBOL_COUNT || table[val].len == 0) return DEFLATE_ERR_CORRUPT;
        if ((err = bs_write(bs, table[val].code, table[val].len)) != DEFLATE_OK) return err;
        if (ctx->token_buf[i].type == 1) {
            if ((err = bs_write(bs, ctx->token_buf[i].dist, 12)) != DEFLATE_OK) return err;
        }
    }

    return bs_write(bs, table[256].code, table[256].len);
}

/* ==================== FAST HUFFMAN DECODING ==================== */

static DeflateError build_fast_decode_table(FastDecodeEntry *decode_table,
                                            const CanonicalEntry *table, int32_t t_count) {
    memset(decode_table, 0, sizeof(FastDecodeEntry) * FAST_DECODE_SIZE);

    for (int32_t i = 0; i < t_count; i++) {
        uint8_t len = table[i].len;
        if (len == 0 || len > FAST_DECODE_BITS) continue;

        int32_t fill_count = 1 << (FAST_DECODE_BITS - len);
        uint32_t base = (uint32_t)(table[i].code << (FAST_DECODE_BITS - len));

        for (int32_t j = 0; j < fill_count; j++) {
            uint32_t idx = base + j;
            if (idx >= FAST_DECODE_SIZE) return DEFLATE_ERR_FORMAT;
            decode_table[idx].symbol = table[i].sym;
            decode_table[idx].bits_used = len;
        }
    }
    return DEFLATE_OK;
}

static int32_t decode_symbol_fast(BitStream *bs, const FastDecodeEntry *decode_table,
                                  const CanonicalEntry *table, int32_t t_count) {
    int32_t available_bits = bs->bit_count + 8 * (int32_t)(bs->bytes_in_buf - bs->pos);

    if (available_bits >= FAST_DECODE_BITS) {
        uint32_t peek = 0;
        uint32_t orig_bit_count = bs->bit_count;
        uint64_t orig_bit_acc = bs->bit_acc;
        size_t orig_pos = bs->pos;

        for (int32_t i = 0; i < FAST_DECODE_BITS; i++) {
            int32_t b = bs_read_bit(bs);
            if (b == -1) return -1;
            peek = (peek << 1) | b;
        }

        if (peek < FAST_DECODE_SIZE) {
            FastDecodeEntry entry = decode_table[peek];
            if (entry.bits_used > 0 && entry.bits_used <= FAST_DECODE_BITS) {
                bs->bit_count = orig_bit_count;
                bs->bit_acc = orig_bit_acc;
                bs->pos = orig_pos;
                for (int32_t i = 0; i < entry.bits_used; i++) bs_read_bit(bs);
                return entry.symbol;
            }
        }

        bs->bit_count = orig_bit_count;
        bs->bit_acc = orig_bit_acc;
        bs->pos = orig_pos;
    }

    uint64_t curr_code = 0;
    int32_t curr_len = 0;

    for (int32_t iter = 0; iter < MAX_DECODE_ITERATIONS; iter++) {
        int32_t b = bs_read_bit(bs);
        if (b == -1) return -1;
        curr_code = (curr_code << 1) | b;
        curr_len++;
        if (curr_len > MAX_HUFFMAN_DEPTH) return -1;

        for (int32_t k = 0; k < t_count; k++) {
            if (table[k].len == curr_len && table[k].code == curr_code)
                return table[k].sym;
        }
    }
    return -1;
}

/* ==================== PATH SECURITY ==================== */

static bool is_safe_path(const char *path) {
    if (!path || !path[0]) return false;
    if (path[0] == '/' || path[0] == '\\' || path[1] == ':') return false;
    if (strstr(path, "..")) return false;
    for (const char *p = path; *p; p++) {
        if (*p < 32 || *p == '<' || *p == '>' || *p == '|' || *p == '"') return false;
    }
    return strlen(path) <= 255;
}

/* ==================== COMPRESSION ==================== */

static DeflateError compress_file(const char *infile, const char *outfile) {
    if (!is_safe_path(infile) || !is_safe_path(outfile)) {
        fprintf(stderr, "Error: Invalid file path\n");
        return DEFLATE_ERR_PATH;
    }

    FILE *in = fopen(infile, "rb");
    if (!in) { perror("Error opening input"); return DEFLATE_ERR_IO; }

    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    if (file_size < 0 || file_size > MAX_INPUT_SIZE) {
        fprintf(stderr, "Error: Input too large (max %lld bytes)\n", MAX_INPUT_SIZE);
        fclose(in);
        return DEFLATE_ERR_LIMIT;
    }

    FILE *out = fopen(outfile, "wb");
    if (!out) { perror("Error opening output"); fclose(in); return DEFLATE_ERR_IO; }

    if (!write_le32(out, SIG_MAGIC)) {
        fclose(in); fclose(out);
        return DEFLATE_ERR_IO;
    }

    DeflateContext *ctx = calloc(1, sizeof(DeflateContext));
    CHECK_NULL(ctx, "Allocation failed");

    init_crc32_table(ctx->crc_table);
    hash_init(&ctx->hash_chain);

    ctx->token_buf = calloc(BLOCK_SIZE, sizeof(Token));
    if (!ctx->token_buf) { free(ctx); fclose(in); fclose(out); return DEFLATE_ERR_MEM; }

    BitStream bs;
    bs_init(&bs, out, true);
    memset(ctx->window, 0, sizeof(ctx->window));

    uint16_t r = 0;
    int32_t len = 0;

    for (; len < MAX_MATCH; len++) {
        int c = fgetc(in);
        if (c == EOF) break;
        ctx->window[len] = (uint8_t)c;
        ctx->window[len + WINDOW_SIZE] = (uint8_t)c;
    }

    uint16_t s = len;
    int32_t match_pos, match_len;
    find_best_match(ctx, r, len, &match_pos, &match_len);
    hash_insert(&ctx->hash_chain, hash4(&ctx->window[r]), r);

    uint32_t crc = 0;
    ctx->bytes_in = len;
    ctx->bytes_out = 4;

    while (len > 0) {
        int32_t tok_count = 0;

        while (tok_count < BLOCK_SIZE && len > 0) {
            if (match_len > len) match_len = len;

            if (match_len < MIN_MATCH) {
                match_len = 1;
                ctx->token_buf[tok_count].type = 0;
                ctx->token_buf[tok_count].val = ctx->window[r];
                ctx->token_buf[tok_count].dist = 0;
                uint8_t b = ctx->window[r];
                crc = update_crc32(ctx->crc_table, crc, &b, 1);
            } else {
                ctx->token_buf[tok_count].type = 1;
                ctx->token_buf[tok_count].val = (match_len - 3) + 257;
                ctx->token_buf[tok_count].dist = (r - match_pos) & WINDOW_MASK;
                crc = update_crc32(ctx->crc_table, crc, &ctx->window[r], match_len);
            }
            tok_count++;

            int32_t last_len = match_len;
            for (int32_t i = 0; i < last_len; i++) {
                int c = fgetc(in);
                ctx->window[s] = (c == EOF) ? 0 : (uint8_t)c;
                ctx->window[s + WINDOW_SIZE] = ctx->window[s];

                if (c == EOF) len--; else ctx->bytes_in++;

                s = (s + 1) & WINDOW_MASK;
                r = (r + 1) & WINDOW_MASK;

                if (r == 0) {
                    for (int32_t j = 0; j < HASH_SIZE; j++)
                        ctx->hash_chain.head[j] = 0xFFFF;
                }

                int32_t new_pos, new_len;
                find_best_match(ctx, r, len, &new_pos, &new_len);
                hash_insert(&ctx->hash_chain, hash4(&ctx->window[r]), r);
                match_pos = new_pos;
                match_len = new_len;
            }
        }

        DeflateError err = encode_block(ctx, &bs, tok_count, len <= 0);
        if (err != DEFLATE_OK) {
            SAFE_FREE(ctx->token_buf); free(ctx); fclose(in); fclose(out);
            return err;
        }
    }

    DeflateError err = bs_flush(&bs);
    if (err != DEFLATE_OK) {
        SAFE_FREE(ctx->token_buf); free(ctx); fclose(in); fclose(out);
        return err;
    }

    if (!write_le32(out, crc)) {
        SAFE_FREE(ctx->token_buf); free(ctx); fclose(in); fclose(out);
        return DEFLATE_ERR_IO;
    }

    ctx->bytes_out = ftell(out);

    printf("Compression Complete\n");
    printf("Input:  %zu bytes\n", ctx->bytes_in);
    printf("Output: %zu bytes\n", ctx->bytes_out);
    printf("Ratio:  %.2f%%\n", 100.0 * ctx->bytes_out / (ctx->bytes_in + 1));
    printf("CRC32:  0x%08X\n", crc);

    SAFE_FREE(ctx->token_buf);
    free(ctx);
    fclose(in);
    fclose(out);
    return DEFLATE_OK;
}

/* ==================== DECOMPRESSION ==================== */

static DeflateError decompress_file(const char *infile, const char *outfile) {
    if (!is_safe_path(infile) || !is_safe_path(outfile)) {
        fprintf(stderr, "Error: Invalid file path\n");
        return DEFLATE_ERR_PATH;
    }

    FILE *in = fopen(infile, "rb");
    if (!in) { perror("Error opening input"); return DEFLATE_ERR_IO; }

    FILE *out = fopen(outfile, "wb");
    if (!out) { perror("Error opening output"); fclose(in); return DEFLATE_ERR_IO; }

    uint32_t magic;
    if (!read_le32(in, &magic) || magic != SIG_MAGIC) {
        fprintf(stderr, "Error: Invalid file format\n");
        fclose(in); fclose(out);
        return DEFLATE_ERR_FORMAT;
    }

    DeflateContext *ctx = calloc(1, sizeof(DeflateContext));
    CHECK_NULL(ctx, "Allocation failed");

    init_crc32_table(ctx->crc_table);
    ctx->decomp_window = calloc(WINDOW_SIZE, 1);
    ctx->decode_table = calloc(FAST_DECODE_SIZE, sizeof(FastDecodeEntry));

    if (!ctx->decomp_window || !ctx->decode_table) {
        SAFE_FREE(ctx->decomp_window); SAFE_FREE(ctx->decode_table);
        free(ctx); fclose(in); fclose(out);
        return DEFLATE_ERR_MEM;
    }

    BitStream bs;
    bs_init(&bs, in, false);

    uint16_t r = 0;
    uint32_t calc_crc = 0;
    size_t total_output = 0;
    bool last_block = false;

    while (!last_block) {
        bool read_err = false;
        last_block = bs_read_bit(&bs);
        uint16_t max_sym = (uint16_t)bs_read_bits(&bs, 16, &read_err);

        if (read_err || max_sym >= SYMBOL_COUNT) {
            fprintf(stderr, "Error: Invalid symbol count\n");
            goto decompress_error;
        }

        uint8_t depths[SYMBOL_COUNT] = {0};
        for (int32_t i = 0; i <= max_sym; i += 2) {
            int32_t d1 = bs_read_bits(&bs, 4, &read_err), d2 = bs_read_bits(&bs, 4, NULL);
            if (read_err || d1 > MAX_HUFFMAN_DEPTH || d2 > MAX_HUFFMAN_DEPTH) {
                fprintf(stderr, "Error: Invalid Huffman depth\n");
                goto decompress_error;
            }
            depths[i] = (uint8_t)d1;
            if (i + 1 <= max_sym) depths[i + 1] = (uint8_t)d2;
        }

        CanonicalEntry table[SYMBOL_COUNT] = {0};
        int32_t t_count = 0, bl_count[32] = {0};
        uint64_t code = 0, next_code[32];

        for (int32_t i = 0; i <= max_sym; i++)
            if (depths[i] > 0) bl_count[depths[i]]++;

        for (int32_t i = 1; i < 32; i++) {
            code = (code + bl_count[i - 1]) << 1;
            next_code[i] = code;
        }

        for (int32_t i = 0; i <= max_sym; i++) {
            if (depths[i] > 0) {
                table[t_count].sym = i;
                table[t_count].len = depths[i];
                table[t_count].code = next_code[depths[i]]++;
                t_count++;
            }
        }

        if (build_fast_decode_table(ctx->decode_table, table, t_count) != DEFLATE_OK)
            goto decompress_error;

        while (1) {
            int32_t sym = decode_symbol_fast(&bs, ctx->decode_table, table, t_count);
            if (sym == -1) { fprintf(stderr, "Error: Invalid symbol\n"); goto decompress_error; }
            if (sym == 256) break;

            if (sym < 257) {
                if (++total_output > MAX_OUTPUT_SIZE) {
                    fprintf(stderr, "Error: Output limit exceeded\n");
                    goto decompress_error;
                }
                fputc(sym, out);
                uint8_t b = (uint8_t)sym;
                calc_crc = update_crc32(ctx->crc_table, calc_crc, &b, 1);
                ctx->decomp_window[r] = b;
                r = (r + 1) & WINDOW_MASK;
            } else {
                int32_t len = (sym - 257) + 3;
                bool dist_err = false;
                int32_t dist = bs_read_bits(&bs, 12, &dist_err);

                if (dist_err || len < MIN_MATCH || len > MAX_MATCH || dist == 0 || dist > WINDOW_SIZE ||
                    (size_t)dist > total_output) {
                    fprintf(stderr, "Error: Invalid match\n");
                    goto decompress_error;
                }

                total_output += len;
                if (total_output > MAX_OUTPUT_SIZE) {
                    fprintf(stderr, "Error: Output limit exceeded\n");
                    goto decompress_error;
                }

                uint16_t src = (r - dist) & WINDOW_MASK;
                for (int32_t i = 0; i < len; i++) {
                    uint8_t c = ctx->decomp_window[(src + i) & WINDOW_MASK];
                    fputc(c, out);
                    calc_crc = update_crc32(ctx->crc_table, calc_crc, &c, 1);
                    ctx->decomp_window[r] = c;
                    r = (r + 1) & WINDOW_MASK;
                }
            }
        }
    }

    uint32_t file_crc = bs_read_aligned_uint32(&bs);

    printf("Decompression Complete\n");
    printf("Output:       %zu bytes\n", total_output);
    printf("Computed CRC: 0x%08X\n", calc_crc);
    printf("File CRC:     0x%08X\n", file_crc);

    if (calc_crc != file_crc) {
        fprintf(stderr, "FATAL: CRC Mismatch - Data Corrupted!\n");
        goto decompress_error;
    }

    printf("Integrity Verified: OK\n");

    SAFE_FREE(ctx->decode_table);
    SAFE_FREE(ctx->decomp_window);
    free(ctx);
    fclose(in);
    fclose(out);
    return DEFLATE_OK;

decompress_error:
    SAFE_FREE(ctx->decode_table);
    SAFE_FREE(ctx->decomp_window);
    free(ctx);
    fclose(in);
    fclose(out);
    return DEFLATE_ERR_CORRUPT;
}

/* ==================== MAIN ==================== */

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("DEFLATE Compressor v2.0\n\n");
        printf("Usage: %s -c|-d <input> <output>\n\n", argv[0]);
        printf("Options:\n");
        printf("  -c    Compress file\n");
        printf("  -d    Decompress file\n\n");
        printf("Limits: %lldMB input, %lldGB output\n",
               MAX_INPUT_SIZE / (1024*1024), MAX_OUTPUT_SIZE / (1024*1024*1024));
        return 1;
    }

    DeflateError result;
    if (strcmp(argv[1], "-c") == 0)
        result = compress_file(argv[2], argv[3]);
    else if (strcmp(argv[1], "-d") == 0)
        result = decompress_file(argv[2], argv[3]);
    else {
        fprintf(stderr, "Error: Use -c or -d\n");
        return 1;
    }

    if (result != DEFLATE_OK) {
        fprintf(stderr, "Error code: %d\n", result);
        return (int)result;
    }
    return 0;
}
