/**
 * deflate.c
 * * HYBRID COMPRESSOR (DEFLATE COMPATIBLE ARCHITECTURE)
 * * ALGORITHM:
 * 1. LZSS (Lempel-Ziv-Storer-Szymanski):
 * - Uses a 4KB sliding window and a Binary Search Tree for O(log n) pattern matching.
 * - Emits a stream of [Literal] or [Match <Dist, Len>] tokens.
 * 2. Canonical Huffman Coding:
 * - Analyzes token frequency per 32KB block.
 * - Generates prefix-free codes based on symbol path lengths.
 * - Header stores only bit-lengths (Canonical representation), minimizing overhead.
 * 3. Integrity:
 * - Standard CRC32 checksum verification.
 * * COMPILATION:
 * gcc -O3 deflate.c -o deflate.exe
 * * USAGE:
 * ./deflate.exe -c <input> <output>
 * ./deflate.exe -d <input> <output>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// --- Configuration Constants ---
#define WINDOW_SIZE     4096        // Window size (Must be power of 2 for bitwise wrapping)
#define WINDOW_MASK     (WINDOW_SIZE - 1)
#define MAX_MATCH       258         // Max match length (Standard Deflate limit)
#define MIN_MATCH       3           // Min match length to encode as reference
#define BLOCK_SIZE      32768       // Process input in 32KB blocks to adapt Huffman tree
#define SYMBOL_COUNT    513         // 0-255 (Lit), 256 (EOB), 257-512 (Len Codes)
#define IO_BUFFER_SIZE  16384       // 16KB Buffered I/O

#define SIG_MAGIC       0x50524F5A  // File Signature "PROZ"
#define ERR_IO          -1
#define ERR_MEM         -2
#define ERR_FMT         -3

// --- Helper Macros ---
#define CHECK_MALLOC(ptr) if (!(ptr)) { fprintf(stderr, "Fatal: Memory allocation failed.\n"); exit(ERR_MEM); }

// --- CRC32 Checksum Subsystem ---
static uint32_t crc32_table[256];
static int crc_initialized = 0;

void init_crc32(void) {
    uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1) c = 0xEDB88320 ^ (c >> 1);
            else       c = c >> 1;
        }
        crc32_table[i] = c;
    }
    crc_initialized = 1;
}

uint32_t update_crc32(uint32_t crc, const uint8_t *buf, size_t len) {
    if (!crc_initialized) init_crc32();
    uint32_t c = crc ^ 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        c = crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

// --- Data Structures ---

// Intermediate Token (LZSS Output)
typedef struct {
    uint16_t type; // 0 = Literal, 1 = Match
    uint16_t val;  // Literal Byte (0-255) OR Match Length Code (257+)
    uint16_t dist; // Match Distance (1-4096)
} Token;

// Huffman Node
typedef struct Node {
    int sym;
    uint64_t freq;
    struct Node *left, *right;
} Node;

// MinHeap for Tree Construction
typedef struct {
    Node **nodes;
    int size;
    int capacity;
} MinHeap;

// Canonical Lookup Table Entry
typedef struct {
    uint16_t sym;
    uint8_t len;
    uint64_t code;
} CanonicalEntry;

// Buffered Bit Stream Context
typedef struct {
    FILE *fp;
    uint8_t buffer[IO_BUFFER_SIZE];
    size_t pos;          // Current byte index in buffer
    size_t bytes_in_buf; // Total valid bytes in buffer (Read Mode)
    uint64_t bit_buffer; // Accumulator for bits
    int bit_count;       // Count of bits in accumulator
    bool mode_write;     // true = Writer, false = Reader
} BitStream;

// Compressor State (Heap Allocated to prevent stack overflow)
typedef struct {
    uint8_t window[WINDOW_SIZE * 2]; // Double buffer for seamless wrapping
    int lson[WINDOW_SIZE + 1];       // BST: Left Children
    int rson[WINDOW_SIZE + 257];     // BST: Right Children
    int dad[WINDOW_SIZE + 1];        // BST: Parents
    Token *token_buf;                // Block Token Buffer
} CompressorState;

// --- Bit Stream Operations ---

void bs_init(BitStream *bs, FILE *fp, bool write) {
    bs->fp = fp;
    bs->pos = 0;
    bs->bytes_in_buf = 0;
    bs->bit_buffer = 0;
    bs->bit_count = 0;
    bs->mode_write = write;
}

// Flush bits and write buffer to disk
void bs_flush(BitStream *bs) {
    if (!bs->mode_write) return;
    
    while (bs->bit_count > 0) {
        // Extract top 8 bits or remaining bits
        int shift = (bs->bit_count >= 8) ? (bs->bit_count - 8) : 0;
        uint8_t byte = (uint8_t)(bs->bit_buffer >> shift);
        
        // If less than 8 bits, align to MSB (left-justify)
        if (bs->bit_count < 8) {
            byte = (uint8_t)(bs->bit_buffer << (8 - bs->bit_count));
            bs->bit_count = 0;
        } else {
            bs->bit_count -= 8;
        }

        bs->buffer[bs->pos++] = byte;
        if (bs->pos == IO_BUFFER_SIZE) {
            fwrite(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
            bs->pos = 0;
        }
    }
    
    if (bs->pos > 0) {
        fwrite(bs->buffer, 1, bs->pos, bs->fp);
        bs->pos = 0;
    }
}

void bs_write(BitStream *bs, uint64_t val, int bits) {
    // Pack bits MSB first
    for (int i = bits - 1; i >= 0; i--) {
        uint8_t bit = (val >> i) & 1;
        bs->bit_buffer = (bs->bit_buffer << 1) | bit;
        bs->bit_count++;
        
        if (bs->bit_count == 8) {
            bs->buffer[bs->pos++] = (uint8_t)bs->bit_buffer;
            bs->bit_buffer = 0;
            bs->bit_count = 0;
            
            if (bs->pos == IO_BUFFER_SIZE) {
                fwrite(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
                bs->pos = 0;
            }
        }
    }
}

int bs_read_bit(BitStream *bs) {
    if (bs->bit_count == 0) {
        // Refill buffer if empty
        if (bs->pos >= bs->bytes_in_buf) {
            bs->bytes_in_buf = fread(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
            bs->pos = 0;
            if (bs->bytes_in_buf == 0) return -1; // EOF
        }
        bs->bit_buffer = bs->buffer[bs->pos++];
        bs->bit_count = 8;
    }
    // Extract MSB
    int bit = (bs->bit_buffer >> 7) & 1;
    bs->bit_buffer <<= 1;
    bs->bit_count--;
    return bit;
}

uint16_t bs_read_val(BitStream *bs, int bits) {
    uint16_t val = 0;
    for (int i = 0; i < bits; i++) {
        int b = bs_read_bit(bs);
        if (b == -1) return 0; 
        val = (val << 1) | b;
    }
    return val;
}

// Specialized reader for the Footer that handles buffer boundaries correctly
uint32_t bs_read_aligned_uint32(BitStream *bs) {
    // 1. Discard sub-byte padding bits
    bs->bit_count = 0; 
    
    uint32_t res = 0;
    for (int i = 0; i < 4; i++) {
        if (bs->pos >= bs->bytes_in_buf) {
            bs->bytes_in_buf = fread(bs->buffer, 1, IO_BUFFER_SIZE, bs->fp);
            bs->pos = 0;
            if (bs->bytes_in_buf == 0) break; 
        }
        uint8_t b = bs->buffer[bs->pos++];
        // Reconstruct Little Endian integer
        res |= ((uint32_t)b << (i * 8));
    }
    return res;
}

// --- LZSS Engine (Tree-Based) ---

void init_compressor_state(CompressorState *ctx) {
    // Reset BST arrays to 'Empty' state
    for (int i = WINDOW_SIZE + 1; i <= WINDOW_SIZE + 256; i++) ctx->rson[i] = WINDOW_SIZE;
    for (int i = 0; i < WINDOW_SIZE; i++) ctx->dad[i] = WINDOW_SIZE;
}

// Insert node at 'r' and find longest match
void insert_node(CompressorState *ctx, int r, int *match_pos, int *match_len) {
    int i, p, cmp;
    uint8_t *key = &ctx->window[r];
    
    *match_len = 0;
    p = WINDOW_SIZE + 1 + key[0];
    ctx->rson[r] = ctx->lson[r] = WINDOW_SIZE;
    
    cmp = 1; // FIX: Must initialize comparison state to prevent infinite loops
    
    while (1) {
        if (cmp >= 0) {
            if (ctx->rson[p] != WINDOW_SIZE) p = ctx->rson[p];
            else { ctx->rson[p] = r; ctx->dad[r] = p; return; }
        } else {
            if (ctx->lson[p] != WINDOW_SIZE) p = ctx->lson[p];
            else { ctx->lson[p] = r; ctx->dad[r] = p; return; }
        }
        
        for (i = 1; i < MAX_MATCH; i++)
            if ((cmp = key[i] - ctx->window[p + i]) != 0) break;
            
        if (i > *match_len) {
            *match_pos = p;
            *match_len = i;
            if (i >= MAX_MATCH) break;
        }
    }
    
    // Replace old node 'p' with new node 'r'
    ctx->dad[r] = ctx->dad[p]; 
    ctx->lson[r] = ctx->lson[p]; 
    ctx->rson[r] = ctx->rson[p];
    ctx->dad[ctx->lson[p]] = r; 
    ctx->dad[ctx->rson[p]] = r;
    if (ctx->rson[ctx->dad[p]] == p) ctx->rson[ctx->dad[p]] = r;
    else ctx->lson[ctx->dad[p]] = r;
    ctx->dad[p] = WINDOW_SIZE;
}

void delete_node(CompressorState *ctx, int p) {
    int q;
    if (ctx->dad[p] == WINDOW_SIZE) return;
    
    if (ctx->rson[p] == WINDOW_SIZE) q = ctx->lson[p];
    else if (ctx->lson[p] == WINDOW_SIZE) q = ctx->rson[p];
    else {
        q = ctx->lson[p];
        if (ctx->rson[q] != WINDOW_SIZE) {
            do { q = ctx->rson[q]; } while (ctx->rson[q] != WINDOW_SIZE);
            ctx->rson[ctx->dad[q]] = ctx->lson[q]; 
            ctx->dad[ctx->lson[q]] = ctx->dad[q];
            ctx->lson[q] = ctx->lson[p]; 
            ctx->dad[ctx->lson[p]] = q;
        }
        ctx->rson[q] = ctx->rson[p]; 
        ctx->dad[ctx->rson[p]] = q;
    }
    ctx->dad[q] = ctx->dad[p];
    if (ctx->rson[ctx->dad[p]] == p) ctx->rson[ctx->dad[p]] = q;
    else ctx->lson[ctx->dad[p]] = q;
    ctx->dad[p] = WINDOW_SIZE;
}

// --- Huffman & Heap Logic ---

MinHeap* heap_create(int cap) {
    MinHeap *h = malloc(sizeof(MinHeap));
    CHECK_MALLOC(h);
    h->nodes = malloc(sizeof(Node*) * cap);
    CHECK_MALLOC(h->nodes);
    h->size = 0;
    h->capacity = cap;
    return h;
}

void heap_push(MinHeap *h, Node *n) {
    int i = h->size++;
    while (i && n->freq < h->nodes[(i-1)/2]->freq) {
        h->nodes[i] = h->nodes[(i-1)/2];
        i = (i-1)/2;
    }
    h->nodes[i] = n;
}

Node* heap_pop(MinHeap *h) {
    if (h->size == 0) return NULL;
    Node *res = h->nodes[0];
    h->nodes[0] = h->nodes[--h->size];
    int i = 0;
    while (1) {
        int smallest = i, l = 2*i + 1, r = 2*i + 2;
        if (l < h->size && h->nodes[l]->freq < h->nodes[smallest]->freq) smallest = l;
        if (r < h->size && h->nodes[r]->freq < h->nodes[smallest]->freq) smallest = r;
        if (smallest == i) break;
        Node *temp = h->nodes[i]; h->nodes[i] = h->nodes[smallest]; h->nodes[smallest] = temp;
        i = smallest;
    }
    return res;
}

void get_tree_depths(Node *root, int depth, uint8_t *lens) {
    if (!root) return;
    if (!root->left && !root->right) {
        lens[root->sym] = depth;
        return;
    }
    get_tree_depths(root->left, depth+1, lens);
    get_tree_depths(root->right, depth+1, lens);
}

void free_tree_recursive(Node *root) {
    if (!root) return;
    free_tree_recursive(root->left);
    free_tree_recursive(root->right);
    free(root);
}

// --- Block Processing (Frequency -> Tree -> Codes) ---

void process_block(CompressorState *ctx, BitStream *bs, int token_count, bool is_last) {
    // 1. Build Frequency Table
    uint64_t freqs[SYMBOL_COUNT] = {0};
    for (int i = 0; i < token_count; i++) freqs[ctx->token_buf[i].val]++;
    freqs[256] = 1; // Mandatory End-of-Block symbol

    // 2. Create Huffman Tree
    MinHeap *h = heap_create(SYMBOL_COUNT);
    for (int i = 0; i < SYMBOL_COUNT; i++) {
        if (freqs[i]) {
            Node *n = malloc(sizeof(Node));
            n->sym = i; n->freq = freqs[i]; n->left = n->right = NULL;
            heap_push(h, n);
        }
    }

    // Handle single-node edge case (unlikely but possible)
    if (h->size == 1) {
        Node *n = heap_pop(h);
        Node *dummy = malloc(sizeof(Node));
        dummy->sym = (n->sym == 0) ? 1 : 0; dummy->freq = 0; dummy->left=dummy->right=NULL;
        Node *p = malloc(sizeof(Node));
        p->sym = -1; p->freq = n->freq; p->left = n; p->right = dummy;
        heap_push(h, p);
    }

    while (h->size > 1) {
        Node *l = heap_pop(h);
        Node *r = heap_pop(h);
        Node *p = malloc(sizeof(Node));
        p->sym = -1; p->freq = l->freq + r->freq; p->left = l; p->right = r;
        heap_push(h, p);
    }
    Node *root = heap_pop(h);
    
    uint8_t depths[SYMBOL_COUNT] = {0};
    get_tree_depths(root, 0, depths);

    // 3. Generate Canonical Codes
    CanonicalEntry table[SYMBOL_COUNT];
    uint16_t max_sym = 0;
    uint64_t code = 0;
    int bl_count[32] = {0};
    uint64_t next_code[32];

    for (int i = 0; i < SYMBOL_COUNT; i++) {
        if (depths[i]) {
            max_sym = i;
            bl_count[depths[i]]++;
        }
    }
    for (int i = 1; i < 32; i++) {
        code = (code + bl_count[i-1]) << 1;
        next_code[i] = code;
    }
    for (int i = 0; i <= max_sym; i++) {
        if (depths[i]) {
            table[i].sym = i;
            table[i].len = depths[i];
            table[i].code = next_code[depths[i]]++;
        }
    }

    // 4. Write Block Header
    bs_write(bs, is_last ? 1 : 0, 1); // Last Block Flag
    bs_write(bs, max_sym, 16);        // Max Symbol Index
    
    // Write packed depths (4 bits each)
    for (int i = 0; i <= max_sym; i+=2) {
        uint8_t d1 = depths[i];
        uint8_t d2 = (i + 1 <= max_sym) ? depths[i+1] : 0;
        bs_write(bs, (d1 & 0x0F), 4);
        bs_write(bs, (d2 & 0x0F), 4);
    }

    // 5. Write Payload
    for (int i = 0; i < token_count; i++) {
        int val = ctx->token_buf[i].val;
        bs_write(bs, table[val].code, table[val].len);
        if (ctx->token_buf[i].type == 1) {
            // Write fixed 12-bit distance for Matches
            bs_write(bs, ctx->token_buf[i].dist, 12);
        }
    }
    // Write EOB
    bs_write(bs, table[256].code, table[256].len);

    free(h->nodes); free(h);
    free_tree_recursive(root);
}

// --- Main Compressor ---

void compress(const char *infile, const char *outfile) {
    FILE *in = fopen(infile, "rb");
    FILE *out = fopen(outfile, "wb");
    if (!in || !out) { perror("IO Error"); exit(ERR_IO); }

    // Write Header (Magic)
    uint32_t magic = SIG_MAGIC;
    fwrite(&magic, 4, 1, out);

    CompressorState *ctx = malloc(sizeof(CompressorState));
    CHECK_MALLOC(ctx);
    ctx->token_buf = malloc(BLOCK_SIZE * sizeof(Token));
    CHECK_MALLOC(ctx->token_buf);
    
    init_compressor_state(ctx);
    BitStream bs;
    bs_init(&bs, out, true);
    
    // Pre-fill window
    int s = 0, r = WINDOW_SIZE - MAX_MATCH;
    memset(ctx->window, 0, WINDOW_SIZE * 2);
    
    int len = 0;
    for (; len < MAX_MATCH; len++) {
        int c = fgetc(in);
        if (c == EOF) break;
        ctx->window[r + len] = c;
    }
    
    int match_pos, match_len;
    for (int i = 1; i <= MAX_MATCH; i++) insert_node(ctx, r - i, &match_pos, &match_len);
    insert_node(ctx, r, &match_pos, &match_len);

    uint32_t crc = 0;
    
    // Main Processing Loop
    while (len > 0) {
        int tok_count = 0;
        
        while (tok_count < BLOCK_SIZE && len > 0) {
            if (match_len > len) match_len = len;
            
            if (match_len < MIN_MATCH) {
                match_len = 1;
                ctx->token_buf[tok_count].type = 0;
                ctx->token_buf[tok_count].val = ctx->window[r];
                crc = update_crc32(crc, &ctx->window[r], 1);
            } else {
                ctx->token_buf[tok_count].type = 1;
                ctx->token_buf[tok_count].val = (match_len - 3) + 257; // Length Symbol
                ctx->token_buf[tok_count].dist = (r - match_pos) & WINDOW_MASK;
                crc = update_crc32(crc, &ctx->window[r], match_len);
            }
            tok_count++;

            int last_len = match_len;
            for (int i = 0; i < last_len; i++) {
                int c = fgetc(in);
                delete_node(ctx, s);
                ctx->window[s] = (c == EOF) ? 0 : c;
                if (s < MAX_MATCH - 1) ctx->window[s + WINDOW_SIZE] = ctx->window[s];
                
                s = (s + 1) & WINDOW_MASK;
                r = (r + 1) & WINDOW_MASK;
                
                int new_pos, new_len;
                insert_node(ctx, r, &new_pos, &new_len);
                match_pos = new_pos; match_len = new_len;
            }
            if (feof(in)) len -= last_len;
        }
        
        process_block(ctx, &bs, tok_count, len <= 0);
    }

    bs_flush(&bs);
    
    // Write CRC32 Footer
    fwrite(&crc, 4, 1, out);
    
    printf("Compression Complete.\nCRC32: 0x%08X\n", crc);

    free(ctx->token_buf);
    free(ctx);
    fclose(in); fclose(out);
}

// --- Main Decompressor ---

void decompress(const char *infile, const char *outfile) {
    FILE *in = fopen(infile, "rb");
    FILE *out = fopen(outfile, "wb");
    if (!in || !out) { perror("IO Error"); exit(ERR_IO); }

    uint32_t magic;
    fread(&magic, 4, 1, in);
    if (magic != SIG_MAGIC) { fprintf(stderr, "Error: Invalid file format.\n"); exit(ERR_FMT); }

    BitStream bs;
    bs_init(&bs, in, false);
    
    uint8_t *window = malloc(WINDOW_SIZE);
    CHECK_MALLOC(window);
    int r = 0;
    uint32_t calc_crc = 0;
    
    bool last_block = false;
    while (!last_block) {
        last_block = bs_read_bit(&bs);
        uint16_t max_sym = bs_read_val(&bs, 16);
        
        uint8_t depths[SYMBOL_COUNT] = {0};
        for (int i = 0; i <= max_sym; i+=2) {
            int d1 = bs_read_val(&bs, 4);
            int d2 = bs_read_val(&bs, 4);
            depths[i] = d1;
            if (i+1 <= max_sym) depths[i+1] = d2;
        }

        // Reconstruct Canonical Codes
        CanonicalEntry table[SYMBOL_COUNT];
        int t_count = 0;
        int bl_count[32] = {0};
        uint64_t code = 0;
        uint64_t next_code[32];

        for (int i = 0; i <= max_sym; i++) if (depths[i]) bl_count[depths[i]]++;
        for (int i = 1; i < 32; i++) {
            code = (code + bl_count[i-1]) << 1;
            next_code[i] = code;
        }
        for (int i = 0; i <= max_sym; i++) {
            if (depths[i]) {
                table[t_count].sym = i;
                table[t_count].len = depths[i];
                table[t_count].code = next_code[depths[i]]++;
                t_count++;
            }
        }

        // Decode Loop
        while (1) {
            uint64_t curr_code = 0;
            int curr_len = 0;
            int sym = -1;
            
            // Match bits to codes
            while (sym == -1) {
                int b = bs_read_bit(&bs);
                if (b == -1) break;
                curr_code = (curr_code << 1) | b;
                curr_len++;
                
                for (int k = 0; k < t_count; k++) {
                    if (table[k].len == curr_len && table[k].code == curr_code) {
                        sym = table[k].sym;
                        break;
                    }
                }
            }

            if (sym == 256) break; // End of Block

            if (sym < 257) {
                // Literal
                fputc(sym, out);
                uint8_t b = (uint8_t)sym;
                calc_crc = update_crc32(calc_crc, &b, 1);
                window[r] = b;
                r = (r + 1) & WINDOW_MASK;
            } else {
                // Match
                int len = (sym - 257) + 3;
                int dist = bs_read_val(&bs, 12);
                int src = (r - dist) & WINDOW_MASK;
                
                for (int i = 0; i < len; i++) {
                    uint8_t c = window[(src + i) & WINDOW_MASK];
                    fputc(c, out);
                    calc_crc = update_crc32(calc_crc, &c, 1);
                    window[r] = c;
                    r = (r + 1) & WINDOW_MASK;
                }
            }
        }
    }

    // Verify CRC Integrity
    // We must use the buffer-aware reader to grab the footer
    uint32_t file_crc = bs_read_aligned_uint32(&bs);
    
    printf("Decompression Complete.\n");
    printf("Computed CRC: 0x%08X\n", calc_crc);
    printf("File CRC:     0x%08X\n", file_crc);
    
    if (calc_crc != file_crc) {
        fprintf(stderr, "Fatal: Checksum Mismatch! Data Corrupted.\n");
        exit(ERR_FMT);
    } else {
        printf("Integrity Verified: OK.\n");
    }

    free(window);
    fclose(in); fclose(out);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s -c|-d <input> <output>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-c") == 0) {
        compress(argv[2], argv[3]);
    } else if (strcmp(argv[1], "-d") == 0) {
        decompress(argv[2], argv[3]);
    } else {
        fprintf(stderr, "Invalid mode flag.\n");
        return 1;
    }

    return 0;
}