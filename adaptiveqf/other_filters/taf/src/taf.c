#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <execinfo.h>
#include <time.h>
#include <openssl/rand.h>
#include <sys/time.h>

#include "murmur3.h"
#include "macros.h"
#include "arcd.h"
#include "taf.h"
#include "bit_util.h"
#include "set.h"

/**
 * Generate a hash for the input word.
 * Returns the full 128 bit murmurhash.
 * Expects a two-slot array of uint64_t's.
 */
static uint64_t taf_hash(const TAF *filter, elt_t elt) {
  uint64_t buf[2];
  MurmurHash3_x64_128(&elt, 8, filter->seed, buf);
  return buf[0];
}

/**
 * Returns the quotient for a 64-bit fingerprint hash.
 */
static size_t calc_quot(const TAF* filter, uint64_t hash) {
  return hash & ONES(filter->q);
}

/**
 * Returns the k-th remainder for h
 */
static rem_t calc_rem(const TAF* filter, uint64_t hash, int k) {
  int n_rems = (64 - (int)filter->q)/(int)filter->r;
  if (k >= n_rems) k %= n_rems;
  return (hash >> (filter->q + k * filter->r)) & ONES(filter->r);
}

/* TAF Helpers */

/**
 * @return The selector code at block `block_i`, padded with zeros as a uint64_t.
 */
static uint64_t get_sel_code(const TAF* filter, size_t block_i) {
  uint64_t code = 0;
  memcpy(&code, filter->blocks[block_i].sel_code, SEL_CODE_BYTES);
  return code;
}

/**
 * Set the selector code for the `block_i`-th block to the first `CODE_BYTES`
 * bits of `code`.
 */
static void set_sel_code(TAF* filter, size_t block_i, uint64_t code) {
  memcpy(filter->blocks[block_i].sel_code, &code, SEL_CODE_BYTES);
}

/**
 * Print an array of selectors.
 */
static void print_sels(const int sels[64]) {
  for (int i=0; i<8; i++) {
    printf("   ");
    for (int j=0; j<8; j++) {
      int sel = sels[i*8 + j];
      if (sel == 0) {
        printf(" _");
      } else {
        printf(" %d", sel);
      }
    }
    printf("\n");
  }
}

/**
 * Returns the absolute index of the `rank`-th 1 bit in Q.runends past the start of
 * the block at `block_index`. `rank` indexes from 0.
 *
 * Returns -1 if result is invalid (out of bounds).
 */
static int select_runend(const TAF* filter, size_t block_index, size_t rank) {
  assert(block_index < filter->nblocks && "block_index out of bounds");

  size_t step;
  size_t loc = block_index * 64;
  while (1) {
    TAFBlock* b = &filter->blocks[loc / 64];
    step = bitselect(b->runends, rank >= 64 ? 63 : (int)rank);
    loc += step;
    if (step != 64 || loc >= filter->nslots) {
      break;
    }
    rank -= popcnt(b->runends);
  }
  if (loc >= filter->nslots) {
    return -1;
  } else {
    return (int)loc;
  }
}

#define RANK_SELECT_EMPTY (-1)
#define RANK_SELECT_OVERFLOW (-2)
/** Performs the blocked equivalent of the unblocked operation
 *    y = select(Q.runends, rank(Q.occupieds, x)).
 *  Note: x indexes from 0.
 *
 *  Return behavior:
 *  - If y <= x, returns Empty
 * - If y > x, returns Full(y)
 * - If y runs off the edge, returns Overflow
 */
static int rank_select(const TAF* filter, size_t x) {
  // Exit early if x obviously out of range
  if (x >= filter->nslots) {
    return RANK_SELECT_OVERFLOW;
  }
  size_t block_i = x/64;
  size_t slot_i = x%64;
  TAFBlock *b = &filter->blocks[block_i];

  // Compute i + O_i where i = x - (x mod 64)
  if (!GET(b->occupieds, 0) && b->offset == 0 && !GET(b->runends, 0)) {
    // b[0] unoccupied, b.offset = 0, b[0] not a runend =>
    // negative offset
    if (slot_i == 0) {
      return RANK_SELECT_EMPTY;
    }
  } else {
    // non-negative offset
    if (slot_i == 0) {
      return (int)(block_i * 64 + b->offset);
    } else {
      block_i += b->offset/64;
    }
  }

  // Handle case where offset runs off the edge
  if (block_i >= filter->nblocks) {
    return RANK_SELECT_OVERFLOW;
  }

  // Count the number of occupied quotients between i+1 (b.start + i) and j (x)
  uint64_t d = bitrank(b->occupieds, slot_i) - GET(b->occupieds, 0);

  // Advance offset to relevant value for the block that b.offset points to
  size_t offset = b->offset % 64;
  b = &filter->blocks[block_i];

  // Account for the runends in [0, offset] of the new block
  d += bitrank(b->runends, offset);

  // If rank(Q.occupieds, x) == 0, then there's nothing to see here
  if (d == 0) {
    return RANK_SELECT_EMPTY;
  } else {
    // (rank-1) accounts for select's indexing from 0
    int loc = select_runend(filter, block_i, d-1);
    if (loc == -1) {
      return RANK_SELECT_OVERFLOW;
    } else if (loc < x) {
      return RANK_SELECT_EMPTY;
    } else {
      return loc;
    }
  }
}

#define NO_UNUSED (-1)
/**
 * Finds the first unused slot at or after absolute location x.
 */
static int first_unused(const TAF* filter, size_t x) {
  while (1) {
    int loc = rank_select(filter, x);
    switch (loc) {
      case RANK_SELECT_EMPTY: return x;
      case RANK_SELECT_OVERFLOW: return NO_UNUSED;
      default:
        if (x <= loc) {
          x = loc + 1;
        } else {
          return x;
        }
    }
  }
}

/**
 * Shift the remainders and runends in [a, b] forward by 1 into [a+1, b+1]
 */
static void shift_rems_and_runends(TAF* filter, int a, int b) {
  if (a > b) return;
  for (int i=b; i>=a; i--) {
    remainder(filter, i+1) = remainder(filter, i);
    set_runend_to(filter, i+1, get_runend(filter, i));
  }
  set_runend_to(filter, a, 0);
}

/**
 * Shift the remote elements in [a,b] forward by 1
 */
static void shift_remote_elts(TAF* filter, int a, int b) {
  if (a > b) return;
  for (int i=b; i>=a; i--) {
    filter->remote[i+1] = filter->remote[i];
  }
  filter->remote[a].elt = 0;
  filter->remote[a].hash = 0;
}

static void inline swap_ptrs(int **a, int **b) {
  int *tmp = *a;
  *a = *b;
  *b = tmp;
}

/**
 * Helper for `shift_sels`.  Shifts sels in `[0, b]` a single block.
 */
static void shift_block_sels(TAF *filter, int block_i, int sels[64], const int prev_sels[64], int b) {
  uint64_t code;
  for (int i=b; i > 0; i--) {
    sels[i] = sels[i-1];
  }
  sels[0] = prev_sels[63];
  if (encode_sel(sels, &code) == -1) {
    code = 0;
  }
  set_sel_code(filter, block_i, code);
}

/**
 * Shift the hash selectors in [a,b] forward by 1
 */
static void shift_sels(TAF* filter, int a, int b) {
  if (a > b) return;
  uint64_t code;
  if (a/64 == (b+1)/64) {
    // a and b+1 in the same block
    int sels[64];
    decode_sel(get_sel_code(filter, a/64), sels);
    for (int i = (b+1)%64; i > a%64; i--) {
      sels[i] = sels[i-1];
    }
    sels[a%64] = 0;
    if (encode_sel(sels, &code) == -1) {
      code = 0;
    }
    set_sel_code(filter, a/64, code);
  } else {
    // a and b+1 in different blocks
    int* sels = malloc(64 * sizeof(int));
    int* prev_sels = malloc(64 * sizeof(int));
    // (1) last block
    int block_i = (b+1)/64;
    decode_sel(get_sel_code(filter, block_i), sels);
    decode_sel(get_sel_code(filter, block_i - 1), prev_sels);
    shift_block_sels(filter, block_i, sels, prev_sels, (b + 1) % 64);
    swap_ptrs(&sels, &prev_sels);
    // (2) middle blocks
    for (block_i--; block_i > a/64; block_i--) {
      decode_sel(get_sel_code(filter, block_i - 1), prev_sels);
      shift_block_sels(filter, block_i, sels, prev_sels, 63);
      swap_ptrs(&sels, &prev_sels);
    }
    // (3) first block
    for (int i=63; i>a%64; i--) {
      sels[i] = sels[i-1];
    }
    sels[a%64] = 0;
    if (encode_sel(sels, &code) == -1) {
      code = 0;
    }
    set_sel_code(filter, a/64, code);
    free(sels);
    free(prev_sels);
  }
}

/**
 * Increment all non-negative offsets with targets in [a,b]
 */
static void inc_offsets(TAF* filter, size_t a, size_t b) {
  assert(a < filter->nslots && b < filter->nslots);
  // Exit early if invalid range
  if (a > b) {
    return;
  }
  // Start i at the first block after b, clamping it so it doesn't go off the end, and work backwards
  size_t start = min(b/64 + 1, filter->nblocks - 1);
  for (int i = start; i>=0; i--) {
    TAFBlock *block = &filter->blocks[i];
    size_t block_start = i * 64;
    // Skip this block if it has a negative offset
    if (!GET(block->occupieds, 0) &&
        block->offset == 0 &&
        !GET(block->runends, 0)) {
      continue;
    }
    // Exit if the target for b.offset is before the interval;
    // if it's within the interval, increment offset
    size_t target = block_start + block->offset;
    if (target < a) {
      break;
    } else if (target <= b) {
      block->offset++;
    }
  }
}

/**
 * Increment non-negative offsets to accommodate insertion of a new run
 * for `quot` at `loc`.
 *
 * Concretely, this function increments unowned offsets in blocks whose
 * first slot `s` is not after `quot`: `s >= quot`.
 */
static void inc_offsets_for_new_run(TAF* filter, size_t quot, size_t loc) {
  assert(loc < filter->nslots);
  // Start i at the first block after loc,
  // clamping it so it doesn't go off the end
  size_t start = min(loc/64 + 1, filter->nblocks - 1);
  for (int i=start; i>=0; i--) {
    TAFBlock *b = &filter->blocks[i];
    size_t b_start = i*64;
    // Skip this block if it has a negative offset
    if (!GET(b->occupieds, 0) && b->offset == 0 && !GET(b->runends, 0)) {
      continue;
    }
    // Exit if the target for b.offset is before the interval;
    // if the target is within the interval, increment b.offset
    size_t target = b_start + b->offset;
    if (target < loc) {
      break;
    } else if (target == loc && !GET(b->occupieds, 0) && quot <= b_start) {
      b->offset++;
    }
  }
}

static void add_block(TAF *filter) {
  // Add block to new_blocks
  TAFBlock *new_blocks = realloc(filter->blocks, (filter->nblocks + 1) * sizeof(TAFBlock));
  if (new_blocks == NULL) {
    printf("add_block failed to realloc new blocks\n");
    exit(1);
  }
  filter->blocks = new_blocks;
  memset(filter->blocks + filter->nblocks, 0, sizeof(TAFBlock));

  // Reallocate remote rep
  Remote_elt *new_remote = realloc(filter->remote,(filter->nslots + 64) * sizeof(Remote_elt));
  if (new_remote == NULL) {
    printf("add_block failed to realloc new remote rep\n");
    exit(1);
  }
  filter->remote = new_remote;
  memset(filter->remote + filter->nslots, 0, 64 * sizeof(Remote_elt));

  // Update counters
  filter->nblocks += 1;
  filter->nslots += 64;
}

/**
 * Adapt a fingerprint at a particular location by incrementing the selector and
 * updating the remainder.
 */
static void adapt_loc(TAF *filter, size_t loc, int sels[64]) {
  // Increment selector at loc%64
  int old_sel = sels[loc%64];
  int new_sel = (old_sel + 1) % MAX_SELECTOR;
  sels[loc%64] = new_sel;
  // Write encoding to block
  uint64_t code;
  if (encode_sel(sels, &code) == -1) {
    // Encoding failed: rebuild
    // Reset all remainders and selectors in block
    memset(sels, 0, 64 * sizeof(sels[0]));
    TAFBlock *b = &filter->blocks[loc/64];
    uint64_t b_start = loc - (loc % 64);
    for (int i=0; i<64; i++) {
      b->remainders[i] = calc_rem(filter, filter->remote[b_start + i].hash, 0);
    }
    // Set sel to new_sel and attempt encode
    sels[loc % 64] = new_sel;
    if (encode_sel(sels, &code) == -1) {
      fprintf(stderr, "Encoding (sel=%d) failed after rebuild!\n", new_sel);
      sels[loc % 64] = 0;
      new_sel = 0;
      code = 0;
    }
  }
  // Encoding succeeded: update sel_code and remainder
  rem_t new_rem = calc_rem(filter, filter->remote[loc].hash, new_sel);
  switch (filter->mode) {
    case TAF_MODE_NORMAL:
      remainder(filter, loc) = new_rem;
      set_sel_code(filter, loc/64, code);
      break;
    case TAF_MODE_ARCD_OVERWRITE:
      remainder(filter, loc) = remainder(filter, loc);
      set_sel_code(filter, loc/64, 0);
      break;
  }
}

/**
 * Adapt on a query element that collided with a stored fingerprint at loc.
 *
 * Go through the rest of the run and fix any other remaining collisions.
 */
static void adapt(TAF *filter, elt_t query, int loc, size_t quot, uint64_t hash, int sels[64]) {
  assert(quot <= loc && loc < filter->nslots);
  // Make sure the query elt isn't mapped to an earlier index in the sequence
  for (int i=loc; i>=(int)quot && (i == loc || !get_runend(filter, i)); i--) {
    if (filter->remote[i].elt == query) {
      return;
    }
  }
  // Adapt on all collisions in the run
  for (int i=loc; i>=(int)quot && (i == loc || !get_runend(filter, i)); i--) {
    // Re-decode if at a new block
    if (i != loc && i % 64 == 63) {
      decode_sel(get_sel_code(filter, i/64), sels);
    }
    // Check collision
    int sel = sels[i % 64];
    if (remainder(filter, i) == calc_rem(filter, hash, sel)) {
      adapt_loc(filter, i, sels);
    }
  }
}

/* TAF */

void taf_init(TAF *filter, size_t n, int seed) {
  filter->seed = seed;
  filter->nelts = 0;
  filter->nblocks = max(1, nearest_pow_of_2(n)/64);
  filter->nslots = filter->nblocks * 64;
  filter->q = (size_t)log2((double)filter->nslots); // nslots = 2^q
  filter->r = REM_SIZE;
  filter->p = filter->q + filter->r;
  filter->blocks = calloc(filter->nblocks, sizeof(TAFBlock));
  filter->remote = calloc(filter->nslots, sizeof(Remote_elt));
  filter->mode = TAF_MODE_NORMAL;
}

void taf_destroy(TAF* filter) {
  free(filter->blocks);
  free(filter->remote);
  free(filter);
}

void taf_clear(TAF* filter) {
  filter->nelts = 0;
  free(filter->blocks);
  free(filter->remote);
  filter->blocks = calloc(filter->nblocks, sizeof(TAFBlock));
  filter->remote = calloc(filter->nslots, sizeof(Remote_elt));
}

int extra_blocks = 0;
static void raw_insert(TAF* filter, elt_t elt, uint64_t hash) {
  size_t quot = calc_quot(filter, hash);
  rem_t rem = calc_rem(filter, hash, 0);
  filter->nelts++;

  // Find the appropriate runend
  int r = rank_select(filter, quot);
  switch (r) {
    case RANK_SELECT_EMPTY: {
      set_occupied(filter, quot);
      set_runend(filter, quot);
      remainder(filter, quot) = rem;
      filter->remote[quot].elt = elt;
      filter->remote[quot].hash = hash;
      break;
    }
    case RANK_SELECT_OVERFLOW: {
      printf("TAF failed to find runend (nslots=%lu, quot=(block=%lu, slot=%lu))\n",
             filter->nslots, quot/64, quot%64);
      exit(1);
    }
    default: {
      // Find u, the first open slot after r, and
      // shift everything in [r+1, u-1] forward by 1 into [r+2, u],
      // leaving r+1 writable
      size_t u = first_unused(filter, r+1);
      if (u == NO_UNUSED) {
        // Extend filter by one block and use the first empty index
        add_block(filter);
        u = filter->nslots - 64;
	extra_blocks++;
      }
      inc_offsets(filter, r+1, u-1);
      shift_rems_and_runends(filter, r + 1, (int)u - 1);
      shift_remote_elts(filter, r + 1, (int)u - 1);
      shift_sels(filter, r + 1, (int)u - 1);

      // Start a new run or extend an existing one
      if (get_occupied(filter, quot)) {
        // quot occupied: extend an existing run
        inc_offsets(filter, r, r);
        unset_runend(filter, r);
      } else {
        // quot unoccupied: start a new run
        inc_offsets_for_new_run(filter, quot, r);
        set_occupied(filter, quot);
      }
      set_runend(filter, r+1);
      remainder(filter, r+1) = rem;
      filter->remote[r+1].elt = elt;
      filter->remote[r+1].hash = hash;
    }
  }
}

static int raw_lookup(TAF* filter, elt_t elt, uint64_t hash) {
  size_t quot = calc_quot(filter, hash);

  if (get_occupied(filter, quot)) {
    int loc = rank_select(filter, quot);
    if (loc == RANK_SELECT_EMPTY || loc == RANK_SELECT_OVERFLOW) {
      return 0;
    }
    // Cache decoded selectors
    int decoded[64];
    int decoded_i = -1;
    do {
      // Refresh cached code
      if (decoded_i != loc/64) {
        decoded_i = loc/64;
        uint64_t code = get_sel_code(filter, loc/64);
        decode_sel(code, decoded);
      }
      int sel = decoded[loc%64];
      rem_t rem = calc_rem(filter, hash, sel);
      if (remainder(filter, loc) == rem) {
        // Check remote
        if (elt != filter->remote[loc].elt) {
          adapt(filter, elt, loc, quot, hash, decoded);
        }
        return loc;
      }
      loc--;
    } while (loc >= (int)quot && !get_runend(filter, loc));
  }
  return 0;
}

/**
 * Return 1 if word is in the filter.
 *
 * Exits with 0 immediately if quot(word) is unoccupied.
 * Otherwise, linear probes through the run to see if the
 * run contains rem(word).
 */
int taf_lookup(TAF *filter, elt_t elt) {
  uint64_t hash = taf_hash(filter, elt);
  return raw_lookup(filter, elt, hash);
}

void taf_insert(TAF *filter, elt_t elt) {
  uint64_t hash = taf_hash(filter, elt);
  raw_insert(filter, elt, hash);
}

double taf_load(TAF *filter) {
  return (double)filter->nelts/(double)filter->nslots;
}

/* Printing */

void print_taf_metadata(TAF* filter) {
  printf("FILTER METADATA:\n");
  printf("  p=%ld, q=%ld, r=%ld\n",
         filter->p, filter->q, filter->r);
  printf("  nslots=%ld, nblocks=%ld, blocksize=%ld, nelts=%ld\n",
         filter->nslots, filter->nslots/64, sizeof(TAFBlock), filter->nelts);
  printf("  seed=%d\n", filter->seed);
  printf("  load factor=%f\n", taf_load(filter));
}

void print_taf_block(TAF* filter, size_t block_index) {
  assert(0 <= block_index && block_index < filter->nslots/64);
  TAFBlock block = filter->blocks[block_index];
  printf("BLOCK %lu:\n", block_index);
  printf("  occupieds=0x%lx\n", block.occupieds);
  printf("  runends=0x%lx\n", block.runends);
  printf("  offset=%ld\n", block.offset);
  printf("  remainders=\n");
  // Print out 8x8
  for (int i=0; i<8; i++) {
    printf("   ");
    for (int j=0; j<8; j++) {
      printf(get_occupied(filter, block_index*64 + i*8 + j) ? "o" : " ");
      printf(get_runend(filter, block_index*64 + i*8 + j) ? "r" : " ");
      printf(" 0x%-*x", (int)(filter->r / 8 + 3), block.remainders[i*8+j]);
    }
    printf("\n");
  }
  printf("  selector code=0x%lx\n", get_sel_code(filter, block_index));
  printf("  selectors=\n");
  int sels [64];
  decode_sel(get_sel_code(filter, block_index), sels);
  print_sels(sels);
  printf("  remote elts=\n");
  for (int i=0; i<8; i++) {
    printf("   ");
    for (int j=0; j<8; j++) {
      printf(" 0x%-*lx", 8, filter->remote[block_index * 64 + i*8 + j].elt);
    }
    printf("\n");
  }
}

void print_taf(TAF* filter) {
  print_taf_metadata(filter);
  for (int i=0; i<filter->nblocks; i++) {
    print_taf_block(filter, i);
  }
}

void print_taf_stats(TAF* filter) {
  printf("TAF stats:\n");
  // Hash selector counts
  int sel_counts[MAX_SELECTOR];
  for (int i=0; i<MAX_SELECTOR; i++) {
    sel_counts[i] = 0;
  }
  int sels[64];
  for (int i=0; i<filter->nslots; i++) {
    if (i%64 == 0) {
      decode_sel(get_sel_code(filter, i/64), sels);
    }
    sel_counts[sels[i%64]]++;
  }
  printf("Hash selector counts:\n");
  for (int i=0; i<MAX_SELECTOR; i++) {
    printf(" %d: %d (%f%%)\n", i, sel_counts[i],
           100 * (double)sel_counts[i]/(double)filter->nslots);
  }
}

// Tests
//#define TEST_TAF 1
#ifdef TEST_TAF

void print_backtrace() {
  void* callstack[128];
  int i, frames = backtrace(callstack, 128);
  char** strs = backtrace_symbols(callstack, frames);
  printf("\n");
  for (i = 0; i < frames; ++i) {
    printf("%s\n", strs[i]);
  }
  free(strs);
}

#define assert_eq(a, b) assert((a) == (b))

#define test_assert_eq(a, b, msg, ...)   \
  if ((a) != (b)) {                 \
    do {                            \
      fprintf(stderr, "Assertion failed: %s != %s: ", #a, #b); \
      fprintf(stderr, msg"\n", __VA_ARGS__); \
      assert_eq(a, b);              \
    } while (0);                    \
  }

#define TAF_SEED 32776517

TAF *new_taf(size_t n) {
  TAF *filter = malloc(sizeof(TAF));
  taf_init(filter, n, TAF_SEED);
  return filter;
}

void test_calc_rem() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(128);

  // q = 7, r = 8
  for (int i=0; i<16; i++) {
    assert_eq(calc_rem(filter, 0, i), 0);
    assert_eq(calc_rem(filter, 0b1111111, i), 0);
  }
  assert_eq(calc_rem(filter, 0b10000000, 0), 1);
  for (int i=1; i<7; i++) {
    assert_eq(calc_rem(filter, 0b10000000, i), 0);
  }
  assert_eq(calc_rem(filter, 0b111000001110000000, 0), 0b111);
  assert_eq(calc_rem(filter, 0b111000001110000000, 1), 0b111);
  for (int i=2; i<7; i++) {
    assert_eq(calc_rem(filter, 0b111000001110000000, i), 0);
  }
  assert_eq(calc_rem(filter, 0b111000001110000000, 7), 0b111);
  assert_eq(calc_rem(filter, 0b111000001110000000, 8), 0b111);

  taf_destroy(filter);
  printf("passed.\n");
}

void test_add_block() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(64 * 2);
  assert_eq(filter->nslots, 128);
  assert_eq(filter->nblocks, 2);
  add_block(filter);
  // Check metadata
  assert_eq(filter->nslots, 192);
  assert_eq(filter->nblocks, 3);
  // Check new block
  TAFBlock b = filter->blocks[2];
  assert_eq(b.occupieds, 0);
  assert_eq(b.runends, 0);
  assert_eq(b.offset, 0);
  for (int i=0; i<64; i++) {
    assert_eq(b.remainders[i], 0);
  }
  // Check remote rep
  for (int i=0; i<64; i++) {
    assert_eq(filter->remote[128 + i].elt, 0);
    assert_eq(filter->remote[128 + i].hash, 0);
  }
  taf_destroy(filter);
  printf("passed.\n");
}

/// Check that adding a block doesn't overwrite existing data
void test_add_block_no_clobber() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(128);

  // Setup
  for (int i=0; i<filter->nslots; i++) {
    set_occupied(filter, i);
    set_runend(filter, i);
    remainder(filter, i) = i%16;
    filter->remote[i].elt = i;
    filter->remote[i].hash = i;
  }
  add_block(filter);
  // Check that data in first 2 blocks is preserved
  for (int i=0; i<128; i++) {
    assert(get_occupied(filter, i));
    assert(get_runend(filter, i));
    assert_eq(remainder(filter, i), i%16);
    assert_eq(filter->remote[i].elt, i);
    assert_eq(filter->remote[i].hash, i);
  }
  // Check that 3rd block is empty
  for (int i=128; i<filter->nslots; i++) {
    assert(!get_occupied(filter, i));
    assert(!get_runend(filter, i));
    assert_eq(remainder(filter, i), 0);
    assert_eq(filter->remote[i].elt, 0);
    assert_eq(filter->remote[i].hash, 0);
  }
  // Check filter metadata
  assert_eq(filter->nslots, 192);
  assert_eq(filter->nblocks, 3);

  taf_destroy(filter);
  printf("passed.\n");
}

void test_adapt_loc_1() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(128);
  // q=7, r=8
  uint64_t code;
  int sels[64];
  code = get_sel_code(filter, 0);
  assert_eq(code, 0);
  decode_sel(code, sels);
  for (int i=0; i<64; i++) {
    assert_eq(sels[i], 0);
  }
  adapt_loc(filter, 0, sels);
  decode_sel(get_sel_code(filter, 0), sels);
  assert_eq(sels[0], 1);
  for (int i=1; i<64; i++) {
    assert_eq(sels[i], 0);
  }
  taf_destroy(filter);
  printf("passed.\n");
}

void test_adapt_loc_2() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(128);
  // q=7, r=8
  int sels[64];
  for (int i=0; i<64; i++) {
    sels[i] = 0;
  }
  // Push encoding to limit (15 1's)
  int limit = 15;
  for (int i=0; i<limit; i++) {
    adapt_loc(filter, i, sels);
  }
  decode_sel(get_sel_code(filter, 0), sels);
  for (int i=0; i<limit; i++) {
    assert_eq(sels[i], 1);
  }
  for (int i=limit; i<64; i++) {
    assert_eq(sels[i], 0);
  }
  adapt_loc(filter, limit, sels);
  for (int i=0; i<64; i++) {
    test_assert_eq(sels[i], i == limit, "i=%d", i);
  }
  taf_destroy(filter);
  printf("passed.\n");
}

void test_adapt_loc_3() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(128);
  // q=7, r=8
  int sels[64];
  for (int i=0; i<64; i++) {
    sels[i] = 0;
  }
  // Push encoding to limit (five 2's, one 1)
  int limit = 5;
  for (int i=0; i<5; i++) {
    adapt_loc(filter, i, sels);
    adapt_loc(filter, i, sels);
  }
  decode_sel(get_sel_code(filter, 0), sels);
  for (int i=0; i<limit; i++) {
    assert_eq(sels[i], 2);
  }
  for (int i=limit; i<64; i++) {
    assert_eq(sels[i], 0);
  }
  adapt_loc(filter, limit, sels);
  for (int i=0; i<64; i++) {
    test_assert_eq(sels[i], i < limit ? 2 : (i == limit ? 1 : 0), "i=%d", i);
  }
  adapt_loc(filter, limit, sels);
  for (int i=0; i<64; i++) {
    test_assert_eq(sels[i], i == limit ? 2 : 0, "i=%d", i);
  }
  taf_destroy(filter);
  printf("passed.\n");
}

void test_adapt_1() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(64);

  printf("[Unimplemented] ");

  taf_destroy(filter);
  printf("passed.\n");
}

void test_raw_lookup_1() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(128);

  printf(" [Unimplemented] ");

  taf_destroy(filter);
  printf("passed.\n");
}

void test_raw_insert_1() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(128);

  printf(" [Unimplemented] ");

  taf_destroy(filter);
  printf("passed.\n");
}

void test_shift_remote_elts() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(128);
  for (int i=0; i<filter->nslots; i++) {
    assert_eq(filter->remote[i].elt, 0);
    assert_eq(filter->remote[i].hash, 0);
  }
  for (int i=0; i<filter->nslots; i++) {
    filter->remote[i].elt = i;
    filter->remote[i].hash = i;
  }
  // Shift elts in [32, 64+32] to [33, 64+33]
  shift_remote_elts(filter, 32, 64+32);
  for (int i=0; i<=31; i++) {
    assert_eq(filter->remote[i].elt, i);
    assert_eq(filter->remote[i].hash, i);
  }
  assert_eq(filter->remote[32].elt, 0);
  assert_eq(filter->remote[32].hash, 0);
  for (int i=33; i<=64+33; i++) {
    assert_eq(filter->remote[i].elt, i-1);
    assert_eq(filter->remote[i].hash, i-1);
  }
  for (int i=64+34; i<filter->nslots; i++) {
    assert_eq(filter->remote[i].elt, i);
    assert_eq(filter->remote[i].hash, i);
  }
  taf_destroy(filter);
  printf("passed.\n");
}

double rand_zipfian(double s, double max, uint64_t source) {
        double p = (double)source / (-1ULL);

        double pD = p * (12 * (pow(max, -s + 1) - 1) / (1 - s) + 6 + 6 * pow(max, -s) + s - s * pow(max, -s + 1));
        double x = max / 2;
        while (1) {
                double m = pow(x, -s - 2);
                double mx = m * x;
                double mxx = mx * x;
                double mxxx = mxx * x;

                double b = 12 * (mxxx - 1) / (1 - s) + 6 + 6 * mxx + s - (s * mx) - pD;
                double c = 12 * mxx - (6 * s * mx) + (m * s * (s + 1));
                double newx = x - b / c > 1 ? x - b / c : 1;
                if (abs(newx - x) <= 0.01) { // this is the tolerance for approximation
                        return newx;
                }
                x = newx;
        }
}

uint64_t hash_str(char *str) {
        uint64_t hash = 5381;
        int c;
        while ((c = *str++)) {
                hash = ((hash << 5) + hash) + c;
        }
        return hash;
}

void csv_get(char* buffer, int col) {
        int i, j;
        for (i = 0; buffer[i] != '\0' && col > 0; i++) {
                if (buffer[i] == ',') col--;
        }
        for (j = 0; buffer[i + j] != '\0' && buffer[i + j] != ','; j++) {
                buffer[j] = buffer[i + j];
        }
        buffer[j] = '\0';
}

double avg_insert_time = 0;
double avg_query_time = 0;
double avg_fp_rate = 0;

/// General integration test: insert and query elts, ensuring that there
/// are no false negatives
void test_insert_and_query() {
  printf("Testing %s...", __FUNCTION__);
  size_t a = 1 << 20;
  double a_s = 100.0; // a/s
  double load = 0.9;
  size_t s = nearest_pow_of_2((size_t)((double)a / a_s));
  s = (size_t)((double)s * load);
  TAF* filter = new_taf(a);
  s = a * load;

  // Generate query set
  srandom(time(NULL));
  int nset = (int)(1.5*(double)s);
  Setnode* set = calloc(nset, sizeof(set[0]));

  elt_t *elts_to_insert = malloc(s * sizeof(elt_t));
  RAND_bytes((unsigned char*)elts_to_insert, s * sizeof(elt_t));

  char str[64];

  double measurement_interval = 0.05f;
  double current_measurement_point = measurement_interval;
  uint64_t next_measurement = current_measurement_point * a;

	clock_t end_clock, start_clock = clock();
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t start_time = tv.tv_sec * 1000000 + tv.tv_usec, end_time, interval_time = start_time;

  for (int i = 0; i < s; i++) {
	  sprintf(str, "%lu", elts_to_insert[i]);
	  set_insert(str, (int)strlen(str), 0, set, nset);
	  taf_insert(filter, elts_to_insert[i]);

	  if (i > next_measurement) {
		  printf("%f:\t%f\n", current_measurement_point, 1000000.0f * (measurement_interval * a) / (clock() - start_time));
		  current_measurement_point += measurement_interval;
		  next_measurement = current_measurement_point * a;
		  start_time = clock();
	  }
  }
  printf("%f:\t%f\n", current_measurement_point, 1000000.0f * (measurement_interval * a) / (clock() - start_time));

	gettimeofday(&tv, NULL);
	end_time = tv.tv_sec * 1000000 + tv.tv_usec;
	end_clock = clock();
	printf("Time for inserts: %f sec\n", (double)(end_time - start_time) / 1000000);
  printf("Insert throughput: %f ops/sec\n", (double)s * 1000000 / (end_time - start_time));
  printf("CPU time for inserts: %f sec\n", (double)(end_clock - start_clock) / CLOCKS_PER_SEC);

  /*char str[64];
  clock_t start_time = clock();
  for (int i=0; i<s; i++) {
    elt_t elt = random();
    sprintf(str, "%lu", elt);
    set_insert(str, (int)strlen(str), 0, set, nset);
    taf_insert(filter, elt);
    //assert(set_lookup(str, (int)strlen(str), set, nset));
    //assert(taf_lookup(filter, elt));
  }
  clock_t end_time = clock();
  avg_insert_time += (double)(end_time - start_time) / s;*/

  int num_queries = 200000000;
  // Query [0, a] and ensure that all items in the set return true
  int fps = 0;
  int fns = 0;

  elt_t *query_set = calloc(num_queries, sizeof(elt_t));
  RAND_bytes((unsigned char*)query_set, num_queries * sizeof(elt_t));
  /*int hash_seed = rand();
  for (int i = 0; i < num_queries; i++) {
  	query_set[i] = rand_zipfian(1.5f, 10000000ull, query_set[i]);
	query_set[i] = MurmurHash64A(&query_set[i], sizeof(query_set[i]), hash_seed);
  }*/

  start_clock = clock();
  for (int i=0; i<num_queries; i++) {
	  elt_t elt;
    //elt = i;
    //elt = rand_zipfian(1.5f, 1lu << 30);
    //elt = random();
    elt = query_set[i];
    sprintf(str, "%lu", elt);
    int in_set = set_lookup(str, (int)strlen(str), set, nset);
    int in_taf = taf_lookup(filter, elt);
    if (in_set && !in_taf) {
      fns++;
      uint64_t hash = taf_hash(filter, elt);
      size_t quot = calc_quot(filter, hash);
      if (get_occupied(filter, quot)) {
        int loc = rank_select(filter, quot);
        if (loc == RANK_SELECT_EMPTY || loc == RANK_SELECT_OVERFLOW) {
          printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu)"
                 " was occupied but didn't have an associated runend\n",
                 elt, elt, quot, quot/64, quot%64);
          print_taf_block(filter, quot/64);
          exit(1);
        } else {
          int sels[64];
          decode_sel(get_sel_code(filter, loc/64), sels);
          int sel = sels[loc%64];
          rem_t query_rem = calc_rem(filter, hash, sel);
          rem_t stored_rem = remainder(filter, loc);
          printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu),"
                 "loc=%d (block=%d, slot=%d); stored rem=0x%hhx doesn't match query rem=0x%hhx\n",
                 elt, elt, quot, quot/64, quot%64, loc, loc/64, loc%64, stored_rem, query_rem);
          print_taf_metadata(filter);
          print_taf_block(filter, loc/64);
          exit(1);
        }
      } else {
        printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu) wasn't occupied\n",
               elt, elt, quot, quot/64, quot%64);
        exit(1);
      }
    } else if (!in_set && in_taf) {
      //fps += in_taf;
      fps++;
    }
    /*if (i % 100 == 0) {
	    printf("%d,%f\n", i, (double)fps / i);
    }*/
  }
  end_clock = clock();
  avg_query_time += (double)(end_clock - start_clock) / num_queries;
  avg_fp_rate += (double)(fps) / num_queries;

  printf("passed. ");
  printf("FPs: %d (%f%%), FNs: %d (%f%%)\n",
         fps, (double)fps/(double)num_queries, fns, (double)fns/(double)a * 100);
  print_taf_metadata(filter);
  taf_destroy(filter);
}

void test_micro() {
	printf("Testing %s...", __FUNCTION__);
	size_t a = 1 << 27;
	double a_s = 100.0; // a/s
	double load = 0.9;
	size_t s = nearest_pow_of_2((size_t)((double)a / a_s));
	s = (size_t)((double)s * load);
	TAF* filter = new_taf(a);
	s = a * load;

	// Generate query set
	srandom(time(NULL));
	int nset = (int)(1.5*(double)s);
	Setnode* set = calloc(nset, sizeof(set[0]));

	elt_t *elts_to_insert = malloc(s * sizeof(elt_t));
	RAND_bytes((unsigned char*)elts_to_insert, s * sizeof(elt_t));

	char str[64];

	double measurement_interval = 0.05f;
	double current_measurement_point = measurement_interval;
	uint64_t next_measurement = current_measurement_point * a;

	clock_t start_clock = clock(), end_clock;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t start_time = tv.tv_sec * 1000000 + tv.tv_usec, end_time, interval_time = start_time;
	for (int i = 0; i < s; i++) {
		taf_insert(filter, elts_to_insert[i]);
	}
	gettimeofday(&tv, NULL);
	end_time = tv.tv_sec * 1000000 + tv.tv_usec;
	end_clock = clock();
	printf("Time for inserts: %f sec\n", (double)(end_time - start_time) / 1000000);
	printf("Insert throughput: %f ops/sec\n", (double)s * 1000000 / (end_time - start_time));
	printf("CPU time for inserts: %f sec\n", (double)(end_clock - start_clock) / CLOCKS_PER_SEC);

	int num_queries = 200000000;
	// Query [0, a] and ensure that all items in the set return true
	int fps = 0;

	elt_t *query_set = calloc(num_queries, sizeof(elt_t));
	RAND_bytes((unsigned char*)query_set, num_queries * sizeof(elt_t));
	int hash_seed = rand();
	for (int i = 0; i < num_queries; i++) {
		query_set[i] = rand_zipfian(1.5f, 10000000ull, query_set[i]);
		query_set[i] = MurmurHash64A(&query_set[i], sizeof(query_set[i]), hash_seed);
	}

	printf("Performing queries...\n");
	start_clock = clock();
	gettimeofday(&tv, NULL);
	start_time = interval_time = tv.tv_sec * 1000000 + tv.tv_usec;
	for (int i=0; i<num_queries; i++) {
		if (taf_lookup(filter, (elt_t)query_set[i])) {
			fps++;
		}
	}
	gettimeofday(&tv, NULL);
	end_time = tv.tv_sec * 1000000 + tv.tv_usec;
	end_clock = clock();

	avg_query_time += (double)(end_time - start_time) / num_queries;
	avg_fp_rate += (double)(fps) / num_queries;

	printf("Time for queries:     %f s\n", (double)(end_time - start_time) / 1000000);
	printf("Query throughput:     %f ops/sec\n", (double)num_queries * 1000000 / (end_time - start_time));
	printf("CPU time for queries: %f s\n", (double)(end_clock - start_clock) / CLOCKS_PER_SEC);

	printf("False positives:      %d\n", fps);
	printf("False positive rate:  %f%%\n", 100. * fps / num_queries);

	print_taf_metadata(filter);
	taf_destroy(filter);
}


void test_insert_and_query_w_repeats(elt_t *query_set, int query_set_size, int n_queries, int step_size, double *fprates, int iter) {
  printf("Testing %s...\n", __FUNCTION__);
  int nslots = 1 << 20;
  double load = 0.95;
  double a_s = 100;
  int queries_per_elt = 10;
  printf("nslots=%d, load=%f, a/s=%f, queries_per_elt = %d\n", nslots, load, a_s, queries_per_elt);

  int s = (int)((double)nearest_pow_of_2(nslots) * load);
  int a = (int)((double)s * a_s);
  printf("%d\n", a);
  //int n_queries = a * queries_per_elt;
  //n_queries = 1000000;

  int fps = 0;  // false positives
  int rfps = 0; // repeated false positives
  int fns = 0;  // false negatives
  int tot_queries = n_queries * queries_per_elt;

  TAF *filter = new_taf(s);
  int nset = (int)(s * 1.5);
  Setnode *set = calloc(nset, sizeof(set[0]));

  srandom(time(NULL));
  char str[64];
  int len;
  fprintf(stderr, "Initializing membership set and filter...\n");
  for (int i = 0; i < s; i++) {
    elt_t elt = random();
    sprintf(str, "%lu", elt);
    len = (int)strlen(str);
    set_insert(str, len, 0, set, nset);
    taf_insert(filter, elt);
  }
  /*fprintf(stderr, "Initializing query set...\n");
  FILE *caida = fopen("../../../aqf/AdaptiveQF/data/20140619-140100.csv", "r");
  char buffer[1024];
  fgets(buffer, sizeof(buffer), caida);
  elt_t *query_set = calloc(a, sizeof(elt_t));
  for (int i=0; i<a; i++) {
    //query_set[i] = random();
    //query_set[i] = rand_zipfian(1.5f, 1lu << 30);
    fgets(buffer, sizeof(buffer), caida);
    csv_get(buffer, 3);
    query_set[i] = hash_str(buffer);
  }
  fclose(caida);*/
  fprintf(stderr, "Querying set and filter...\n");
  int nseen = (int)(s * 1.5);
  Setnode *seen = calloc(nseen, sizeof(seen[0]));
  for (int i=0; i<n_queries; i++) {
    elt_t elt = query_set[random() % query_set_size];
    sprintf(str, "%lu", elt);
    len = (int)strlen(str);
    int in_filter = taf_lookup(filter, elt);
    int in_set = set_lookup(str, len, set, nset);
    if (in_filter && !in_set) {
      fps++;
      if (set_lookup(str, len, seen, nseen)) {
        rfps++;
      } else {
        set_insert(str, len, 0, seen, nseen);
      }
    } else if (!in_filter && in_set) {
      fns++;
      uint64_t hash = taf_hash(filter, elt);
      size_t quot = calc_quot(filter, hash);
      if (get_occupied(filter, quot)) {
        int loc = rank_select(filter, quot);
        if (loc == RANK_SELECT_EMPTY || loc == RANK_SELECT_OVERFLOW) {
          printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu)"
                 " was occupied but didn't have an associated runend\n",
                 elt, elt, quot, quot/64, quot%64);
          print_taf_block(filter, quot/64);
          exit(1);
        } else {
          int sels[64];
          decode_sel(get_sel_code(filter, loc/64), sels);
          int sel = sels[loc%64];
          rem_t query_rem = calc_rem(filter, hash, sel);
          rem_t stored_rem = remainder(filter, loc);
          printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu),"
                 "loc=%d (block=%d, slot=%d); stored rem=0x%hhx doesn't match query rem=0x%hhx\n",
                 elt, elt, quot, quot/64, quot%64, loc, loc/64, loc%64, stored_rem, query_rem);
          print_taf_metadata(filter);
          print_taf_block(filter, loc/64);
          exit(1);
        }
      } else {
        printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu) wasn't occupied\n",
               elt, elt, quot, quot/64, quot%64);
        exit(1);
      }
    }
    if (i % 100 == 0) {
	    fprates[i / 100] += (double)fps / i;
    }
  }
  printf("Test results:\n");
  printf("FPs: %d (%f%%), RFPs: %d (%f%%)\n",
         fps, (double)fps/tot_queries, rfps, (double)rfps/tot_queries * 100);
  printf("FNs: %d (%f%%)\n", fns, (double)fns/tot_queries * 100);

  taf_destroy(filter);
  printf("Done testing %s.\n", __FUNCTION__);
}

void test_dataset_evolution(char* input_file_name, char* output_file_name, int num_trials, int query_space_size, int num_queries, int step_size) {
	FILE* outfp = fopen(output_file_name, "w");
	fclose(outfp);
	outfp = fopen(output_file_name, "a");
	char buffer[1024];
	//FILE* infp = fopen(input_file_name, "r");
	//fgets(buffer, sizeof(buffer), infp);

	elt_t *query_set = calloc(query_space_size, sizeof(elt_t));
	for (int i = 0; i < query_space_size; i++) {
		/*fgets(buffer, sizeof(buffer), infp);
		csv_get(buffer, 3);
		query_set[i] = hash_str(buffer);*/
		query_set[i] = rand();
	}

	double *fprates = calloc(num_queries / 100, sizeof(double));

	for (int i = 0; i < num_trials; i++) {
		test_insert_and_query_w_repeats(query_set, query_space_size, num_queries, step_size, fprates, i);
	}

	for (int i = 0; i < num_queries / step_size; i++) {
		sprintf(buffer, "%d,%f\n", i * step_size, fprates[i] / num_trials);
		fputs(buffer, outfp);
	}
	
	//fclose(infp);
	fclose(outfp);
	free(query_set);
	free(fprates);
}

void test_hash_accesses(int qbits, int rbits, double load, uint64_t num_queries, uint64_t seed) {
	if (seed == -1) seed = time(NULL);
	printf("testing hash accesses on seed %lu\n", seed);
	srand(seed);

	uint64_t nslots = 1ull << qbits;
	//uint64_t xnslots = nslots + 10 * sqrt(nslots);

	uint64_t num_inserts = nslots * load;

	int fps = 0;  // false positives
	int rfps = 0; // repeated false positives
	int fns = 0;
	int tps = 0;
	int tns = 0;
	int hash_accesses = 0;
	int negatives = 0;

	TAF *filter = new_taf(nslots);
	int nset = 1.3 * num_inserts;
	Setnode *set = calloc(nset, sizeof(set[0]));
	elt_t *inserts = calloc(num_inserts, sizeof(elt_t));

	char str[64];
	int len;
	printf("starting %lu inserts\n", num_inserts);
	for (int i = 0; i < num_inserts; i++) {
		elt_t elt = rand();
		sprintf(str, "%lu", elt);
		len = (int)strlen(str);

		set_insert(str, len, i, set, nset);
		taf_insert(filter, elt);
		inserts[i] = elt;
	}

	FILE *fp = fopen("target/hash_accesses.txt", "w");
	fprintf(fp, "queries\taccesses\tfps\trfps\ttps\tnegatives\tfns\ttns\n");
	fclose(fp);
	fp = fopen("target/hash_accesses.txt", "a");

	elt_t *query_set = malloc(num_queries * sizeof(elt_t));

	int nseen = 1.3 * num_inserts;
	Setnode *seen = calloc(nseen, sizeof(seen[0]));
	printf("starting %lu queries\n", num_queries);
	for (int i = 0; i < num_queries; i++) {
		elt_t elt = rand_zipfian(1.5f, 10000000ull, query_set[i]);
		sprintf(str, "%lu", elt);
		len = (int)strlen(str);

		int in_filter = taf_lookup(filter, elt);
		int in_set = set_lookup(str, len, set, nset);

		if (in_filter) {
			hash_accesses++;
			if (in_set) {
				tps++;
				if (inserts[in_set - 1] != elt) {
					printf("original insert was %lu but set was triggered by %lu\n", inserts[in_set - 1], elt);
				}
			}
		}
		else {
			negatives++;
			if (!in_set) tns++;
		}
		if (in_filter && !in_set) {
			fps++;
			if (set_lookup(str, len, seen, nseen)) {
				rfps++;
			} else {
				set_insert(str, len, 0, seen, nseen);
			}
		} else if (!in_filter && in_set) {
			fns++;
			uint64_t hash = taf_hash(filter, elt);
			size_t quot = calc_quot(filter, hash);
			if (get_occupied(filter, quot)) {
				int loc = rank_select(filter, quot);
				if (loc == RANK_SELECT_EMPTY || loc == RANK_SELECT_OVERFLOW) {
					printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu)"
							" was occupied but didn't have an associated runend\n",
							elt, elt, quot, quot/64, quot%64);
					print_taf_block(filter, quot/64);
					exit(1);
				} else {
					int sels[64];
					decode_sel(get_sel_code(filter, loc/64), sels);
					int sel = sels[loc%64];
					rem_t query_rem = calc_rem(filter, hash, sel);
					rem_t stored_rem = remainder(filter, loc);
					printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu),"
							"loc=%d (block=%d, slot=%d); stored rem=0x%hhx doesn't match query rem=0x%hhx\n",
							elt, elt, quot, quot/64, quot%64, loc, loc/64, loc%64, stored_rem, query_rem);
					print_taf_metadata(filter);
					print_taf_block(filter, loc/64);
					exit(1);
				}
			} else {
				printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu) wasn't occupied\n",
						elt, elt, quot, quot/64, quot%64);
				exit(1);
			}
		}

		if (i % 100000 == 0) {
			fprintf(fp, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", i, hash_accesses, fps, rfps, tps, negatives, fns, tns);
		}
	}

	fclose(fp);

	printf("Test results:\n");
	printf("FPs: %d (%f%%), RFPs: %d (%f%%)\n",
			fps, (double)fps/num_queries, rfps, (double)rfps/num_queries * 100);
	printf("FNs: %d (%f%%)\n", fns, (double)fns/num_queries * 100);

	taf_destroy(filter);
	printf("Done testing %s.\n", __FUNCTION__);
}


void test_mixed_insert_and_query_w_repeats() {
  printf("Testing %s...\n", __FUNCTION__);
  int nslots = 1 << 14;
  double load = 0.95;
  double a_s = 100;
  int queries_per_elt = 10;
  printf("nslots=%d, load=%f, a/s=%f, queries_per_elt = %d\n", nslots, load, a_s, queries_per_elt);

  int s = (int)((double)nearest_pow_of_2(nslots) * load);
  int a = (int)((double)s * a_s);
  int n_queries = a * queries_per_elt;

  int fps = 0;  // false positives
  int rfps = 0; // repeated false positives
  int fns = 0;  // false negatives
  int tot_queries = n_queries * queries_per_elt;

  TAF *filter = new_taf(s);
  int nset = (int)(s * 1.5);
  Setnode *set = calloc(nset, sizeof(set[0]));

  srandom(TAF_SEED);
  char str[64];
  int len;
  fprintf(stderr, "Initializing query set...\n");
  elt_t *query_set = calloc(a, sizeof(elt_t));
  for (int i=0; i<a; i++) {
    query_set[i] = random();
  }
  fprintf(stderr, "Initializing membership set and filter...\n");
  for (int i=0; i<s/2; i++) {
    elt_t elt = random();
    sprintf(str, "%lu", elt);
    len = (int)strlen(str);
    set_insert(str, len, 0, set, nset);
    taf_insert(filter, elt);
  }
  fprintf(stderr, "Performing interleaved queries...\n");
  for (int i=0; i<n_queries; i++) {
    elt_t elt = query_set[random() % a];
    taf_lookup(filter, elt);
  }
  fprintf(stderr, "Finishing initialization of membership set and filter...\n");
  for (int i=s/2; i<s; i++) {
    elt_t elt = random();
    sprintf(str, "%lu", elt);
    len = (int)strlen(str);
    set_insert(str, len, 0, set, nset);
    taf_insert(filter, elt);
  }
  fprintf(stderr, "Querying set and filter...\n");
  int nseen = (int)(s * 1.5);
  Setnode *seen = calloc(nseen, sizeof(seen[0]));
  for (int i=0; i<n_queries; i++) {
    elt_t elt = query_set[random() % a];
    sprintf(str, "%lu", elt);
    len = (int)strlen(str);
    int in_filter = taf_lookup(filter, elt);
    int in_set = set_lookup(str, len, set, nset);
    if (in_filter && !in_set) {
      fps++;
      if (set_lookup(str, len, seen, nseen)) {
        rfps++;
      } else {
        set_insert(str, len, 0, seen, nseen);
      }
    } else if (!in_filter && in_set) {
      fns++;
      uint64_t hash = taf_hash(filter, elt);
      size_t quot = calc_quot(filter, hash);
      if (get_occupied(filter, quot)) {
        int loc = rank_select(filter, quot);
        if (loc == RANK_SELECT_EMPTY || loc == RANK_SELECT_OVERFLOW) {
          printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu)"
                 " was occupied but didn't have an associated runend\n",
                 elt, elt, quot, quot/64, quot%64);
          print_taf_block(filter, quot/64);
          exit(1);
        } else {
          int sels[64];
          decode_sel(get_sel_code(filter, loc/64), sels);
          int sel = sels[loc%64];
          rem_t query_rem = calc_rem(filter, hash, sel);
          rem_t stored_rem = remainder(filter, loc);
          printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu),"
                 "loc=%d (block=%d, slot=%d); stored rem=0x%hhx doesn't match query rem=0x%hhx\n",
                 elt, elt, quot, quot/64, quot%64, loc, loc/64, loc%64, stored_rem, query_rem);
          print_taf_metadata(filter);
          print_taf_block(filter, loc/64);
          exit(1);
        }
      } else {
        printf("False negative (elt=%lu, 0x%lx): quot=%lu (block=%lu, slot=%lu) wasn't occupied\n",
               elt, elt, quot, quot/64, quot%64);
        exit(1);
      }
    }
  }
  printf("Test results:\n");
  printf("FPs: %d (%f%%), RFPs: %d (%f%%)\n",
         fps, (double)fps/tot_queries, rfps, (double)rfps/tot_queries * 100);
  printf("FNs: %d (%f%%)\n", fns, (double)fns/tot_queries * 100);
  print_taf_stats(filter);
  taf_destroy(filter);
  printf("Done testing %s.\n", __FUNCTION__);
}

// a, b+1 in the same block
void test_shift_sels_single_block() {
  printf("Testing %s...", __FUNCTION__);

  // Setup
  TAF *filter = new_taf(64 * 3);
  int sels[64];
  for (int i=0; i<64; i++) {
    sels[i] = i % 8 == 0;
  }
  uint64_t code;
  encode_sel(sels, &code);
  set_sel_code(filter, 0, code);

  // Shift sels in [0, 62] -> [1, 63] and check
  for (int j=1; j <= 64; j++) {
    shift_sels(filter, 0, 62);
    decode_sel(get_sel_code(filter, 0), sels);
    for (int i=0; i<64; i++) {
      test_assert_eq(sels[i],
                     (i - j) % 8 == 0 && i > j-1,
                     "j=%d, i=%d", j, i);
    }
  }
  taf_destroy(filter);
  printf("passed.\n");
}

void test_swap_sels() {
  printf("Testing %s...", __FUNCTION__);
  int* xs = malloc(64 * sizeof(int));
  int* ys = malloc(64 * sizeof(int));
  for (int i=0; i<64; i++) {
    xs[i] = i;
    ys[i] = 64 + i;
  }
  swap_ptrs(&xs, &ys);
  for (int i=0; i<64; i++) {
    assert_eq(ys[i], i);
    assert_eq(xs[i], 64+i);
  }
  printf("passed.\n");
}

TAF* sel_setup() {
  TAF* filter = new_taf(64 * 4);
  int sels[64];
  uint64_t code;
  for (int i=0; i<filter->nblocks; i++) {
    for (int j=0; j<64; j++) {
      sels[j] = j % 8 == 0;
    }
    encode_sel(sels, &code);
    set_sel_code(filter, i, code);
  }
  return filter;
}

// a, b+1 in different blocks
void test_shift_sels_multi_block() {
  printf("Testing %s...", __FUNCTION__);
  int sels[64];
  TAF *filter = sel_setup();
  // (1) Shift sels in [0, 127] -> [1,128]
  shift_sels(filter, 0, 127);
  for (int i=0; i<filter->nblocks; i++) {
    decode_sel(get_sel_code(filter, i), sels);
    for (int j=0; j<64; j++) {
      test_assert_eq(sels[j],
                     (i < 2) ? ((j-1)%8 == 0) : (i == 2 && j == 0 ? 0 : j%8 == 0),
                     "i=%d, j=%d", i, j);
    }
  }
  taf_destroy(filter);
  filter = sel_setup();
  // (2) Shift sels in [32, 64+32] -> [33, 64+33]
  shift_sels(filter, 32, 64+32);
  for (int i=0; i<filter->nslots; i++) {
    if (i%64 == 0) {
      decode_sel(get_sel_code(filter, i/64), sels);
    }
    test_assert_eq(sels[i%64],
                   i < 32 ? i%8 == 0 :
                   (i == 32 ? 0 :
                    (i <= 64 + 33) ? (i-1)%8 == 0 : i%8 == 0),
                   "i=%d", i);
  }
  taf_destroy(filter);
  printf("passed.\n");
}

void test_template() {
  printf("Testing %s...", __FUNCTION__);
  TAF *filter = new_taf(64 * 3);

  printf("[unimplemented]");

  taf_destroy(filter);
  printf("passed.\n");
}

int main(int argc, char *argv[]) {
  /*test_calc_rem();
  test_add_block();
  test_add_block_no_clobber();
  test_adapt_loc_1();
  test_adapt_loc_2();
  test_adapt_loc_3();
  test_adapt_1();
  test_raw_lookup_1();
  test_raw_insert_1();
  test_shift_remote_elts();
  test_swap_sels();
  test_shift_sels_single_block();
  test_shift_sels_multi_block();
//  test_insert_and_query();
//  test_insert_and_query_w_repeats();
  test_mixed_insert_and_query_w_repeats();*/

  /*if (argc < 3) {
    printf("provide number of slots and number of inserts");
    return 0;
  }

  TAF* filter = new_taf(atoi(argv[1]));
  abort();

  int num_inserts = atoi(argv[2]), num_queries = 1000000;
  clock_t start_time = clock();
  int i;
  for (i = 0; i < num_inserts; i++) {
    taf_insert(filter, i);
  }
  printf("made %d insertions\n", i);
  printf("time for insert: %ld\n", clock() - start_time);
  printf("time per insert: %f\n", (double)(clock() - start_time) / i);

  for (i = 0; i < num_queries; i++) {
    assert(taf_lookup(filter, 1));
  }
  printf("time for query: %ld\n", clock() - start_time);
  printf("time per query: %f\n", (double)(clock() - start_time) / num_queries);

  taf_destroy(filter);

  printf("%d\n", extra_blocks);
  printf("finished with no issues\n");*/

  //test_dataset_evolution("../../../aqf/AdaptiveQF/data/shalla.txt", "progress.csv", 10, 1000000, 2000000, 100);
  //test_dataset_evolution("../../../aqf/AdaptiveQF/data/20140619-140100.csv", "progress.csv", 10, 1000000, 1000000, 100);
  int num_trials = 1;
  for (int i = 0; i < num_trials; i++) {
  	//test_insert_and_query();
	test_micro();
  }
  /*printf("insert time: %f\n", avg_insert_time / num_trials);
  printf("query time: %f\n", avg_query_time / num_trials);
  printf("fp rate: %f\n", avg_fp_rate / num_trials);*/

	//test_hash_accesses(20, 8, 0.9, 10000000, 0);
}
#endif // TEST_TAF
