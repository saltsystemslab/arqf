#include "arqf_inmem.hpp"
#include "gqf.h"
#include "gqf_int.h"
#include "assert.h"
#include <vector>
#include <iostream>

#define GET_KEY_HASH(flag) (flag & QF_KEY_IS_HASH)
#define QF_KEY_IS_HASH (0x08)
#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

int InMemArqf_init(InMemArqf* arqf, uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed) {
  QF* qf;
  qf = (QF*)malloc(sizeof(QF));
  qf_malloc(qf, nslots, key_bits, value_bits, QF_HASH_DEFAULT, seed);

  arqf->qf = qf;
  return 0;
}

int InMemArqf_bulk_load(InMemArqf* arqf, uint64_t *sorted_hashes, uint64_t *keys, uint64_t nkeys, int flags) {
  qf_bulk_load(arqf->qf, sorted_hashes, nkeys);

  const uint64_t quotient_bits = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_bits = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = arqf->qf->metadata->value_bits;
  const uint64_t n_slots = arqf->qf->metadata->nslots;
  const uint64_t seed = arqf->qf->metadata->seed;
  uint64_t last_fingerprint = -1;

  std::cout<<nkeys<<std::endl;

  for (uint64_t i = 0; i < nkeys; i++) {
    uint64_t key = keys[i];
    uint64_t hash = keys[i];
    if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
      hash = arqf_hash(arqf->qf, key);
    }
    uint64_t fingerprint = (hash >> memento_bits) & BITMASK(quotient_bits + remainder_bits);
    arqf->rhm.insert({fingerprint, key});

    if ((i % 1000000) == 0) {
      printf("%lld/%lld keys loaded into RHM\n", i, nkeys);
    }
  }
  return 0;
}

// x, y must be fingerprints (no mementos)
inline uint8_t min_diff_fingerprint_size(uint64_t x, uint64_t y, int quotient_size, int remainder_size, int memento_size) {
  if (x == y) {
    abort();
  }
  uint8_t fingerprint_size = quotient_size + remainder_size;
  while ((x & BITMASK(fingerprint_size)) == (y & BITMASK(fingerprint_size))) {
      if (fingerprint_size == quotient_size + remainder_size) {
        fingerprint_size += memento_size; // First extension is memento size.
      }
      else  fingerprint_size += (remainder_size + memento_size);
      if (fingerprint_size > 64) {
        abort();
      }
  };
#if DEBUG
  printf("%016llx %016llx differ in %u bits\n", x, y, fingerprint_size);
#endif
  return fingerprint_size;
}


#define POINT_QUERY 0
#define LEFT_PREFIX 1
#define RIGHT_PREFIX 2

inline bool should_adapt_keepsake(
    uint64_t *colliding_keys,
    uint64_t num_colliding_keys,
    uint64_t fp_key,
    int query_type,
    int memento_size)
{
  uint64_t fp_memento = fp_key & BITMASK(memento_size);
  uint64_t fp_prefix = fp_key >> memento_size;
  for (uint64_t i=0; i < num_colliding_keys; i++) {
    uint64_t colliding_key = colliding_keys[i];
    uint64_t collision_memento = colliding_key & BITMASK(memento_size);
    if (query_type == LEFT_PREFIX && collision_memento >= fp_memento) return true;
    else if (query_type == RIGHT_PREFIX && collision_memento <= fp_memento) return true;
    else if (query_type == POINT_QUERY && collision_memento == fp_memento) return true;
  }
  assert(query_type != POINT_QUERY); // If point query doesn't find fp_memento, we screwed up the query.
  return false;
}

inline void adapt_keepsake(
    InMemArqf *arqf, 
    uint64_t *colliding_keys,
    uint64_t num_colliding_keys,
    uint64_t fp_hash,
    uint64_t keepsake_fingerprint, 
    uint64_t keepsake_start,
    uint64_t keepsake_end) {
#if DEBUG
  printf("Adapting hash: %lld in keepsake[%llu %llu] containing %u keys\n", fp_hash, keepsake_start, keepsake_end, num_colliding_keys);
#endif
  const uint64_t quotient_size = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_size = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_size = arqf->qf->metadata->value_bits;
  const uint64_t fp_prefix = fp_hash >> memento_size;

  uint64_t current_keepsake_end = keepsake_end;
  uint64_t last_overwritten_index = keepsake_start-1;
  uint8_t min_fingerprint_size = 64;
  arqf->rhm.erase(keepsake_fingerprint);

  for (int i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
    uint64_t collision_prefix = (collision_hash) >> memento_size;
    uint64_t collision_memento = (collision_hash) & BITMASK(memento_size);
    if (collision_prefix == fp_prefix) {
      printf("Skipping equal prefix for now: %016llx %llu %llu\n", collision_prefix, collision_memento, fp_hash & BITMASK(memento_size));
      continue;
    }
    uint8_t new_fingerprint_size = min_diff_fingerprint_size(fp_prefix, collision_prefix, quotient_size, remainder_size, memento_size);
    if (min_fingerprint_size > new_fingerprint_size) min_fingerprint_size = new_fingerprint_size;
    uint64_t new_fingerprint_bits = collision_prefix & BITMASK(new_fingerprint_size);
    _overwrite_keepsake(
        arqf->qf, 
        new_fingerprint_bits, 
        new_fingerprint_size, 
        collision_memento, 
        keepsake_start, 
        &last_overwritten_index, 
        &current_keepsake_end
      );
    arqf->rhm.insert({new_fingerprint_bits, key_in_keepsake});
  }

  for (uint64_t i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
    uint64_t collision_prefix = (collision_hash) >> memento_size;
    uint64_t collision_memento = (collision_hash) & BITMASK(memento_size);
    if (collision_prefix != fp_prefix) continue;
    uint64_t new_fingerprint_bits = collision_prefix & BITMASK(min_fingerprint_size);
    _overwrite_keepsake(
        arqf->qf, 
        new_fingerprint_bits, min_fingerprint_size, collision_memento, keepsake_start, &last_overwritten_index, &current_keepsake_end);
    arqf->rhm.insert({new_fingerprint_bits, key_in_keepsake});
  }
#if DEBUG
  for (uint64_t i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    printf("Checking if key %llu was lost\n", key_in_keepsake);
    assert(qf_point_query(arqf->qf, key_in_keepsake, 0) == 1);
  }
  assert(qf_point_query(arqf->qf, fp_hash, QF_KEY_IS_HASH) == 0);
#endif
}

inline int  maybe_adapt_keepsake(InMemArqf *arqf, uint64_t fp_hash, int query_type) {
  const uint64_t quotient_size = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_size = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_size = arqf->qf->metadata->value_bits;
  

  uint64_t colliding_fingerprint;
  uint64_t collision_index;
  uint64_t collision_runend_index;
  uint64_t num_ext_bits;

  int ret = find_colliding_fingerprint(
      arqf->qf, fp_hash, &colliding_fingerprint, &collision_index, &num_ext_bits, &collision_runend_index);
  if (ret != 0) return ret;
#if DEBUG
  printf("%016llx found at %llu with fingerprint: %016llx\n", fp_hash, collision_index, colliding_fingerprint);
#endif

  uint64_t num_colliding_keys = arqf->rhm.count(colliding_fingerprint);
  uint64_t* colliding_keys = (uint64_t*)malloc(num_colliding_keys * sizeof(uint64_t));

  int i = 0;
  auto range = arqf->rhm.equal_range(colliding_fingerprint);
  for (auto it = range.first; it != range.second; it++) {
    colliding_keys[i++] = it->second;
  }
  if (query_type == POINT_QUERY || 
      should_adapt_keepsake(colliding_keys, num_colliding_keys, fp_hash, query_type, memento_size)) {
    adapt_keepsake(
        arqf,
        colliding_keys,
        num_colliding_keys,
        fp_hash,
        colliding_fingerprint,
        collision_index,
        collision_runend_index);
  }
  free(colliding_keys);
  return 0;
}

int InMemArqf_adapt_range(InMemArqf* arqf, uint64_t left, uint64_t right, int flags) {
  uint64_t l_hash = left;
  uint64_t r_hash = right;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    l_hash = arqf_hash(arqf->qf, l_hash);
    r_hash = arqf_hash(arqf->qf, r_hash);
  }
#if DEBUG
  printf("Adapting range: %llu %llu\n", l_hash, r_hash);
#endif
  if (l_hash == 2145303114483721267ULL) {
    printf("Adapting wrong key: %lld\n", l_hash);
    int x = maybe_adapt_keepsake(arqf, l_hash, LEFT_PREFIX);
    int y = maybe_adapt_keepsake(arqf, r_hash, RIGHT_PREFIX);
    printf("%lld\n", x, y);
  }
  maybe_adapt_keepsake(arqf, l_hash, LEFT_PREFIX);
  maybe_adapt_keepsake(arqf, r_hash, RIGHT_PREFIX);
  return 0;
}

int InMemArqf_adapt(InMemArqf* arqf, uint64_t fp_key, int flags) {
  // Find the colliding fingerprint which caused fp
  uint64_t fp_hash = fp_key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    fp_hash = arqf_hash(arqf->qf, fp_key);
  }
  maybe_adapt_keepsake(arqf, fp_hash, POINT_QUERY);
  return 0;
}
