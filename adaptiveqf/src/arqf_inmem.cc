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

  for (uint64_t i = 0; i < nkeys; i++) {
    uint64_t key = keys[i];
    uint64_t hash = keys[i];
    if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
      hash = arqf_hash(arqf->qf, key);
    } else {
      hash = key >> memento_bits;
    }
    uint64_t fingerprint = hash & BITMASK(quotient_bits + remainder_bits);
    arqf->rhm.insert({fingerprint, key});
  }
  return 0;
}

int InMemArqf_insert(InMemArqf* arqf, uint64_t value, int flags) {
  // TODO: Check if value exists already.
  const uint64_t quotient_bits = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_bits = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = arqf->qf->metadata->value_bits;
  const uint64_t n_slots = arqf->qf->metadata->nslots;
  const uint64_t seed = arqf->qf->metadata->seed;
  uint64_t last_fingerprint = -1;

  uint64_t fingerprint;
  qf_insert_memento(arqf->qf, value, flags, &fingerprint);
  arqf->rhm.insert({ fingerprint, value });
  return 0;
  
}
// x, y must be fingerprints (no mementos)
inline uint8_t min_diff_fingerprint_size(uint64_t x, uint64_t y, int quotient_size, int remainder_size, int memento_size) {
  if (x == y) {
    return 255;
  }
  uint8_t mask_size = quotient_size + remainder_size;
  uint8_t fingerprint_size = quotient_size + remainder_size;
  while ((x & BITMASK(mask_size)) == (y & BITMASK(mask_size))) {
      if (fingerprint_size == quotient_size + remainder_size) {
        fingerprint_size += memento_size; // First extension is memento size.
        mask_size += memento_size;
      }
      else  {
        fingerprint_size += (remainder_size + memento_size);
        mask_size += (remainder_size + memento_size);
      }
      if (fingerprint_size > 64) {
        mask_size = 64;
      }
  };
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

inline int adapt_keepsake(
    InMemArqf *arqf, 
    uint64_t *colliding_keys,
    uint64_t num_colliding_keys,
    uint64_t fp_key,
    uint64_t fp_hash,
    uint64_t keepsake_fingerprint, 
    uint64_t keepsake_start,
    uint64_t keepsake_end) {
#if DEBUG 
#if VERBOSE
   printf("Adapting hash: %016llx in keepsake[%llu %llu] containing %u keys\n", fp_hash, keepsake_start, keepsake_end, num_colliding_keys);
#endif
  for (uint64_t i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    assert(qf_point_query(arqf->qf, key_in_keepsake, 0) == 1);
  }
#endif
  const uint64_t quotient_size = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_size = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_size = arqf->qf->metadata->value_bits;

  uint64_t current_keepsake_end = keepsake_end;
  uint64_t last_overwritten_index = keepsake_start-1;
  uint8_t min_required_fingerprint_size = 0;
  arqf->rhm.erase(keepsake_fingerprint);
  
  for (int i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
    if (collision_hash == fp_hash) {
#if DEBUG
      if ((fp_key >> memento_size) != key_in_keepsake >> memento_size) {
        printf("Collision on hash detected, need more bits, might fail to adapt.\n");
      }
#endif
      continue;
    }
    uint8_t new_fingerprint_size = min_diff_fingerprint_size(fp_hash, collision_hash, quotient_size, remainder_size, memento_size);
    if (min_required_fingerprint_size < new_fingerprint_size) min_required_fingerprint_size = new_fingerprint_size;
  }

  if (min_required_fingerprint_size == 255 || min_required_fingerprint_size == 0) {
    for (uint64_t i=0; i < num_colliding_keys; i++) {
      uint64_t key_in_keepsake = colliding_keys[i];
#if DEBUG
      uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
      printf("Not enough bits to break collision\n"); 
      printf("keys:\n%016llx\n%016llx\n", fp_key, key_in_keepsake);
      printf("hash:\n%016llx\n%016llx\n", fp_hash, collision_hash);
#endif
      arqf->qf->metadata->n_failed_adapt_no_bits++;
      arqf->rhm.insert({keepsake_fingerprint, key_in_keepsake});
    }
    return -1; // Failed to adapt;
  }

  for (int i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
    uint64_t collision_memento = (key_in_keepsake) & BITMASK(memento_size);

    uint8_t new_fingerprint_size = min_diff_fingerprint_size(fp_hash, collision_hash, quotient_size, remainder_size, memento_size);
    if (collision_hash == fp_hash) {
      new_fingerprint_size = min_required_fingerprint_size;
    }
    uint64_t new_fingerprint_bits = collision_hash & BITMASK(new_fingerprint_size);
    if (new_fingerprint_size > 64) {
      new_fingerprint_bits = collision_hash;
    }
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

#if DEBUG
  for (uint64_t i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    assert(qf_point_query(arqf->qf, key_in_keepsake, 0) == 1);
  }
  assert(qf_point_query(arqf->qf, fp_key, 0) == 0);
#endif
  return 0;
}

inline int  maybe_adapt_keepsake(InMemArqf *arqf, uint64_t fp_key, uint64_t fp_hash, int query_type) {
  const uint64_t quotient_size = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_size = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_size = arqf->qf->metadata->value_bits;
  

  uint64_t colliding_fingerprint;
  uint64_t collision_index;
  uint64_t collision_runend_index;
  uint64_t num_ext_bits;

  int ret = find_colliding_fingerprint(
      arqf->qf, fp_hash, &colliding_fingerprint, &collision_index, &num_ext_bits, &collision_runend_index);
  if (ret != 0) return 0; // There was no need to adapt this keepsake, so consider as adapted.

  if (arqf->qf->metadata->noccupied_slots > 0.999 * arqf->qf->metadata->xnslots) {
    // printf("Hit space limit %llu %llu\n", arqf->qf->metadata->noccupied_slots, arqf->qf->metadata->xnslots);
    arqf->qf->metadata->n_failed_adapt_no_space++;
    return -1; // not enough space;
  }

  uint64_t num_colliding_keys = arqf->rhm.count(colliding_fingerprint);
  if (num_colliding_keys == 0) {
    abort(); // Improperly maintained RHM.
  }
  uint64_t* colliding_keys = (uint64_t*)malloc(num_colliding_keys * sizeof(uint64_t));

  int i = 0;
  auto range = arqf->rhm.equal_range(colliding_fingerprint);
  for (auto it = range.first; it != range.second; it++) {
    colliding_keys[i++] = it->second;
  }
  ret = 0;
  if (query_type == POINT_QUERY || 
      should_adapt_keepsake(colliding_keys, num_colliding_keys, fp_key, query_type, memento_size)) {
    ret = adapt_keepsake(
        arqf,
        colliding_keys,
        num_colliding_keys,
        fp_key,
        fp_hash,
        colliding_fingerprint,
        collision_index,
        collision_runend_index);
  }
  free(colliding_keys);
  return ret;
}

int InMemArqf_adapt_range(InMemArqf* arqf, uint64_t left, uint64_t right, int flags) {
  uint64_t l_prefix = left >> (arqf->qf->metadata->value_bits);
  uint64_t r_prefix = right >> (arqf->qf->metadata->value_bits);
  uint64_t l_hash = left;
  uint64_t r_hash = right;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    l_hash = arqf_hash(arqf->qf, left);
    r_hash = arqf_hash(arqf->qf, right);
  } else {
    l_hash = left >> (arqf->qf->metadata->value_bits);
    r_hash = right >> (arqf->qf->metadata->value_bits);
  }
   // printf("Adapting range: %llu %llu, hash: %llu %llu\n", left, right, l_hash, r_hash);
  int ret1 = maybe_adapt_keepsake(arqf, left, l_hash, LEFT_PREFIX);
  int ret2 = 0;
  if (l_prefix != r_prefix) {
    ret2 = maybe_adapt_keepsake(arqf, right, r_hash, RIGHT_PREFIX);
  }
  assert((ret1!=0 || ret2!=0) || (qf_range_query(arqf->qf,left, right, 0) == 0));
  if (ret1 == 0 && ret2 == 0) {
    arqf->qf->metadata->n_successful_adapts++;
    return 0;
  } else {
    return -1;
  }
}

int InMemArqf_adapt(InMemArqf* arqf, uint64_t fp_key, int flags) {
  // Find the colliding fingerprint which caused fp
  uint64_t fp_hash = fp_key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    fp_hash = arqf_hash(arqf->qf, fp_key);
  } else {
    fp_hash = fp_hash >> (arqf->qf->metadata->value_bits);
  }
  int ret = maybe_adapt_keepsake(arqf, fp_key, fp_hash, POINT_QUERY);
  if (ret == 0) {
    arqf->qf->metadata->n_successful_adapts++;
  }
  return ret;
}
