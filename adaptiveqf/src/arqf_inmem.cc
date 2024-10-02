#include "arqf_inmem.hpp"
#include "gqf.h"
#include "gqf_int.h"
#include "assert.h"
#include "splinterdb/platform_linux/public_platform.h"
#include <algorithm>
#include <cstdint>
#include <vector>
#include <iostream>

#define GET_KEY_HASH(flag) (flag & QF_KEY_IS_HASH)
#define QF_KEY_IS_HASH (0x08)
#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

int InMemArqf_init(InMemArqf* arqf, uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed, bool expandable) {
  QF* qf;
  qf = (QF*)malloc(sizeof(QF));
  qf_malloc(qf, nslots, key_bits, value_bits, QF_HASH_DEFAULT, seed, expandable);

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
    }
    uint64_t fingerprint = ((hash >> memento_bits) & BITMASK(quotient_bits + remainder_bits))
                    | (arqf->qf->metadata->is_expandable ? 1ULL << (quotient_bits + remainder_bits) : 0);
    arqf->rhm.insert({fingerprint, key});
  }
  return 0;
}

// x, y must be fingerprints (no mementos)
inline uint8_t min_diff_fingerprint_size(uint64_t x, uint64_t y, int quotient_size, int remainder_size, int memento_size) {
  if (x == y) {
    return 255;
  }
  uint8_t fingerprint_size = quotient_size + remainder_size;
  while ((x & BITMASK(fingerprint_size)) == (y & BITMASK(fingerprint_size))) {
      if (fingerprint_size == quotient_size + remainder_size) {
        fingerprint_size += memento_size; // First extension is memento size.
      }
      else  fingerprint_size += (remainder_size + memento_size);
      if (fingerprint_size > 64) {
        return 255;
      }
  };
  return fingerprint_size;
}

#define POINT_QUERY 0
#define LEFT_PREFIX 1
#define RIGHT_PREFIX 2

static inline bool should_adapt_keepsake(
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
    if (query_type == LEFT_PREFIX && collision_memento >= fp_memento)
        return true;
    else if (query_type == RIGHT_PREFIX && collision_memento <= fp_memento)
        return true;
    else if (query_type == POINT_QUERY && collision_memento == fp_memento)
        return true;
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
  const uint64_t fp_prefix = fp_hash >> memento_size;

  uint64_t current_keepsake_end = keepsake_end;
  uint64_t last_overwritten_index = keepsake_start-1;
  uint8_t min_required_fingerprint_size = 0;
  arqf->rhm.erase(keepsake_fingerprint);
  
  for (int i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
    uint64_t collision_prefix = (collision_hash) >> memento_size;
    if (collision_prefix == fp_prefix) {
#if DEBUG
      if ((fp_key >> memento_size) != key_in_keepsake >> memento_size) {
        printf("Collision on hash detected, need more bits, might fail to adapt.\n");
      }
#endif
      continue;
    }
    uint64_t collision_memento = (collision_hash) & BITMASK(memento_size);
    uint8_t new_fingerprint_size = min_diff_fingerprint_size(fp_prefix, collision_prefix, quotient_size, remainder_size, memento_size);
    if (min_required_fingerprint_size < new_fingerprint_size) min_required_fingerprint_size = new_fingerprint_size;
  }

  if (min_required_fingerprint_size == 255 || min_required_fingerprint_size == 0) {
    for (uint64_t i=0; i < num_colliding_keys; i++) {
      uint64_t key_in_keepsake = colliding_keys[i];
#if DEBUG
      uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
      uint64_t collision_prefix = (collision_hash) >> memento_size;
      printf("Not enough bits to break collision\n", fp_prefix, collision_prefix);
#endif
      arqf->rhm.insert({keepsake_fingerprint, key_in_keepsake});
    }
    return -1; // Failed to adapt;
  }

  for (int i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
    uint64_t collision_prefix = (collision_hash) >> memento_size;
    uint64_t collision_memento = (collision_hash) & BITMASK(memento_size);

    uint8_t new_fingerprint_size = min_diff_fingerprint_size(fp_prefix, collision_prefix, quotient_size, remainder_size, memento_size);
    if (collision_prefix == fp_prefix) {
      new_fingerprint_size = min_required_fingerprint_size;
    }
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

#if DEBUG
  for (uint64_t i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    assert(qf_point_query(arqf->qf, key_in_keepsake, 0) == 1);
  }
  assert(qf_point_query(arqf->qf, fp_hash, QF_KEY_IS_HASH) == 0);
#endif
  return 0;
}

inline int maybe_adapt_keepsake_expandable(InMemArqf *arqf, uint64_t fp_key, uint64_t fp_hash, int query_type) {
    const uint64_t quotient_size = arqf->qf->metadata->quotient_bits;
    const uint64_t remainder_size = arqf->qf->metadata->key_remainder_bits;
    const uint64_t memento_size = arqf->qf->metadata->value_bits;

    int64_t matching_fp_pos[64], matching_fp_ind = 0;
    matching_fp_pos[0] = -1;
    while (next_matching_fingerprint(arqf->qf, fp_hash, matching_fp_pos + matching_fp_ind) != -1) {
        matching_fp_ind++;
        matching_fp_pos[matching_fp_ind] = matching_fp_pos[matching_fp_ind - 1];
    }
    if (matching_fp_ind == 0)
        return 0; // There was no need to adapt this keepsake, so consider as adapted.

    fp_hash >>= memento_size;

    if (arqf->qf->metadata->noccupied_slots > 0.95 * arqf->qf->metadata->xnslots) {
        if (qf_is_auto_resize_enabled(arqf->qf)) {
            // Expand
            qf_resize_malloc(arqf->qf, arqf->qf->metadata->nslots * 2);
        }
        // printf("Hit space limit %llu %llu\n", arqf->qf->metadata->noccupied_slots, arqf->qf->metadata->xnslots);
        return -1; // not enough space;
    }

    const uint64_t bucket_index = fp_hash & BITMASK(quotient_size);
    const uint64_t runstart_pos = bucket_index == 0 ? 0 : run_end(arqf->qf, bucket_index-1) + 1;
    const uint64_t runend_pos = run_end(arqf->qf, bucket_index);

    uint64_t num_colliding_keys = 0;
    for (int32_t i = 0; i < matching_fp_ind; i++) {
        uint64_t matching_fp_size;
        uint64_t colliding_fingerprint = read_fingerprint_bits(arqf->qf, matching_fp_pos[i], &matching_fp_size);
        colliding_fingerprint |= 1ULL << matching_fp_size;
        colliding_fingerprint = (colliding_fingerprint << quotient_size) | bucket_index;
        num_colliding_keys += arqf->rhm.count(colliding_fingerprint);
    }
    uint64_t colliding_keys[num_colliding_keys];

    int colliding_keys_ind = 0;
    for (int32_t i = 0; i < matching_fp_ind; i++) {
        uint64_t matching_fp_size;
        uint64_t colliding_fingerprint = read_fingerprint_bits(arqf->qf, matching_fp_pos[i], &matching_fp_size);
        colliding_fingerprint |= 1ULL << matching_fp_size;
        colliding_fingerprint = (colliding_fingerprint << quotient_size) | bucket_index;
        auto range = arqf->rhm.equal_range(colliding_fingerprint);
        for (auto it = range.first; it != range.second; it++)
            colliding_keys[colliding_keys_ind++] = it->second;
    }

    if (query_type != POINT_QUERY && 
            !should_adapt_keepsake(colliding_keys, num_colliding_keys, fp_hash, query_type, memento_size)) 
        return -1;

    uint64_t run_size = runend_pos - runstart_pos + 1;
    for (int32_t i = matching_fp_ind - 1; i >= 0; i--) {
        uint64_t matching_fp_size;
        uint64_t keepsake_fingerprint = read_fingerprint_bits(arqf->qf, matching_fp_pos[i], &matching_fp_size);
        keepsake_fingerprint |= 1ULL << matching_fp_size;
        arqf->rhm.erase(keepsake_fingerprint);

        const uint32_t keepsake_size = get_keepsake_len(arqf->qf, matching_fp_pos[i]);
        remove_keepsake_and_shift_remainders_and_runends_and_offsets(arqf->qf,
                                                                     run_size == keepsake_size,
                                                                     bucket_index,
                                                                     matching_fp_pos[i],
                                                                     keepsake_size);
        run_size -= keepsake_size;
    }

    std::pair<uint64_t, uint64_t> hash_key_pairs[num_colliding_keys];
    std::transform(colliding_keys, colliding_keys + num_colliding_keys, hash_key_pairs,
                   [=](uint64_t key) { return std::make_pair(arqf_hash(arqf->qf, key), key); });
    std::sort(hash_key_pairs, hash_key_pairs + num_colliding_keys);
    uint8_t min_new_fp_size = 0;
    for (int32_t i = 0; i < num_colliding_keys; i++)
        min_new_fp_size = std::max(min_new_fp_size, min_diff_fingerprint_size(fp_hash, 
                                                                              hash_key_pairs[i].first >> memento_size,
                                                                              quotient_size,
                                                                              remainder_size,
                                                                              memento_size));
    uint64_t mementos[num_colliding_keys];
    uint64_t prev_fp = (hash_key_pairs[0].first >> memento_size) & BITMASK(min_new_fp_size), cur_fp;
    uint32_t num_mementos = 0;
    mementos[num_mementos++] = hash_key_pairs[0].first & BITMASK(memento_size);
    for (int32_t i = 1; i < num_colliding_keys; i++) {
        cur_fp = (hash_key_pairs[i].first >> memento_size) & BITMASK(min_new_fp_size);
        if (cur_fp != prev_fp) {
            qf_insert_keepsake(arqf->qf, prev_fp, min_new_fp_size, mementos, num_mementos, QF_KEY_IS_HASH);
            num_mementos = 0;
            prev_fp = cur_fp;
        }
        mementos[num_mementos++] = hash_key_pairs[i].first & BITMASK(memento_size);
    }
    qf_insert_keepsake(arqf->qf, prev_fp, min_new_fp_size, mementos, num_mementos, QF_KEY_IS_HASH);
    for (auto [hash, key] : hash_key_pairs)
        arqf->rhm.insert({(hash >> memento_size) | (1ULL << min_new_fp_size), key});
#if DEBUG
  for (uint64_t i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    assert(qf_point_query(arqf->qf, key_in_keepsake, 0) == 1);
  }
  assert(qf_point_query(arqf->qf, (fp_hash << memento_size) | fp_key & BITMASK(memento_size), QF_KEY_IS_HASH) == 0);
#endif
    return 0;
}

inline int maybe_adapt_keepsake(InMemArqf *arqf, uint64_t fp_key, uint64_t fp_hash, int query_type) {
  if (arqf->qf->metadata->is_expandable)
      return maybe_adapt_keepsake_expandable(arqf, fp_key, fp_hash, query_type);

  const uint64_t quotient_size = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_size = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_size = arqf->qf->metadata->value_bits;

  uint64_t colliding_fingerprint;
  uint64_t collision_index;
  uint64_t collision_runend_index;
  uint64_t num_ext_bits;

  int ret = find_colliding_fingerprint(
      arqf->qf, fp_hash, &colliding_fingerprint, &collision_index, &num_ext_bits, &collision_runend_index);
  if (ret != 0)
      return 0; // There was no need to adapt this keepsake, so consider as adapted.

  if (arqf->qf->metadata->noccupied_slots > 0.99 * arqf->qf->metadata->xnslots) {
    if (qf_is_auto_resize_enabled(arqf->qf)) {
        // Expand
        qf_resize_malloc(arqf->qf, arqf->qf->metadata->nslots * 2);
    }
    // printf("Hit space limit %llu %llu\n", arqf->qf->metadata->noccupied_slots, arqf->qf->metadata->xnslots);
    return -1; // not enough space;
  }

  uint64_t num_colliding_keys = arqf->rhm.count(colliding_fingerprint);
  uint64_t* colliding_keys = (uint64_t*)malloc(num_colliding_keys * sizeof(uint64_t));

  int i = 0;
  auto range = arqf->rhm.equal_range(colliding_fingerprint);
  for (auto it = range.first; it != range.second; it++) {
    colliding_keys[i++] = it->second;
  }
  ret = 0;
  if (query_type == POINT_QUERY || 
      should_adapt_keepsake(colliding_keys, num_colliding_keys, fp_hash, query_type, memento_size)) {
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
    l_hash = arqf_hash(arqf->qf, l_hash);
    r_hash = arqf_hash(arqf->qf, r_hash);
  }
#if VERBOSE 
   printf("Adapting range: %llu %llu, hash: %llu %llu\n", left, right, l_hash, r_hash);
#endif
  int ret1 = maybe_adapt_keepsake(arqf, left, l_hash, LEFT_PREFIX);
  int ret2 = 0;
  if (l_prefix != r_prefix) {
    ret2 = maybe_adapt_keepsake(arqf, right, r_hash, RIGHT_PREFIX);
  }
  assert((ret1!=0 || ret2!=0) || (qf_range_query(arqf->qf,l_hash, r_hash, QF_KEY_IS_HASH) == 0));
  if (ret1 == 0 && ret2 == 0) {
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
  }
  return maybe_adapt_keepsake(arqf, fp_key, fp_hash, POINT_QUERY);
}
