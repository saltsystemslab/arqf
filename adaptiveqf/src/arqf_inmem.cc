#include "arqf_inmem.hpp"
#include "gqf.h"
#include "gqf_int.h"
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

int InMemArqf_adapt(InMemArqf* arqf, uint64_t fp_key, int flags) {
  // Find the colliding fingerprint which caused fp
#if 0
  uint64_t fp_hash = fp_key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    fp_hash = arqf_hash(arqf->qf, fp_key);
  }
  uint64_t colliding_fingerprint;
  uint64_t collision_index;
  uint64_t collision_runend_index;
  uint64_t num_ext_bits;
  int ret = find_colliding_fingerprint(
      arqf->qf, fp_hash, &colliding_fingerprint, &collision_index, &num_ext_bits, &collision_runend_index);
  if (ret < 0) {
    return ret;
  }
  uint64_t fp_fingerprint_bits = fp_hash >> arqf->qf->metadata->value_bits;

  std::vector<uint64_t> colliding_keys;
  for (auto it = arqf->rhm.begin(colliding_fingerprint); it != arqf->rhm.end(colliding_fingerprint); it++) {
    uint64_t key = it->second;
    colliding_keys.push_back(key);
  }
  arqf->rhm.erase(colliding_fingerprint);

  uint64_t keepsake_start_index = collision_index;
  uint64_t last_overwritten_index = collision_index - 1;
  for (auto key: colliding_keys) {
    uint64_t hash = key;
    if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
      hash = arqf_hash(arqf->qf, key);
    }
    uint64_t memento = hash & BITMASK(arqf->qf->metadata->value_bits);
    uint64_t fingerprint_bits = hash >> arqf->qf->metadata->value_bits;
    // First extension is memento sized.
    // Intial Fingerprint (without adapting) uses qf->metadata->quotient_bits + qf->metadata->key_remainder_bits.
    // The next minimal fingerprint extends it by value_bits (the memento size).
    // subsequent bits extend it by slot size (key_remainder + memento)
    uint8_t num_fingerprint_bits = arqf->qf->metadata->quotient_bits + arqf->qf->metadata->key_remainder_bits + arqf->qf->metadata->value_bits;
    while ((fingerprint_bits & BITMASK(num_fingerprint_bits)) == (fp_fingerprint_bits & BITMASK(num_fingerprint_bits))) {
      num_fingerprint_bits += arqf->qf->metadata->bits_per_slot;
    }
    _overwrite_keepsake(arqf->qf, fingerprint_bits, num_fingerprint_bits, memento, keepsake_start_index, &last_overwritten_index, &collision_runend_index);
    // Insert new fingerprints into the RHM.
    uint64_t new_fingerprint = fingerprint_bits & BITMASK(num_fingerprint_bits);
    arqf->rhm.insert({new_fingerprint, key});
  }

#if DEBUG
  for (auto key: colliding_keys) {
    if (qf_point_query(arqf->qf, key, 0) == 0) {
      printf("%llu got lost while adapting\n", key);
      abort();
    }
  }
  if (qf_point_query(arqf->qf, fp_key, 0) == 1) {
    printf("%llu was not adapted\n", fp_key);
    abort();
  }
#endif
  return 0;
#endif
}
