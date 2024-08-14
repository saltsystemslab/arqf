#include "arqf.h"
#include "gqf.h"
#include "include/splinter_util.h"

#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

__attribute__((always_inline)) static inline uint32_t fast_reduce(uint32_t hash, uint32_t n)
{
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}

// TODO(chesetti): inline this
uint64_t arqf_hash(ARQF* arqf, uint64_t x)
{
  const uint64_t quotient_bits = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_bits = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = arqf->qf->metadata->value_bits;
  const uint64_t n_slots = arqf->qf->metadata->nslots;
  const uint64_t seed = arqf->qf->metadata->seed;

  const uint64_t quotient_mask = (1ULL << quotient_bits) - 1;
  const uint64_t memento_mask = (1ULL << memento_bits) - 1;
  const uint64_t hash_mask = (1ULL << (quotient_bits + remainder_bits)) - 1;
  auto y = x >> memento_bits;
  uint64_t mhash = MurmurHash64A(((void*)&y), sizeof(y), seed) & hash_mask;
  const uint64_t address = fast_reduce((mhash & quotient_mask) << (32 - quotient_bits),
      n_slots);
  uint64_t hash = (mhash >> quotient_bits) | (address << remainder_bits);
  hash = (hash << memento_bits) | (x & memento_mask);
  // Fill the higher order bits with bits from the MurmurHash, these will be used as extensions.
  hash = hash | (mhash & ~BITMASK(quotient_bits + remainder_bits + memento_bits));
  return hash;
}

int arqf_init_with_rhm(ARQF* arqf, uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed, const char* rhm_path)
{
  QF* qf;
  qf = (QF*)malloc(sizeof(QF));
  qf_malloc(qf, nslots, key_bits, value_bits, QF_HASH_DEFAULT, seed);

  splinterdb* db;
  data_config data_cfg = qf_data_config_init();
  splinterdb_config splinterdb_cfg = qf_splinterdb_config_init(rhm_path, &data_cfg);
  remove(splinterdb_cfg.filename);
  if (splinterdb_create(&splinterdb_cfg, &db)) {
    return -1;
  }
  splinterdb_lookup_result_init(db, arqf->db_result, 0, NULL);
  arqf->rhm = db;
  arqf->qf = qf;
  return 0;
}

int arqf_bulk_load(ARQF* arqf, uint64_t* sorted_hashes, uint64_t* keys, uint64_t nkeys)
{
  qf_bulk_load(arqf->qf, sorted_hashes, nkeys);

  const uint64_t quotient_bits = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_bits = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = arqf->qf->metadata->value_bits;
  const uint64_t n_slots = arqf->qf->metadata->nslots;
  const uint64_t seed = arqf->qf->metadata->seed;

  for (uint64_t i = 0; i < nkeys; i++) {
    uint64_t key = keys[i];
    uint64_t hash = arqf_hash(arqf, key);
    uint64_t fingerprint = (hash >> memento_bits) & BITMASK(quotient_bits + remainder_bits);
    db_insert(arqf->rhm, &fingerprint, sizeof(fingerprint), &key, sizeof(key), 1, 0);
  }
  return 0;
}

int arqf_adapt(ARQF *arqf, uint64_t fp_key, int flags) {
#if 0
  uint64_t fp_hash = fp_key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    fp_hash = arqf_hash(arqf, fp_key);
  }
  const uint64_t quotient_bits = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_bits = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = arqf->qf->metadata->value_bits;
  const uint64_t n_slots = arqf->qf->metadata->nslots;
  const uint64_t seed = arqf->qf->metadata->seed;

  uint64_t fp_fingerprint = (fp_hash >> memento_bits) & BITMASK(quotient_bits + remainder_bits);
  uint64_t fp_remainder = (fp_hash & BITMASK(remainder_bits));
  uint64_t fp_quotient = (fp_hash >> remainder_bits);

  // Now go to fp_fingerprint, and see how many times this level was adapted.
  if (!is_occupied(fp_quotient)) {
    return 0; // Should not have happened, unless called on not a fp.
  }

	uint64_t current_index = fp_quotient == 0 ? 0 : run_end(arqf->qf, fp_quotient-1) + 1;
  if (current_index < fp_quotient) current_index = fp_quotient;
  uint64_t nearest_remainder = lower_bound_remainder(arqf->qf, fp_remainder, &current_index); 
  if (nearest_remainder != fp_remainder) {
    return 0; // Again should not have happened, unless called on not a fp.
  }
  // Ok, now is the tricky part.
  // 1. Get all keys with fingerprint qr, we don't need to rewrite this (we always query for qr).
  // 2. Insert those keys.
  //    3. Find out how many extensions you need?  (For now assume 1)
  //    4. Get starting and ending slot.
  //    5. Insert the keys in again. 
  //    6. Add new slots if necessary.
  //  Optimization: Store only prefix in rhm. Query DB for actual keys - reduces storage space.
  //  Do we always extend for all remainders?
#endif
  return 0;
}
