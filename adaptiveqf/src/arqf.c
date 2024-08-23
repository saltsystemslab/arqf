#include "arqf.h"
#include "gqf.h"
#include "include/splinter_util.h"

#define GET_KEY_HASH(flag) (flag & QF_KEY_IS_HASH)
#define QF_KEY_IS_HASH (0x08)
#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

__attribute__((always_inline)) static inline uint32_t fast_reduce(uint32_t hash, uint32_t n)
{
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}


int arqf_init_with_rhm(ARQF* arqf, splinterdb *rhm, uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed)
{
  QF* qf;
  qf = (QF*)malloc(sizeof(QF));
  qf_malloc(qf, nslots, key_bits, value_bits, QF_HASH_DEFAULT, seed);

  arqf->db_result = (splinterdb_lookup_result *)malloc(sizeof(splinterdb_lookup_result));
  splinterdb_lookup_result_init(rhm, arqf->db_result, 0, NULL);
  arqf->rhm = rhm;
  arqf->qf = qf;
  return 0;
}

int arqf_bulk_load(ARQF* arqf, uint64_t* sorted_hashes, uint64_t* keys, uint64_t nkeys, int flags)
{
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
      hash = arqf_hash(arqf, key);
    }
    uint64_t fingerprint = (hash >> memento_bits) & BITMASK(quotient_bits + remainder_bits);
    if (i==0 || fingerprint != last_fingerprint) {
      db_insert(arqf->rhm, &fingerprint, sizeof(fingerprint), &key, sizeof(key), 0, 0);
      last_fingerprint = fingerprint;
    } else {
      db_insert(arqf->rhm, &fingerprint, sizeof(fingerprint), &key, sizeof(key), 1, 0);
    }

  }
  return 0;
}

int arqf_adapt(ARQF *arqf, uint64_t fp_key, int flags) {
  // Find the colliding fingerprint which caused fp
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
#if DEBUG
  fprintf(stderr, "Colliding with %016llx, occupying [%lld\n %lld\n]", colliding_fingerprint, collision_index, collision_runend_index);
#endif
  if (ret < 0) {
    return ret;
  }
  uint64_t fp_fingerprint_bits = fp_hash >> arqf->qf->metadata->value_bits;
  // Lookup the reverse hashmap and find all keys mapped to this fingerprint.
	char buffer[MAX_KEY_SIZE];
	slice db_query = padded_slice(&colliding_fingerprint, MAX_KEY_SIZE, sizeof(colliding_fingerprint), buffer, 0);
	ret = splinterdb_lookup(arqf->rhm, db_query, arqf->db_result);
  if (!splinterdb_lookup_found(arqf->db_result)) {
    abort(); // Improperly maintained RHM.
  }
	slice result_val;
	splinterdb_lookup_result_value(arqf->db_result, &result_val);

  // Extend the keepsake.
  uint64_t keepsake_start_index = collision_index;
  uint64_t last_overwritten_index= 0; 
  for (uint64_t i=0; i < result_val.length; i += MAX_VAL_SIZE) {
    uint64_t key = *(uint64_t *)(slice_data(result_val) + i);
    uint64_t memento = key & BITMASK(arqf->qf->metadata->value_bits);
    uint64_t fingerprint_bits = key >> arqf->qf->metadata->value_bits;
    // First extension is memento sized.
    // Intial Fingerprint (without adapting) uses qf->metadata->quotient_bits + qf->metadata->key_remainder_bits.
    // The next minimal fingerprint extends it by value_bits (the memento size).
    // subsequent bits extend it by slot size (key_remainder + memento)
    uint8_t num_fingerprint_bits = arqf->qf->metadata->quotient_bits+ arqf->qf->metadata->key_remainder_bits + arqf->qf->metadata->value_bits;
    while ( ((fingerprint_bits ^ fp_fingerprint_bits) & BITMASK(num_fingerprint_bits)) == 0) {
      num_fingerprint_bits += arqf->qf->metadata->bits_per_slot;
    }
#if DEBUG
    fprintf(stderr, "Extending %016llx to %016llx\n", colliding_fingerprint, fingerprint_bits & BITMASK(num_fingerprint_bits));
#endif
    _overwrite_keepsake(arqf->qf, fingerprint_bits, num_fingerprint_bits, memento, keepsake_start_index, &last_overwritten_index, &collision_runend_index); // Implement overwrite keepsake.
    // TODO(chesetti): Insert new fingerprints into the RHM.
    uint64_t new_fingerprint = fingerprint_bits & BITMASK(num_fingerprint_bits);
    db_insert(arqf->rhm, &new_fingerprint, sizeof(new_fingerprint), &key, sizeof(key), 1, 0);
  }
  splinterdb_delete(arqf->rhm, db_query);
  return 0;
}
