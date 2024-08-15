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
  uint64_t mhash = MurmurHash64A(((void*)&y), sizeof(y), seed);
  // Use the lower order q bits of mhash to determine address.
  const uint64_t address = fast_reduce((mhash & quotient_mask) << (32 - quotient_bits),
      n_slots);
  // Use the lower order r (after q bits) of mhash to determine reminder.
  uint64_t hash = ((mhash & hash_mask) >> quotient_bits) | (address << remainder_bits);
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
  uint64_t fp_hash = fp_key; // fp is false-positive.
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    fp_hash = arqf_hash(arqf->qf, fp_key);
  }


  // Find the colliding fingerprint which caused fp
  uint64_t colliding_fingerprint;
  uint64_t collision_index;
  int ret = find_colliding_fingerprint(arqf->qf, fp_hash, &colliding_fingerprint, &collision_index);
  if (ret < 0) {
    return ret;
  }

  // Lookup the reverse hashmap and find all keys mapped to this fingerprint.
	char buffer[MAX_KEY_SIZE];
	slice db_query = padded_slice(&colliding_fingerprint, MAX_KEY_SIZE, sizeof(colliding_fingerprint), buffer, 0);
	splinterdb_lookup(arqf->rhm, db_query, arqf->db_result);
	slice result_val;
	splinterdb_lookup_result_value(arqf->db_result, &result_val);

  // Extend the keepsake.
  uint64_t keepsake_start_index = collision_index;
  uint64_t keepsake_slots_written = 0; 
  for (uint64_t i=0; i < result_val.length; i += MAX_VAL_SIZE) {
    uint64_t key; // TODO(chesetti): Read this key.
    uint64_t new_fingerprint;
    uint64_t memento;
    _overwrite_keepsake(arqf->qf, new_fingerprint, memento, keepsake_start_index, &keepsake_slots_written); // Implement overwrite keepsake.
    // TODO(chesetti): Insert new fingerprints into the RHM.
  }
  // TODO(chesetti): Delete old fingerprint.
  

  return 0;
}
