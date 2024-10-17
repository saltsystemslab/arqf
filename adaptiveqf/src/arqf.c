#include "arqf.h"
#include "gqf.h"
#include "include/splinter_util.h"
#include "splinterdb/platform_linux/public_platform.h"

#define GET_KEY_HASH(flag) (flag & QF_KEY_IS_HASH)
#define QF_KEY_IS_HASH (0x08)
#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

static inline uint64_t get_base_hash(QF *qf, uint64_t hash) {
    const uint32_t quotient_bits = qf->metadata->quotient_bits;
    const uint32_t orig_quotient_bits = qf->metadata->orig_quotient_bits;
    const uint32_t quotient_bit_diff = quotient_bits - orig_quotient_bits;

    const uint64_t fp_bits = hash >> quotient_bits;
    const uint64_t orig_quotient = (hash >> quotient_bit_diff) & BITMASK(orig_quotient_bits);
    const uint64_t extended_quotient_bits = hash & BITMASK(quotient_bit_diff);
    return orig_quotient | (extended_quotient_bits << orig_quotient_bits) | (fp_bits << quotient_bits);
}

int arqf_init_with_rhm(ARQF* arqf, splinterdb* rhm, uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed, bool expandable)
{
  QF* qf;
  qf = (QF*) malloc(sizeof(QF));
  qf_malloc(qf, nslots, key_bits, value_bits, QF_HASH_DEFAULT, seed, expandable);

  arqf->db_result = (splinterdb_lookup_result*) malloc(sizeof(splinterdb_lookup_result));
  splinterdb_lookup_result_init(rhm, arqf->db_result, 0, NULL);
  arqf->rhm = rhm;
  arqf->qf = qf;
  return 0;
}

int arqf_bulk_load(ARQF* arqf, uint64_t* sorted_hashes, uint64_t* keys, uint64_t nkeys, int flags) {
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
    fingerprint = get_base_hash(arqf->qf, fingerprint);
    db_insert(arqf->rhm, &fingerprint, sizeof(fingerprint), &key, sizeof(key), 1, 0);
  }
  return 0;
}

// x, y must be fingerprints (no mementos)
static inline uint8_t min_diff_fingerprint_size(uint64_t x, uint64_t y, int quotient_size, int remainder_size, int memento_size) {
  if (x == y) {
    return 255;
  }
  uint8_t fingerprint_size = quotient_size + remainder_size;
  while ((x & BITMASK(fingerprint_size)) == (y & BITMASK(fingerprint_size))) {
      if (fingerprint_size == quotient_size + remainder_size)
        fingerprint_size += memento_size; // First extension is memento size.
      else
          fingerprint_size += (remainder_size + memento_size);
      if (fingerprint_size > 64)
        return 255;
  }
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

static inline int adapt_keepsake(
    ARQF *arqf, 
    uint64_t *colliding_keys,
    uint64_t num_colliding_keys,
    uint64_t fp_key,
    uint64_t fp_hash,
    uint64_t keepsake_fingerprint, 
    uint64_t keepsake_start,
    uint64_t keepsake_end) {
#if DEBUG 
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
  uint64_t last_overwritten_index = keepsake_start-1;   // Underflow issues?
  uint8_t min_required_fingerprint_size = 0;
  // TODO(Chesetti): Erase old fingerprint
  char buffer[MAX_KEY_SIZE];
  uint64_t db_conv_hash = get_base_hash(arqf->qf, keepsake_fingerprint);
  slice db_query = padded_slice(&db_conv_hash, MAX_KEY_SIZE, sizeof(db_conv_hash), buffer, 0);
  splinterdb_delete(arqf->rhm, db_query); // Delete the old keys. They will be reinserted even if they map to same fingerprint.
  
  for (int i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
    uint64_t collision_prefix = collision_hash >> memento_size;
    if (collision_prefix == fp_prefix) {
#if DEBUG
      if ((fp_key >> memento_size) != key_in_keepsake >> memento_size) {
        printf("Collision on hash detected, need more bits, might fail to adapt.\n");
      }
#endif
      continue;
    }
    uint64_t collision_memento = collision_hash & BITMASK(memento_size);
    uint8_t new_fingerprint_size = min_diff_fingerprint_size(fp_prefix, collision_prefix, quotient_size, remainder_size, memento_size);
    if (min_required_fingerprint_size < new_fingerprint_size) min_required_fingerprint_size = new_fingerprint_size;
  }

  if (min_required_fingerprint_size == 255 || min_required_fingerprint_size == 0) {
    for (uint64_t i=0; i < num_colliding_keys; i++) {
      uint64_t key_in_keepsake = colliding_keys[i];
#if DEBUG
      uint64_t collision_hash = arqf_hash(arqf->qf, key_in_keepsake);
      uint64_t collision_prefix = (collision_hash) >> memento_size;
      printf("Not enough bits to break collision\n");
#endif
      db_conv_hash = get_base_hash(arqf->qf, keepsake_fingerprint);
      db_insert(arqf->rhm, &db_conv_hash, sizeof(db_conv_hash), &key_in_keepsake, sizeof(key_in_keepsake), 1, 0);
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
    db_conv_hash = get_base_hash(arqf->qf, new_fingerprint_bits);
    db_insert(arqf->rhm, &db_conv_hash, sizeof(db_conv_hash), &key_in_keepsake, sizeof(key_in_keepsake), 1, 0);
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

static inline int int64_t_compare(const void *a, const void *b) {
    return (*(int64_t *)a - *(int64_t *)b);
}

static inline int maybe_adapt_keepsake_expandable(ARQF *arqf, uint64_t fp_key, uint64_t fp_hash, int query_type) {
#ifdef DEBUG
    validate_filter(arqf->qf);
#endif /* DEBUG */
    const uint64_t quotient_size = arqf->qf->metadata->quotient_bits;
    const uint64_t remainder_size = arqf->qf->metadata->key_remainder_bits;
    const uint64_t memento_size = arqf->qf->metadata->value_bits;
    uint64_t db_conv_hash;

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

    uint64_t *colliding_keys = NULL;
    uint64_t num_colliding_keys = 0;
    for (int32_t i = 0; i < matching_fp_ind; i++) {
        uint64_t matching_fp_size;
        uint64_t colliding_fingerprint = read_fingerprint_bits(arqf->qf, matching_fp_pos[i], &matching_fp_size);
        colliding_fingerprint |= 1ULL << matching_fp_size;
        colliding_fingerprint = (colliding_fingerprint << quotient_size) | bucket_index;

        char buffer[MAX_KEY_SIZE];
        db_conv_hash = get_base_hash(arqf->qf, colliding_fingerprint);
        slice db_query = padded_slice(&db_conv_hash, MAX_KEY_SIZE, sizeof(db_conv_hash), buffer, 0);
        splinterdb_lookup(arqf->rhm, db_query, arqf->db_result);
        if (!splinterdb_lookup_found(arqf->db_result))
            abort(); // Improperly maintained RHM.
        slice result_val;
        splinterdb_lookup_result_value(arqf->db_result, &result_val);

        const uint32_t num_new_colliding_keys = result_val.length / MAX_VAL_SIZE;
        uint64_t *tmp = colliding_keys;
        colliding_keys = calloc(num_colliding_keys + num_new_colliding_keys, sizeof(uint64_t));
        memcpy(colliding_keys, tmp, num_colliding_keys * sizeof(uint64_t));
        free(tmp);
        for (uint64_t i = 0; i < result_val.length; i += MAX_VAL_SIZE)
            colliding_keys[num_colliding_keys + i / MAX_VAL_SIZE] = *(uint64_t*)(slice_data(result_val) + i);
        num_colliding_keys += num_new_colliding_keys;
    }

    if (query_type != POINT_QUERY && 
            !should_adapt_keepsake(colliding_keys, num_colliding_keys, fp_hash, query_type, memento_size)) {
        free(colliding_keys);
        return -1;
    }

    uint64_t run_size = runend_pos - runstart_pos + 1;
    for (int32_t i = matching_fp_ind - 1; i >= 0; i--) {
        uint64_t matching_fp_size;
        uint64_t keepsake_fingerprint = read_fingerprint_bits(arqf->qf, matching_fp_pos[i], &matching_fp_size);
        keepsake_fingerprint = ((keepsake_fingerprint | (1ULL << matching_fp_size)) << quotient_size)
                                | bucket_index;
        char buffer[MAX_KEY_SIZE];
        uint64_t db_conv_hash = get_base_hash(arqf->qf, keepsake_fingerprint);
        slice db_query = padded_slice(&db_conv_hash, MAX_KEY_SIZE, sizeof(db_conv_hash), buffer, 0);
        splinterdb_delete(arqf->rhm, db_query); // Delete the old keys. They will be reinserted even if they map to same fingerprint.

        const uint32_t keepsake_size = get_keepsake_len(arqf->qf, matching_fp_pos[i]);
        remove_keepsake_and_shift_remainders_and_runends_and_offsets(arqf->qf,
                                                                     run_size == keepsake_size,
                                                                     bucket_index,
                                                                     matching_fp_pos[i],
                                                                     keepsake_size);
        run_size -= keepsake_size;
    }

    uint64_t hash_key_pairs[2 * num_colliding_keys];
    for (int32_t i = 0; i < num_colliding_keys; i++) {
        hash_key_pairs[2 * i] = arqf_hash(arqf->qf, colliding_keys[i]);
        hash_key_pairs[2 * i + 1] = colliding_keys[i];
    }
    qsort(hash_key_pairs, num_colliding_keys, 2 * sizeof(uint64_t), int64_t_compare);
    uint8_t min_new_fp_size = 0;
    for (int32_t i = 0; i < num_colliding_keys; i++) {
        const uint8_t current_diff = min_diff_fingerprint_size(fp_hash, 
                                                               hash_key_pairs[2 * i] >> memento_size,
                                                               quotient_size,
                                                               remainder_size,
                                                               memento_size);
        min_new_fp_size = min_new_fp_size < current_diff ? current_diff : min_new_fp_size;
    }
    uint64_t mementos[num_colliding_keys];
    uint64_t prev_fp = (hash_key_pairs[0] >> memento_size) & BITMASK(min_new_fp_size), cur_fp;
    uint32_t num_mementos = 0;
    mementos[num_mementos++] = hash_key_pairs[0] & BITMASK(memento_size);
    for (int32_t i = 1; i < num_colliding_keys; i++) {
        cur_fp = (hash_key_pairs[2 * i] >> memento_size) & BITMASK(min_new_fp_size);
        if (cur_fp != prev_fp) {
            qf_insert_keepsake_merge(arqf->qf, prev_fp, min_new_fp_size, mementos, num_mementos, QF_KEY_IS_HASH);
            num_mementos = 0;
            prev_fp = cur_fp;
        }
        mementos[num_mementos++] = hash_key_pairs[2 * i] & BITMASK(memento_size);
    }
    qf_insert_keepsake_merge(arqf->qf, prev_fp, min_new_fp_size, mementos, num_mementos, QF_KEY_IS_HASH);
    for (int32_t i = 0; i < num_colliding_keys; i++) {
        const uint64_t hash = hash_key_pairs[2 * i];
        const uint64_t key = hash_key_pairs[2 * i + 1];
        const uint64_t rhm_hash = ((hash >> memento_size) & BITMASK(min_new_fp_size)) | (1ULL << min_new_fp_size);
        db_conv_hash = get_base_hash(arqf->qf, rhm_hash);
        db_insert(arqf->rhm, &db_conv_hash, sizeof(db_conv_hash), &key, sizeof(key), 1, 0);
    }
#if DEBUG
  for (uint64_t i=0; i < num_colliding_keys; i++) {
    uint64_t key_in_keepsake = colliding_keys[i];
    assert(qf_point_query(arqf->qf, key_in_keepsake, 0) == 1);
  }
  assert(qf_point_query(arqf->qf, (fp_hash << memento_size) | fp_key & BITMASK(memento_size), QF_KEY_IS_HASH) == 0);
  validate_filter(arqf->qf);
#endif
    free(colliding_keys);
    return 0;
}

static inline int maybe_adapt_keepsake(ARQF *arqf, uint64_t fp_key, uint64_t fp_hash, int query_type) {
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

  char buffer[MAX_KEY_SIZE];
  slice db_query = padded_slice(&colliding_fingerprint, MAX_KEY_SIZE, sizeof(colliding_fingerprint), buffer, 0);
  splinterdb_lookup(arqf->rhm, db_query, arqf->db_result);
  if (!splinterdb_lookup_found(arqf->db_result))
    abort(); // Improperly maintained RHM.
  slice result_val;
  splinterdb_lookup_result_value(arqf->db_result, &result_val);

  uint64_t num_colliding_keys = result_val.length / MAX_VAL_SIZE;
  uint64_t *colliding_keys = (uint64_t *)malloc(num_colliding_keys * sizeof(uint64_t));
  for (uint64_t i = 0; i < result_val.length; i += MAX_VAL_SIZE) {
    uint64_t key = *(uint64_t*)(slice_data(result_val) + i);
    colliding_keys[i / MAX_VAL_SIZE] = key;
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

int arqf_adapt_range(ARQF *arqf, uint64_t left, uint64_t right, int flags) {
  uint64_t l_prefix = left >> (arqf->qf->metadata->value_bits);
  uint64_t r_prefix = right >> (arqf->qf->metadata->value_bits);
  uint64_t l_hash = left;
  uint64_t r_hash = right;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    l_hash = arqf_hash(arqf->qf, l_hash);
    r_hash = arqf_hash(arqf->qf, r_hash);
  }
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

int arqf_adapt(ARQF* arqf, uint64_t fp_key, int flags)
{
  uint64_t fp_hash = fp_key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    fp_hash = arqf_hash(arqf->qf, fp_key);
  }
  return maybe_adapt_keepsake(arqf, fp_key, fp_hash, POINT_QUERY);
}

static inline uint64_t move_one_bit_in_hash(QF *qf, uint64_t hash) {
    const uint32_t quotient_bit_diff = qf->metadata->quotient_bits - qf->metadata->orig_quotient_bits;
    const uint64_t fp_bits = hash >> qf->metadata->quotient_bits;
    const uint64_t orig_quotient = (hash >> (quotient_bit_diff - 1)) & BITMASK(qf->metadata->orig_quotient_bits);
    const uint64_t extended_quotient_bits = (hash & BITMASK(quotient_bit_diff - 1))
        | (((hash >> (qf->metadata->quotient_bits - 1)) & 1ULL) << (quotient_bit_diff - 1));
    return extended_quotient_bits | (orig_quotient << quotient_bit_diff) | (fp_bits << qf->metadata->quotient_bits);
}

static inline void move_and_maybe_rejuvenate_keepsake(ARQF *arqf, QF *new_qf,
                                                      uint64_t hash, uint32_t hash_len,
                                                      uint64_t *mementos, uint32_t num_mementos) {
    const uint32_t quotient_size = new_qf->metadata->quotient_bits;
    const uint32_t remainder_size = new_qf->metadata->key_remainder_bits;
    const uint32_t memento_size = new_qf->metadata->value_bits;

    if (hash_len < quotient_size) {     // Rejuvenate using reverse map
        const uint32_t rejuv_hash_size = quotient_size + remainder_size;
        const uint64_t capped_hash = hash | (new_qf->metadata->is_expandable ? 1ULL << hash_len : 0ULL);

        char buffer[MAX_KEY_SIZE];
        uint64_t db_conv_hash = get_base_hash(arqf->qf, capped_hash);
        slice db_query = padded_slice(&db_conv_hash, MAX_KEY_SIZE, sizeof(db_conv_hash), buffer, 0);
        splinterdb_lookup(arqf->rhm, db_query, arqf->db_result);
        if (!splinterdb_lookup_found(arqf->db_result))
            abort(); // Improperly maintained RHM.
        slice result_val;
        splinterdb_lookup_result_value(arqf->db_result, &result_val);

        uint64_t num_colliding_keys = result_val.length / MAX_VAL_SIZE;
        uint64_t colliding_keys[num_colliding_keys];
        for (uint64_t i = 0; i < result_val.length; i += MAX_VAL_SIZE) {
            uint64_t key = *(uint64_t*)(slice_data(result_val) + i);
            colliding_keys[i / MAX_VAL_SIZE] = key;
        }
        db_query = padded_slice(&db_conv_hash, MAX_KEY_SIZE, sizeof(db_conv_hash), buffer, 0);
        splinterdb_delete(arqf->rhm, db_query); // Delete the old keys. They will be reinserted even if they map to same fingerprint.

        uint64_t hash_key_pairs[2 * num_colliding_keys];
        for (int32_t i = 0; i < num_colliding_keys; i++) {
            hash_key_pairs[2 * i] = arqf_hash(new_qf, colliding_keys[i]);
            hash_key_pairs[2 * i + 1] = colliding_keys[i];
        }
        qsort(hash_key_pairs, num_colliding_keys, 2 * sizeof(uint64_t), int64_t_compare);
        uint64_t prev_fp = (hash_key_pairs[0] >> memento_size) & BITMASK(rejuv_hash_size), cur_fp;
        uint32_t num_mementos = 0;
        uint64_t mementos[num_colliding_keys];
        mementos[num_mementos++] = hash_key_pairs[0] & BITMASK(memento_size);
        for (int32_t i = 1; i < num_colliding_keys; i++) {
            cur_fp = (hash_key_pairs[2 * i] >> memento_size) & BITMASK(rejuv_hash_size);
            if (cur_fp != prev_fp) {
                qf_insert_keepsake_merge(new_qf, prev_fp, rejuv_hash_size, mementos, num_mementos, QF_KEY_IS_HASH);
                num_mementos = 0;
                prev_fp = cur_fp;
            }
            mementos[num_mementos++] = hash_key_pairs[2 * i] & BITMASK(memento_size);
        }
        qf_insert_keepsake_merge(new_qf, prev_fp, rejuv_hash_size, mementos, num_mementos, QF_KEY_IS_HASH);
        for (int32_t i = 0; i < num_colliding_keys; i++) {
            const uint64_t hash = hash_key_pairs[2 * i];
            const uint64_t key = hash_key_pairs[2 * i + 1];
            const uint64_t rhm_hash = ((hash >> memento_size) & BITMASK(rejuv_hash_size)) | (1ULL << rejuv_hash_size);
            db_conv_hash = get_base_hash(new_qf, rhm_hash);
            db_insert(arqf->rhm, &db_conv_hash, sizeof(db_conv_hash), &key, sizeof(key), 1, 0);
        }
    }
    else
        qf_insert_keepsake_merge(new_qf, hash, hash_len, mementos, num_mementos, QF_KEY_IS_HASH);
}


int arqf_expand(ARQF *arqf) {
    perror("EXPANSION JUTSU!!!");
    QF *qf = arqf->qf;
    const uint64_t nslots = 2 * qf->metadata->nslots;

	QF new_qf;
	if (!qf_malloc(&new_qf, nslots, qf->metadata->key_bits + 1, qf->metadata->value_bits,
                   qf->metadata->hash_mode, qf->metadata->seed, qf->metadata->is_expandable))
        return 0;
	if (qf->runtimedata->auto_resize)
        qf_set_auto_resize(&new_qf, true);
    new_qf.metadata->orig_quotient_bits = qf->metadata->orig_quotient_bits;

    uint64_t hash, mementos[50 * (1ULL << new_qf.metadata->value_bits) + 50];
    uint32_t hash_len, num_mementos = 0;
	QFi qfi;
    qf_iterator_from_position(qf, &qfi, 0);
	qfi_get_hash(&qfi, &hash, &hash_len, mementos + num_mementos);
    hash = hash_len < new_qf.metadata->quotient_bits ? hash : move_one_bit_in_hash(&new_qf, hash);
    num_mementos++;
    for (qfi_next(&qfi); !qfi_end(&qfi); qfi_next(&qfi)) {
        uint64_t new_hash, new_memento;
        uint32_t new_hash_len;
        qfi_get_hash(&qfi, &new_hash, &new_hash_len, &new_memento);
        new_hash = new_hash_len < new_qf.metadata->quotient_bits ? new_hash : move_one_bit_in_hash(&new_qf, new_hash);
        if (new_hash_len == hash_len && new_hash == hash)
            mementos[num_mementos++] = new_memento;
        else {
            move_and_maybe_rejuvenate_keepsake(arqf, &new_qf, hash, hash_len, mementos, num_mementos);
            hash = new_hash;
            hash_len = new_hash_len;
            mementos[0] = new_memento;
            num_mementos = 1;
        }
    }
    move_and_maybe_rejuvenate_keepsake(arqf, &new_qf, hash, hash_len, mementos, num_mementos);

	qf_free(qf);
	memcpy(qf, &new_qf, sizeof(QF));

	return 1;
}

int arqf_insert(ARQF *arqf, uint64_t key) {
    QF *qf = arqf->qf;
    const uint64_t hash = arqf_hash(qf, key);
    const uint32_t required_hash_len = qf_insert_memento(qf, hash, QF_KEY_IS_HASH);
    const uint64_t rhm_hash = ((hash >> qf->metadata->value_bits) & BITMASK(required_hash_len))
                                | (qf->metadata->is_expandable ? 1ULL << required_hash_len : 0ULL);
    const uint64_t db_conv_hash = get_base_hash(qf, rhm_hash);
    db_insert(arqf->rhm, &db_conv_hash, sizeof(db_conv_hash), &key, sizeof(key), 1, 0);
    return 1;
}

