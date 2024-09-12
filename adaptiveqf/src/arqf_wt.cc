#include "arqf_wt.h"
#include "arqf_inmem.hpp"
#include "bigint.hpp"
#include "gqf_int.h"
#include <cassert>
#include <filesystem>

#define GET_KEY_HASH(flag) (flag & QF_KEY_IS_HASH)
#define QF_KEY_IS_HASH (0x08)
#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

static const char *wt_home = "./rhm_database_home";
const uint32_t max_schema_len = 128;
const uint32_t max_conn_config_len = 128;

static inline void error_check(int ret)
{
  if (ret != 0) {
    std::cerr << "WiredTiger Error: " << wiredtiger_strerror(ret) << std::endl;
    exit(ret);
  }
}

int WtArqf_init(
    WtArqf* arqf, uint64_t wt_buffer_pool_size_mb,
    uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed)
{
  QF* qf;
  qf = (QF*)malloc(sizeof(QF));
  qf_malloc(qf, nslots, key_bits, value_bits, QF_HASH_DEFAULT, seed);
  arqf->qf = qf;

  WT_CONNECTION* conn;
  WT_SESSION* session;
  WT_CURSOR* cursor;
  char table_schema[max_schema_len];
  char connection_config[max_conn_config_len];
  sprintf(table_schema, "key_format=Q,value_format=u");
  sprintf(connection_config, "create,statistics=(all),direct_io=[data],cache_size=%ldMB", wt_buffer_pool_size_mb);

  if (std::filesystem::exists(wt_home))
    std::filesystem::remove_all(wt_home);
  std::filesystem::create_directory(wt_home);

  error_check(wiredtiger_open(wt_home, NULL, connection_config, &conn));
  error_check(conn->open_session(conn, NULL, NULL, &session));
  error_check(session->create(session, "table:rhm", table_schema));
  error_check(session->open_cursor(session, "table:rhm", NULL, NULL, &cursor));
  std::cerr << "[+] WiredTiger (as RHM) initialized" << std::endl;
  arqf->conn = conn;
  arqf->session = session;
  arqf->cursor = cursor;
  return 0;
}

inline void upsert_key(WT_CURSOR *cursor, uint64_t key, uint64_t value) {
  WT_ITEM db_value;
  char *value_buf[8];
  memcpy(value_buf, &value, sizeof(uint64_t));
  db_value.data = value_buf;
  db_value.size = sizeof(uint64_t);
  
  cursor->set_key(cursor, key);
  int ret = cursor->search(cursor);
  if (ret == WT_NOTFOUND) {
      cursor->set_key(cursor, key);
      cursor->set_value(cursor, &db_value);
      error_check(cursor->insert(cursor));
  } else {
    WT_ITEM old_value;
    error_check(cursor->get_value(cursor, &old_value));
    char *new_value_buf[old_value.size + sizeof(uint64_t)];
    memcpy(new_value_buf, old_value.data, old_value.size);
    memcpy(new_value_buf + old_value.size, &value, sizeof(uint64_t));

    WT_ITEM new_value;
    new_value.data = new_value_buf;
    new_value.size = old_value.size + sizeof(uint64_t);
    cursor->set_key(cursor, key);
    cursor->set_value(cursor, &new_value);
    error_check(cursor->insert(cursor));
  }
}


int WtArqf_bulk_load(WtArqf* arqf, uint64_t* sorted_hashes, uint64_t* keys, uint64_t nkeys, int flags)
{
  qf_bulk_load(arqf->qf, sorted_hashes, nkeys);
  const uint64_t quotient_bits = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_bits = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = arqf->qf->metadata->value_bits;

  for (uint64_t i = 0; i < nkeys; i++) {
    uint64_t key = keys[i];
    uint64_t hash = keys[i];
    if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
      hash = arqf_hash(arqf->qf, key);
    }
    uint64_t fingerprint = (hash >> memento_bits) & BITMASK(quotient_bits + remainder_bits);
    upsert_key(arqf->cursor, fingerprint, keys[i]);
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

inline int adapt_keepsake(
    WtArqf *arqf, 
    uint64_t *colliding_keys,
    uint64_t num_colliding_keys,
    uint64_t fp_key,
    uint64_t fp_hash,
    uint64_t keepsake_fingerprint, 
    uint64_t keepsake_start,
    uint64_t keepsake_end) {
#if DEBUG 
   printf("Adapting hash: %016llx in keepsake[%llu %llu] containing %u keys\n", fp_hash, keepsake_start, keepsake_end, num_colliding_keys);
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
  // TODO(Chesetti): Erase old fingerprint
  arqf->cursor->reset(arqf->cursor);
  arqf->cursor->set_key(arqf->cursor, keepsake_fingerprint);
  error_check(arqf->cursor->remove(arqf->cursor));
  
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
      // TODO(chesetti): Insert new extended fingerprint
      // arqf->rhm.insert({keepsake_fingerprint, key_in_keepsake});
      upsert_key(arqf->cursor, keepsake_fingerprint, key_in_keepsake);
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
    // TODO(chesetti): Insert new fingerprint
    // arqf->rhm.insert({new_fingerprint_bits, key_in_keepsake});
    upsert_key(arqf->cursor, keepsake_fingerprint, key_in_keepsake);
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

inline int  maybe_adapt_keepsake(WtArqf *arqf, uint64_t fp_key, uint64_t fp_hash, int query_type) {
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
    printf("Hit space limit %llu %llu\n", arqf->qf->metadata->noccupied_slots, arqf->qf->metadata->xnslots);
    return -1; // not enough space;
  }

  WT_ITEM value;
  arqf->cursor->set_key(arqf->cursor, colliding_fingerprint);
  error_check(arqf->cursor->search(arqf->cursor));
  error_check(arqf->cursor->get_value(arqf->cursor, &value));
  uint64_t num_colliding_keys = value.size / sizeof(uint64_t);
  uint64_t *colliding_keys = (uint64_t *)value.data;
  // TODO(chesetti): Change this, fetch keys from WiredTiger;
  // uint64_t num_colliding_keys = arqf->rhm.count(colliding_fingerprint);
  // uint64_t* colliding_keys = (uint64_t*)malloc(num_colliding_keys * sizeof(uint64_t));
  // int i = 0;
  // auto range = arqf->rhm.equal_range(colliding_fingerprint);
  // for (auto it = range.first; it != range.second; it++) {
    // colliding_keys[i++] = it->second;
  //}
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
  return ret;
}

int WtArqf_adapt_range(WtArqf* arqf, uint64_t left, uint64_t right, int flags) {
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

int WtArqf_adapt(WtArqf* arqf, uint64_t fp_key, int flags) {
  // Find the colliding fingerprint which caused fp
  uint64_t fp_hash = fp_key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    fp_hash = arqf_hash(arqf->qf, fp_key);
  }
  return maybe_adapt_keepsake(arqf, fp_key, fp_hash, POINT_QUERY);
}
