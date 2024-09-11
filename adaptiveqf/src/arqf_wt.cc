#include "arqf_wt.h"
#include "bigint.hpp"
#include "gqf_int.h"
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
  const int key_len = 8;
  const int val_len = 8;

  WT_CONNECTION* conn;
  WT_SESSION* session;
  WT_CURSOR* cursor;
  char table_schema[max_schema_len];
  char connection_config[max_conn_config_len];
  sprintf(table_schema, "key_format=%lds,value_format=%lds", key_len, val_len);
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

int WtArqf_bulk_load(WtArqf* arqf, uint64_t* sorted_hashes, uint64_t* keys, uint64_t nkeys, int flags)
{
  const int key_len = 8;
  const int val_len = 8;
  const uint64_t quotient_bits = arqf->qf->metadata->quotient_bits;
  const uint64_t remainder_bits = arqf->qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = arqf->qf->metadata->value_bits;

  SimpleBigInt big_int_k(key_len), big_int_v(val_len);
  SimpleBigInt big_int_l(key_len), big_int_r(key_len);
  for (uint64_t i = 0; i < nkeys; i++) {
    uint64_t key = keys[i];
    uint64_t hash = keys[i];
    if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
      hash = arqf_hash(arqf->qf, key);
    }
    uint64_t fingerprint = (hash >> memento_bits) & BITMASK(quotient_bits + remainder_bits);
    big_int_k = fingerprint;
    big_int_v = key;
    arqf->cursor->set_key(arqf->cursor, big_int_k);
    arqf->cursor->set_value(arqf->cursor, big_int_v);
    error_check(arqf->cursor->insert(arqf->cursor));
  }
  return 0;
}

bool WtArqf_adapt(WtArqf* arqf, uint64_t fp_key, int flags) {
  return -1;
}

bool WtArqf_adapt_range(WtArqf* arqf, uint64_t left, uint64_t right, int flags) {
  return -1;
}
