#include "gqf.h"
#include "arqf.h"
#include "gqf_int.h"
#include "include/splinter_util.h"
#include <assert.h>

#define SEED 1
#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

#define MAX_KEY_SIZE 16
#define MAX_VAL_SIZE 16

const uint64_t nslots = 200;
const uint64_t key_bits = 13;
const uint64_t memento_bits = 4; // bits_per_slot should be 9 now.

void test_point_insert_in_order()
{
  QF qf;
  qf_malloc(&qf, nslots, key_bits, memento_bits, QF_HASH_NONE, SEED);

  uint64_t nkeys = 0;
  uint64_t hashes[255];

  // Insert at end
  for (uint64_t i = 0; i < 32; i++) {
     qf_insert_memento(&qf, i, QF_KEY_IS_HASH);
     hashes[i] = i;
     nkeys++;
  }

  QFi qfi;
  qf_iterator_from_position(&qf, &qfi, 0);
  uint64_t idx = 0;
  uint64_t hash = 0;
  while (!qfi_end(&qfi)) {
    qfi_get_memento_hash(&qfi, &hash);
    assert(hash == idx);
    qfi_next(&qfi);
    idx++;
  }
  assert(idx == nkeys);

  for (uint64_t i = 0; i < nkeys; i++) {
    assert(qf_point_query(&qf, hashes[i], QF_KEY_IS_HASH | QF_NO_LOCK) == 1);
  }
  qf_free(&qf);
}

void test_point_insert_reverse_order()
{
  QF qf;
  qf_malloc(&qf, nslots, key_bits, memento_bits, QF_HASH_NONE, SEED);

  uint64_t nkeys = 0;
  uint64_t hashes[255];

  // Insert at end
  for (int64_t i = 31; i >= 0 ; i--) {
      hashes[i] = i;
      qf_insert_memento(&qf, i, QF_KEY_IS_HASH);
      nkeys++;
  }

  QFi qfi;
  qf_iterator_from_position(&qf, &qfi, 0);
  uint64_t idx = 0;
  uint64_t hash = 0;
  while (!qfi_end(&qfi)) {
    qfi_get_memento_hash(&qfi, &hash);
    assert(hash == idx);
    qfi_next(&qfi);
    idx++;
  }
  assert(idx == nkeys);

  for (uint64_t i = 0; i < nkeys; i++) {
    assert(qf_point_query(&qf, hashes[i], QF_KEY_IS_HASH | QF_NO_LOCK) == 1);
  }
  qf_free(&qf);
}

void test_point_insert_across_quotients()
{
  QF qf;
  qf_malloc(&qf, nslots, key_bits, memento_bits, QF_HASH_NONE, SEED);

  uint64_t nkeys = 0;
  uint64_t sorted_hashes[255];

  // Insert at end
  for (int64_t i = 31; i >= 0 ; i--) {
     qf_insert_memento(&qf, i, QF_KEY_IS_HASH);
     qf_insert_memento(&qf, i | (1ULL << 9), QF_KEY_IS_HASH);
     sorted_hashes[i] = i;
     sorted_hashes[(i+32)] = i | (1ULL << 9);
  }
  nkeys = 32 * 2;

  QFi qfi;
  qf_iterator_from_position(&qf, &qfi, 0);
  uint64_t idx = 0;
  uint64_t hash = 0;
  while (!qfi_end(&qfi)) {
    qfi_get_memento_hash(&qfi, &hash);
    assert(hash == sorted_hashes[idx]);
    qfi_next(&qfi);
    idx++;
  }
  assert(idx == nkeys);

  for (uint64_t i = 0; i < nkeys; i++) {
    assert(qf_point_query(&qf, sorted_hashes[i], QF_KEY_IS_HASH | QF_NO_LOCK) == 1);
  }
  qf_free(&qf);
}

void test_bulk_load() {
  QF qf;
  qf_malloc(&qf, nslots, key_bits, memento_bits, QF_HASH_NONE, SEED);
  
  uint64_t nkeys = 0;
  uint64_t sorted_hashes[255];
  for (uint64_t i=0; i < (1<<key_bits) && nkeys < 255; i++) {
    if (rand() % (1<<key_bits) < nslots) {
      sorted_hashes[nkeys] = i;
      nkeys++;
    }
  }
  qf_bulk_load(&qf, sorted_hashes, nkeys);

  QFi qfi;
  qf_iterator_from_position(&qf, &qfi, 0);
  uint64_t idx = 0;
  uint64_t hash = 0;
  while (!qfi_end(&qfi)) {
    qfi_get_memento_hash(&qfi, &hash);
    assert(hash == sorted_hashes[idx]);
    qfi_next(&qfi);
    idx++;
  }
  assert(idx == nkeys);


  for (uint64_t i=0; i < nkeys; i++) {
    assert(qf_point_query(&qf, sorted_hashes[i], QF_KEY_IS_HASH | QF_NO_LOCK) == 1);
  }

  qf_free(&qf);
}

void test_splinter_ops() {
	data_config db_data_cfg = qf_data_config_init();
	splinterdb_config splinterdb_cfg = qf_splinterdb_config_init("db", &db_data_cfg);
	remove(splinterdb_cfg.filename);
	splinterdb *db;
	if (splinterdb_create(&splinterdb_cfg, &db)) {
    abort();
	}

  uint64_t key = 102;
  uint64_t val = 1010;
  db_insert(db, &key, sizeof(key), &val, sizeof(val), 1, 0);

  val = 1023;
  db_insert(db, &key, sizeof(key), &val, sizeof(val), 0, 0);

  val = 201023;
  db_insert(db, &key, sizeof(key), &val, sizeof(val), 1, 0);

	splinterdb_lookup_result db_result;
	splinterdb_lookup_result_init(db, &db_result, 0, NULL);

	char buffer[10 * MAX_VAL_SIZE];
	slice db_query = padded_slice(&key, MAX_KEY_SIZE, sizeof(key), buffer, 0);
	splinterdb_lookup(db, db_query, &db_result);
	slice result_val;
	splinterdb_lookup_result_value(&db_result, &result_val);
  uint64_t *value1_from_db = slice_data(result_val);
  printf("%lld\n", result_val.length);
  printf("%lld\n", *value1_from_db);

	splinterdb_close(&db);
}

void test_adaptivity() {
  splinterdb* db;
  data_config data_cfg = qf_data_config_init();
  splinterdb_config splinterdb_cfg = qf_splinterdb_config_init("rhm", &data_cfg);
  remove(splinterdb_cfg.filename);
  if (splinterdb_create(&splinterdb_cfg, &db)) {
    return -1;
  }

  ARQF arqf;
  arqf_init_with_rhm(&arqf, db, 256, 16, 4, 0);
  qf_dump_metadata(arqf.qf);

  uint64_t sorted_hashes[3] = {0xA01011, 0xA01012, 0xB01012};
  arqf_bulk_load(&arqf, sorted_hashes, sorted_hashes, 3, QF_KEY_IS_HASH);

  assert(qf_point_query(arqf.qf, 0x01011, QF_KEY_IS_HASH)==1);
  assert(qf_point_query(arqf.qf, 0x01012, QF_KEY_IS_HASH)==1);

  arqf_adapt(&arqf, 0x01011, QF_KEY_IS_HASH);

  assert(qf_point_query(arqf.qf, 0x01011, QF_KEY_IS_HASH)==0);
  assert(qf_point_query(arqf.qf, 0x01012, QF_KEY_IS_HASH)==0);
  assert(qf_point_query(arqf.qf, 0xAAA01011, QF_KEY_IS_HASH)==1);
  assert(qf_point_query(arqf.qf, 0xAAA01012, QF_KEY_IS_HASH)==1);

  arqf_adapt(&arqf, 0xAAA01011, QF_KEY_IS_HASH);

  assert(qf_point_query(arqf.qf, 0xAAA01011, QF_KEY_IS_HASH)==0);
  assert(qf_point_query(arqf.qf, 0xAAA01012, QF_KEY_IS_HASH)==0);
}


int main()
{
  test_bulk_load();
  test_point_insert_in_order();
  test_point_insert_reverse_order();
  test_point_insert_across_quotients();
  test_splinter_ops();
  test_adaptivity();
}
