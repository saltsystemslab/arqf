#include "gqf.h"
#include "gqf_int.h"
#include <assert.h>

#define SEED 1
#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

const uint64_t nslots = 200;
const uint64_t key_bits = 13;
const uint64_t memento_bits = 4; // bits_per_slot should be 9 now.

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


int main()
{
  test_bulk_load();
}
