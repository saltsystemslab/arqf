#include "gqf.h"
#include "gqf_int.h"

#define SEED 1

const uint64_t nslots = 256;
const uint64_t key_bits = 13;
const uint64_t memento_bits = 5;

void test_without_hashing() {
  QF *qf;
  qf_malloc(qf, nslots, key_bits, memento_bits, QF_HASH_NONE, SEED);
}

int main() {
  test_without_hashing();
}
