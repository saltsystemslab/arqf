#include "gqf.h"
#include "gqf_int.h"

#define SEED 1

const uint64_t nslots = 256;
const uint64_t key_bits = 13;
const uint64_t memento_bits = 5;

void test_without_hashing() {
  QF qf;
  qf_malloc(&qf, nslots, key_bits, memento_bits, QF_HASH_NONE, SEED);
  uint64_t sorted_hashes[5];
  for (uint64_t i=0; i<5; i++) {
    uint64_t quotient = 0; //nslots = 256, so quotient bits = 8
    uint64_t remainder = 31; // remainder 5 bits
    uint64_t memento = i+10;
    uint64_t hash = (quotient << 8) | (remainder << 5) | memento;
    sorted_hashes[i] = hash;
  }
  qf_bulk_load(&qf, sorted_hashes, 5);
}

int main() {
  test_without_hashing();
}
