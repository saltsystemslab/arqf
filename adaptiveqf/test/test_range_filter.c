#include "include/gqf.h"
#include "include/gqf_int.h"

#include <stdio.h>

// For pretty print.
static const char *k_green = "\033[0;32m";
static const char *k_white = "\033[0;0m";
static const char *k_red = "\033[31m";

const uint64_t nslots = 256;
const uint64_t key_bits = 13;
const uint64_t memento_bits = 5;

int main()
{
  QF qf;
  // VALUE_BITS must be equal to MEMENTO_BITS
  if (!qf_malloc(&qf, nslots, key_bits, memento_bits, QF_HASH_DEFAULT, 0)) {
    fprintf(stderr, "Failed to initialize filter\n");
    return -1;
  }
  fprintf(stderr,
          "%s######################### EXECUTING test_without_hashing "
          "########################%s\n",
          k_red, k_white);
  qf_dump_metadata(&qf);
  for(int i=0; i<5; i++) {
    // COUNT = 1
    uint64_t quotient = 0x00000000;
    printf("%lx\n", quotient);
    qf_insert(&qf, quotient, 5-i, 1, QF_NO_LOCK | QF_KEY_IS_HASH);
  }
  qf_dump(&qf);
  qf_dump_metadata(&qf);

  return 0;
}
