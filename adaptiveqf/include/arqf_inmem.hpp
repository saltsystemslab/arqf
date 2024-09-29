#ifndef _ARQF_INMEM_H_
#define _ARQF_INMEM_H_

#include "gqf.h"

#include <unordered_map>

struct InMemArqf {
  QF *qf;
  std::unordered_multimap<uint64_t, uint64_t> rhm;
};

int InMemArqf_init(InMemArqf* arqf, uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed, bool expandable);
int InMemArqf_bulk_load(InMemArqf* arqf, uint64_t *sorted_hashes, uint64_t *keys, uint64_t nkeys, int flags);
int InMemArqf_adapt(InMemArqf* arqf, uint64_t fp_key, int flags);
int InMemArqf_adapt_range(InMemArqf* arqf, uint64_t left, uint64_t right, int flags);

#endif
