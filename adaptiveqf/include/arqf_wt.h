#ifndef _ARQF_INMEM_H_
#define _ARQF_INMEM_H_

#include "gqf.h"

#include <wiredtiger.h>

struct WtArqf {
  QF* qf;
  WT_CONNECTION* conn;
  WT_SESSION* session;
  WT_CURSOR *cursor;
};

int WtArqf_init(WtArqf* arqf, uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed);
int WtArqf_bulk_load(WtArqf* arqf, uint64_t *sorted_hashes, uint64_t *keys, uint64_t nkeys, int flags);
int WtArqf_adapt(WtArqf* arqf, uint64_t fp_key, int flags);
int WtArqf_adapt_range(WtArqf* arqf, uint64_t left, uint64_t right, int flags);

#endif
