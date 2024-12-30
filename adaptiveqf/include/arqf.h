#ifndef _ARQF_SPLINTER_H_
#define _ARQF_SPLINTER_H_

#include "gqf.h"

#include <splinterdb/data.h>
#include <splinterdb/default_data_config.h>
#include <splinterdb/public_platform.h>
#include <splinterdb/public_util.h>
#include <splinterdb/splinterdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct adaptive_range_quotient_filter adaptive_range_quotient_filter;
typedef adaptive_range_quotient_filter ARQF;

struct adaptive_range_quotient_filter {
  QF* qf;
  splinterdb* rhm;
  splinterdb_lookup_result* db_result;
};

/* Initialize and allocate memory for AQF and the reverse hash map. 
   * Will allocate the required bytes using malloc.
   * A SplinterDB instance will be created at the passed path to be used as a reverse hash map.
   **/
int arqf_init_with_rhm(ARQF* arqf, splinterdb* db, uint64_t nslots, uint64_t key_bits, uint64_t value_bits, uint64_t seed, bool expandable);

/*
   * Bulk load the RHM and filter with the keys and hashes.
   * Chesetti: This is not most ideal API. Ideally this would be arqf_bulk_load(arqf, keys, nkeys).
   * But I haven't figured out how to call the boost sort method from C (it might be easy, it might be hard, just haven't tried it out)
   * So I use the arqf_hash to compute the hashes and sort them outside. 
   * The keys DO not have to be sorted. We compute the hash again when inserting into the RHM (Again, not the most ideal).. 
   * TODO(chesetti): Revisit bulk load API.
   *  */
int arqf_bulk_load(ARQF* arqf, uint64_t* sorted_hashes, uint64_t* keys, uint64_t nkeys, int flags);
int arqf_adapt(ARQF* arqf, uint64_t fp_key, int flags);
int arqf_adapt_range(ARQF* arqf, uint64_t left, uint64_t right, int flags);

int arqf_expand(ARQF *arqf);
int arqf_expand_full(ARQF *arqf);
int arqf_insert(ARQF *arqf, uint64_t key);
int arqf_free(ARQF *arqf);

#ifdef __cplusplus
}
#endif

#endif
