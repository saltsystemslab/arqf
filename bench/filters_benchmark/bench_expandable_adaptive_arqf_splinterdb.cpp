/*
 * This file is part of Grafite <https://github.com/marcocosta97/grafite>.
 * Copyright (C) 2023 Marco Costa.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <boost/sort/sort.hpp>

#include "arqf.h"
#include "splinter_util.h"
#include "../bench_template.hpp"
#include "gqf.h"
#include "arqf_wt.h"
#include "gqf_int.h"

#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits) \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

/**
 * This file contains the benchmark for Memento filter.
 */

inline uint64_t MurmurHash64A(const void * key, int len, unsigned int seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t * data = (const uint64_t *)key;
	const uint64_t * end = data + (len/8);

	while(data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const unsigned char * data2 = (const unsigned char*)data;

	switch(len & 7) {
		case 7: h ^= (uint64_t)data2[6] << 48; do {} while (0);  /* fallthrough */
		case 6: h ^= (uint64_t)data2[5] << 40; do {} while (0);  /* fallthrough */
		case 5: h ^= (uint64_t)data2[4] << 32; do {} while (0);  /* fallthrough */
		case 4: h ^= (uint64_t)data2[3] << 24; do {} while (0);  /* fallthrough */
		case 3: h ^= (uint64_t)data2[2] << 16; do {} while (0);  /* fallthrough */
		case 2: h ^= (uint64_t)data2[1] << 8; do {} while (0); /* fallthrough */
		case 1: h ^= (uint64_t)data2[0];
						h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}

__attribute__((always_inline))
static inline uint32_t fast_reduce(uint32_t hash, uint32_t n) {
    // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    return (uint32_t) (((uint64_t) hash * n) >> 32);
}

inline void check_iteration_validity(QF *qf, uint64_t *hashes, uint64_t nkeys)
{
  printf("Running sanity\n");
  for (uint64_t i = 0; i < nkeys; i++) {
    if (qf_point_query(qf, hashes[i], QF_KEY_IS_HASH | QF_NO_LOCK) == 0) {
      printf("Point query %lld failed!\n", i);
      abort();
    }
  }

  for (uint64_t i = 1; i < nkeys; i++) {
    uint64_t k = (hashes[i] + hashes[i - 1]) >> 1;
    if (std::binary_search(hashes, hashes + nkeys, k,
                [=](const auto& lhs, const auto& rhs) { return qf_hash_cmp(qf, lhs, rhs) < 0; }))
        continue;
    if (qf_point_query(qf, k, QF_KEY_IS_HASH | QF_NO_LOCK) == 1) {
      abort();
    }
  }
  printf("sanity passed\n");
}

template <typename t_itr, typename... Args>
inline ARQF *init_arqf(const t_itr begin, const t_itr end, const double bpk, Args... args)
{
    auto&& t = std::forward_as_tuple(args...);
    auto queries_temp = std::get<0>(t);
    auto query_lengths = std::vector<uint64_t>(queries_temp.size());
    std::transform(queries_temp.begin(), queries_temp.end(), query_lengths.begin(), [](auto x) {
            auto [left, right, result] = x;
            return right - left + 1;
        });
    const uint64_t n_items = std::distance(begin, end);
    //const uint64_t seed = std::chrono::steady_clock::now().time_since_epoch().count();
    const uint64_t seed = 1380;
    const uint64_t max_range_size = *std::max_element(query_lengths.begin(), query_lengths.end());
    const double load_factor = 0.95;
    const uint64_t n_slots = n_items / load_factor + 100 * std::sqrt(n_items);
    uint32_t memento_bits = 1;
    while ((1ULL << memento_bits) < max_range_size)
        memento_bits++;
    memento_bits = memento_bits < 2 ? 2 : memento_bits;
    const uint32_t fingerprint_size = round(bpk * load_factor - memento_bits - 3.125);
    if (bpk * load_factor - memento_bits - 3.125 < 0) {
        abort();
    }
    uint32_t key_size = 0;
    while ((1ULL << key_size) < n_slots)
        key_size++;
    key_size += fingerprint_size;
    std::cerr << "key_size=" << key_size << " fingerprint_size=" << fingerprint_size << " memento_bits=" << memento_bits << std::endl;

    data_config* data_cfg;
    splinterdb_config* splinterdb_cfg;
    splinterdb* db;
    qf_init_splinterdb(&db, &data_cfg, &splinterdb_cfg, "rhm");
    ARQF* arqf = (ARQF*)malloc(sizeof(ARQF));
    arqf_init_with_rhm(arqf, db, n_slots, key_size, memento_bits, seed, true);
    //qf_set_auto_resize(arqf->qf, true);

    start_timer(build_time);

    auto key_hashes = std::vector<uint64_t>(n_items);
    std::transform(begin, end, key_hashes.begin(), [&](auto x) {
            uint64_t hash = arqf_hash(arqf->qf, x);
            return hash & BITMASK(arqf->qf->metadata->quotient_bits 
                    + arqf->qf->metadata->value_bits 
                    + arqf->qf->metadata->key_remainder_bits);
        });
    auto keys = std::vector<uint64_t>(n_items);
    std::transform(begin, end, keys.begin(), [&](auto x) {
            return x;
        });
    std::sort(key_hashes.begin(), key_hashes.end(), [=](const auto& lhs, const auto& rhs) { return qf_hash_cmp(arqf->qf, lhs, rhs) < 0; });
    int retcode = arqf_bulk_load(arqf, &key_hashes[0], &keys[0], key_hashes.size(), 0);
    if (retcode < 0) {
        std::cerr << "Failed to initialize iterator" << std::endl;
        abort();
    }
    stop_timer(build_time);
    check_iteration_validity(arqf->qf, &key_hashes[0], key_hashes.size());
    return arqf;
}

template <typename value_type>
inline void insert_arqf(ARQF* arqf, const value_type key)
{
  QF* qf = arqf->qf;
  if (qf->metadata->noccupied_slots >= qf->metadata->nslots * 0.95 ||
          qf->metadata->noccupied_slots + 1 >= qf->metadata->nslots) {
      t_start_expansion_time = timer::now();
      arqf_expand(arqf);
      t_end_expansion_time = timer::now();
      t_duration_expansion_time += std::chrono::duration_cast<std::chrono::nanoseconds>(t_end_expansion_time - t_start_expansion_time).count();
      just_expanded = true;
  }
  arqf_insert(arqf, key);
}

template <typename value_type>
inline bool query_arqf(ARQF* arqf, const value_type left, const value_type right)
{
  QF* qf = arqf->qf;
  uint64_t l_hash = arqf_hash(qf, left);
  uint64_t r_hash = arqf_hash(qf, right);

  int result;
  if (left == right) {
    result = qf_point_query(arqf->qf, l_hash, QF_KEY_IS_HASH | QF_NO_LOCK);
  } else {
    result = qf_range_query(arqf->qf, l_hash, r_hash, QF_KEY_IS_HASH | QF_NO_LOCK);
  }
  return result;
}

template <typename value_type>
inline bool adapt_arqf(ARQF *qf, const value_type left, const value_type right) 
{
  int ret = -1;
  if (left == right) {
    ret = arqf_adapt(qf, left, 0);
  } else {
    ret = arqf_adapt_range(qf, left, right, 0);
  }
  return (ret == 0);
}

inline bool should_reconstruct(ARQF* f) 
{
    return false;
}

inline size_t size_arqf(ARQF* f)
{
  return qf_get_total_size_in_bytes(f->qf);
}

inline int free_arqf(ARQF* f)
{
    return arqf_free(f);
}

inline void add_metadata(ARQF *qf) 
{
  test_out.add_measure("q_bits", qf->qf->metadata->quotient_bits);
  test_out.add_measure("r_bits", qf->qf->metadata->key_remainder_bits);
  test_out.add_measure("m_bits", qf->qf->metadata->value_bits);
  test_out.add_measure("n_slots", qf->qf->metadata->xnslots);
  test_out.add_measure("noccupied_slots", qf->qf->metadata->noccupied_slots);

  std::string expansion_str = std::to_string(expansion);
  test_out.add_measure("splinter_expand_read_seconds_" + expansion_str, qf->qf->metadata->splinter_expand_read_clocks);
  test_out.add_measure("splinter_expand_delete_seconds_" + expansion_str, qf->qf->metadata->splinter_expand_delete_clocks);
  test_out.add_measure("splinter_expand_insert_seconds_" + expansion_str, qf->qf->metadata->splinter_expand_insert_clocks);
  test_out.add_measure("clocks_per_sec" , CLOCKS_PER_SEC); 
}

template <
    typename InitFun, typename InsertFun, typename RangeFun, typename AdaptFun,
    typename ShouldReconstructFun, typename SizeFun, typename FreeFun,
    typename MetadataFun, typename... Args>
void run_test(
    argparse::ArgumentParser& parser,
    InitFun init_f,
    InsertFun insert_f,
    RangeFun range_f,
    AdaptFun adapt_f,
    ShouldReconstructFun should_reconstruct_f,
    SizeFun size_f,
    FreeFun free_f,
    MetadataFun metadata_f)
{
  auto test_type = parser.get<std::string>("--test-type");
  auto [keys, queries, arg] = read_parser_arguments(parser);
  if (test_type == "adaptivity_inmem") {
    experiment_adaptivity(
        init_f,
        range_f,
        adapt_f,
        size_f,
        metadata_f,
        arg,
        keys,
        queries,
        queries);
  } if (test_type == "expandability_inmem") {
    experiment_expandability(
        init_f,
        insert_f,
        range_f,
        adapt_f,
        should_reconstruct_f,
        size_f,
        free_f,
        metadata_f,
        arg,
        keys,
        queries,
        queries);
  } else if (test_type == "adaptivity_disk") {
    std::string db_home = parser.get<std::string>("keys");
    db_home += "_wtdb";
    experiment_adaptivity_disk(
        init_f,
        range_f,
        adapt_f,
        size_f,
        metadata_f,
        arg,
        db_home,
        keys,
        queries,
        queries);
  } else if (test_type == "expandability_disk") {
    std::string db_home = parser.get<std::string>("keys");
    db_home += "_wtdb";
    experiment_expandability_disk(
        init_f,
        insert_f,
        range_f,
        adapt_f,
        should_reconstruct_f,
        size_f,
        free_f,
        metadata_f,
        arg,
        db_home,
        keys,
        queries,
        queries);
  } else {
    std::cerr << "Specify which type of test to run with --test_type" << std::endl;
    abort();
  }
}

int main(int argc, char const *argv[])
{
    auto parser = init_parser("bench-expandability-splinter");
    try {
        parser.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << parser;
        std::exit(1);
    }
    auto test_type = parser.get<std::string>("--test-type");
    run_test(parser,
            pass_fun(init_arqf),
            pass_ref(insert_arqf),
            pass_ref(query_arqf),
            pass_ref(adapt_arqf),
            pass_ref(should_reconstruct),
            pass_ref(size_arqf),
            pass_ref(free_arqf),
            pass_ref(add_metadata));
    print_test();
    return 0;
}

