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
#if 0
    QFi iter;
    qf_iterator_from_position(qf, &iter, 0);
    uint64_t hash_result;
    uint64_t cur_key = 0;

    while (!qfi_end(&iter)) {
      qfi_get_memento_hash(&iter, &hash_result);
      if (hashes[cur_key] != hash_result) {
        printf("Iterator did not match sorted hash order\n");
        printf("%lld\n%016llx\n%016llx\n", cur_key, hashes[cur_key], hash_result);
        abort();
      }
      while (hashes[cur_key] == hash_result) {
        cur_key++;
      };
      qfi_next(&iter);
    }
    assert(cur_key == nkeys);

#endif
    for (uint64_t i=0; i<nkeys; i++) {
      if (qf_point_query(qf, hashes[i], QF_KEY_IS_HASH | QF_NO_LOCK) == 0) {
        printf("Point query %lu failed!\n", i);
        abort();
      }
    }

    for (uint64_t i=1; i<nkeys; i++) {
      uint64_t k = (hashes[i] + hashes[i-1]) >> 1;
      if (k == hashes[i] || k == hashes[i-1]) continue;
      if (qf_point_query(qf, k, QF_KEY_IS_HASH | QF_NO_LOCK) == 1) {
        abort();
      }
    }
  printf("sanity passed\n");

#if 0
    do {
        if (mode) {
            std::cerr << "run=" << iter.run << " current=" << iter.current << " vs. nslots=" << qf->metadata->nslots << std::endl;
            //qf_dump_block(qf, 2654 / QF_SLOTS_PER_BLOCK);
        }
        int result_length = qfi_get_hash(&iter, &hash_result, memento_result);
        current_fingerprint = hash_result >> (qf->metadata->key_bits - qf->metadata->key_bits);
        assert(current_fingerprint > 0);
        if (iter.run != last_run)
            last_run = iter.run;
        else {
            if (last_fingerprint > current_fingerprint) {
                std::cerr << "HMMM iter.run=" << iter.run << " iter.current=" << iter.current << std::endl;
            }
            assert(last_fingerprint <= current_fingerprint);
        }
        last_fingerprint = current_fingerprint;
        for (int i = 1; i < result_length; i++) {
            if (memento_result[i] < memento_result[i - 1]) {
                std::cerr << "run=" << iter.run << " current=" << iter.current << std::endl;
                for (int j = 0; j < result_length; j++)
                    std::cerr << memento_result[j] << ' ';
                std::cerr << std::endl;
            }
            assert(memento_result[i] >= memento_result[i - 1]);
        }

    } while (qfi_next(&iter) >= 0);
#endif
}

template <typename t_itr, typename... Args>
inline ARQF *init_qf(const t_itr begin, const t_itr end, bool load_keys, const double bpk, Args... args)
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
    const uint64_t n_slots = n_items / load_factor + std::sqrt(n_items);
    uint32_t memento_bits = 1;
    while ((1ULL << memento_bits) < max_range_size)
        memento_bits++;
    memento_bits = memento_bits < 2 ? 2 : memento_bits;
    const uint32_t fingerprint_size = round(bpk * load_factor - memento_bits - 2.125);
    if (bpk * load_factor - memento_bits - 2.125 < 0) {
        abort();
    }
    uint32_t key_size = 0;
    while ((1ULL << key_size) < n_slots)
        key_size++;
    key_size += fingerprint_size;
    std::cerr << "key_size="<< key_size << " fingerprint_size=" << fingerprint_size << " memento_bits=" << memento_bits << std::endl;

    data_config* data_cfg;
    splinterdb_config* splinterdb_cfg;
    splinterdb* db;
    qf_init_splinterdb(&db, &data_cfg, &splinterdb_cfg, "rhm");
    ARQF* arqf = (ARQF*)malloc(sizeof(ARQF));
    arqf_init_with_rhm(arqf, db, n_slots, key_size, memento_bits, seed);

    if (!load_keys) return arqf;

    start_timer(build_time);

    auto key_hashes = std::vector<uint64_t>(n_items);
    std::transform(begin, end, key_hashes.begin(), [&](auto x) {
      uint64_t hash = arqf_hash(arqf->qf, x);
      uint64_t memento_mask  = (1ULL << (arqf->qf->metadata->value_bits)) - 1;
      hash = (hash << arqf->qf->metadata->value_bits) | (x & memento_mask);
      uint64_t hash_mask  = (1ULL << (arqf->qf->metadata->quotient_bits + arqf->qf->metadata->bits_per_slot)) - 1;
      uint64_t key_hash = hash & (hash_mask);
      return hash & (hash_mask);
    });
    auto keys = std::vector<uint64_t>(n_items);
    std::transform(begin, end, keys.begin(), [&](auto x) {
        return x;
    });
    uint64_t nkeys  = key_hashes.size();
    boost::sort::spreadsort::spreadsort(key_hashes.begin(), key_hashes.end());

    int retcode = arqf_bulk_load(arqf, &key_hashes[0], &keys[0], key_hashes.size(), 0);
    if (retcode < 0) {
      std::cerr << "Failed to initialize iterator" << std::endl;
      abort();
    }

    stop_timer(build_time);
    // check_iteration_validity(arqf->qf, &key_hashes[0], nkeys);
    arqf->qf->metadata->n_filter_queries = 0;
    return arqf;
}

template <typename value_type>
inline bool adapt_qf(ARQF *qf, const value_type left, const value_type right) {
  int ret = -1;
  if (left == right) {
    ret = arqf_adapt(qf, left, 0);
  } else {
    ret = arqf_adapt_range(qf, left, right, 0);
  }
  return (ret == 0);
}

inline void add_metadata(ARQF *qf) {
  test_out.add_measure("q_bits", qf->qf->metadata->quotient_bits);
  test_out.add_measure("r_bits", qf->qf->metadata->key_remainder_bits);
  test_out.add_measure("m_bits", qf->qf->metadata->value_bits);
  test_out.add_measure("n_slots", qf->qf->metadata->xnslots);
  test_out.add_measure("noccupied_slots", qf->qf->metadata->noccupied_slots);
  test_out.add_measure("n_successful_adapts", qf->qf->metadata->n_successful_adapts);
  test_out.add_measure("n_failed_adapt_no_space", qf->qf->metadata->n_failed_adapt_no_space);
  test_out.add_measure("n_failed_adapt_no_bits", qf->qf->metadata->n_failed_adapt_no_bits);

  test_out.add_measure("qf_insert_duration", qf->qf->metadata->qf_insert_duration);
  test_out.add_measure("db_insert_duration", qf->qf->metadata->db_insert_duration);

  test_out.add_measure("n_filter_queries", qf->qf->metadata->n_filter_queries);
}

template <typename value_type>
inline bool insert_arqf(ARQF* arqf, const value_type value) 
{
  uint64_t fingerprint, key=value;
  start_timer(qf_insert);
  qf_insert_memento(arqf->qf, value, 0, &fingerprint);
  measure_timer(qf_insert);

  start_timer(db_insert);
  db_insert(arqf->rhm, &fingerprint, sizeof(fingerprint), &key, sizeof(key), 1, 0);
  measure_timer(db_insert);

  arqf->qf->metadata->qf_insert_duration += t_duration_qf_insert;
  arqf->qf->metadata->db_insert_duration += t_duration_db_insert;

  return 0;
}

template <typename value_type>
inline bool query_qf(ARQF *qf, const value_type left, const value_type right)
{
    int result;
    if (left == right) {
      result = qf_point_query(qf->qf, left, QF_NO_LOCK);
    } else {
      result = qf_range_query(qf->qf, left, right, QF_NO_LOCK);
    }
    return result;
}

inline size_t size_qf(ARQF *qf)
{
  return qf_get_total_size_in_bytes(qf->qf);
}

int main(int argc, char const *argv[])
{
    auto parser = init_parser("bench-rqf-adaptive-wiredtiger");

    try
    {
        parser.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << parser;
        std::exit(1);
    }
    auto [ keys, queries, arg ] = read_parser_arguments(parser);
    auto test_type = parser.get<std::string>("--test-type");

    if (test_type == "fpr") {
      experiment_fpr(
          pass_fun(init_qf), 
          pass_ref(query_qf), 
          pass_ref(adapt_qf),
          pass_ref(size_qf), 
          pass_ref(add_metadata), 
          arg, keys, queries, queries);
    } else if (test_type == "adversarial") {
      std::string db_home = parser.get<std::string>("keys");
      db_home += "_wtdb";
      experiment_adversarial_workload(
          pass_fun(init_qf), 
          pass_ref(query_qf), 
          pass_ref(adapt_qf),
          pass_ref(size_qf), 
          pass_ref(add_metadata), 
          arg, db_home, keys, queries, queries);
    } else if (test_type == "mixed") {
      std::string wt_home = "mixed_workload_wt";
      if (std::filesystem::exists(wt_home))
        std::filesystem::remove_all(wt_home);
      std::filesystem::create_directory(wt_home);
      experiment_mixed_workload(
          pass_fun(init_qf), 
          pass_ref(insert_arqf), 
          pass_ref(query_qf), 
          pass_ref(adapt_qf),
          pass_ref(size_qf), 
          pass_ref(add_metadata), 
          arg,
          wt_home,
          keys,
          queries,
          queries);
    } else {
      std::cerr<<"Specify which type of test to run with --test_type"<<std::endl;
      abort();
    }
    print_test();
    return 0;
}
