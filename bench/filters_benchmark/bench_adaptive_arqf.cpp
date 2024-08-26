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

#include "splinter_util.h"
#include "../bench_template.hpp"
#include "arqf.h"
#include "gqf.h"
#include "gqf_int.h"

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



static inline uint64_t memento_hash(uint64_t x, uint64_t n_slots, uint64_t quotient_bits, uint64_t remainder_bits, uint64_t memento_bits, uint64_t seed)
{
  const uint64_t quotient_mask = (1ULL << quotient_bits) - 1;
  const uint64_t memento_mask =  (1ULL << memento_bits) - 1;
  const uint64_t hash_mask = (1ULL << (quotient_bits + remainder_bits)) - 1;
  auto y = x >> memento_bits;
  uint64_t hash = MurmurHash64A(((void*)&y), sizeof(y), seed) & hash_mask;
  const uint64_t address = fast_reduce((hash & quotient_mask) << (32 - quotient_bits),
      n_slots);
  hash = (hash >> quotient_bits) | (address << remainder_bits);
  return (hash << memento_bits) | (x & memento_mask);
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

    data_config *data_cfg;
    splinterdb_config *splinterdb_cfg;
    splinterdb* db;
    qf_init_splinterdb(&db, &data_cfg, &splinterdb_cfg, "test_db3");
    ARQF *arqf = (ARQF *) malloc(sizeof(ARQF));
    arqf_init_with_rhm(arqf, db, n_slots, key_size, memento_bits, seed);
    // qf_set_auto_resize(qf, true);

    start_timer(build_time);

    auto key_hashes = std::vector<uint64_t>(n_items);
    std::transform(begin, end, key_hashes.begin(), [&](auto x) {
      uint64_t hash = arqf_hash(arqf->qf, x);
      uint64_t mask  = 1ULL << (arqf->qf->metadata->quotient_bits + arqf->qf->metadata->bits_per_slot);
      return hash & (mask - 1);
    });
    auto keys = std::vector<uint64_t>(n_items);
    std::transform(begin, end, keys.begin(), [&](auto x) {
        return x;
    });

    /*
     * The following code uses the Boost library to sort the elements in a single thread, via spreadsort function.
     * This function is faster than std::sort and exploits the fact that the size of the maximum hash is bounded
     * via hybrid radix sort.
     */
    boost::sort::spreadsort::spreadsort(key_hashes.begin(), key_hashes.end());
    int retcode = arqf_bulk_load(arqf, &key_hashes[0], &keys[0], key_hashes.size(), 0);
    if (retcode < 0) {
      std::cerr << "Failed to initialize iterator" << std::endl;
      abort();
    }
    stop_timer(build_time);
    // check_iteration_validity(arqf->qf, &key_hashes[0], key_hashes.size());
    return arqf;
}

template <typename value_type>
inline bool query_arqf(ARQF *arqf, const value_type left, const value_type right)
{
    QF *qf = arqf->qf;
    uint64_t l_hash = memento_hash(left, qf->metadata->nslots, qf->metadata->quotient_bits, qf->metadata->key_remainder_bits, qf->metadata->value_bits, qf->metadata->seed);
    uint64_t r_hash = memento_hash(right, qf->metadata->nslots, qf->metadata->quotient_bits, qf->metadata->key_remainder_bits, qf->metadata->value_bits, qf->metadata->seed);

    int result;
    if (left == right) {
      result = qf_point_query(arqf->qf, l_hash, QF_KEY_IS_HASH | QF_NO_LOCK);
    } else {
      result = qf_range_query(arqf->qf, l_hash, r_hash, QF_KEY_IS_HASH | QF_NO_LOCK);
    }
    return result;
}

template <typename value_type>
inline void adapt_arqf(ARQF *arqf, const value_type left, const value_type right)
{
  std::cout<<"Adapting"<<std::endl;
}

inline size_t size_arqf(ARQF *f)
{
  return qf_get_total_size_in_bytes(f->qf);
}

int main(int argc, char const *argv[])
{
    auto parser = init_parser("bench-adaptivity");

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

    experiment(pass_fun(init_arqf), pass_ref(query_arqf), 
                pass_ref(size_arqf), arg, keys, queries, queries);

    print_test();

    return 0;
}
