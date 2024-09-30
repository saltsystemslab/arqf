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
#include <boost/sort/sort.hpp>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <iterator>

#include "../bench_template.hpp"
#include "gqf.h"
#include "gqf_int.h"

/**
 * This file contains the benchmark for Memento filter.
 */

inline uint64_t MurmurHash64A(const void* key, int len, unsigned int seed)
{
  const uint64_t m = 0xc6a4a7935bd1e995;
  const int r = 47;

  uint64_t h = seed ^ (len * m);

  const uint64_t* data = (const uint64_t*)key;
  const uint64_t* end = data + (len / 8);

  while (data != end) {
    uint64_t k = *data++;

    k *= m;
    k ^= k >> r;
    k *= m;

    h ^= k;
    h *= m;
  }

  const unsigned char* data2 = (const unsigned char*)data;

  switch (len & 7) {
  case 7:
    h ^= (uint64_t)data2[6] << 48;
    do {
    } while (0); /* fallthrough */
  case 6:
    h ^= (uint64_t)data2[5] << 40;
    do {
    } while (0); /* fallthrough */
  case 5:
    h ^= (uint64_t)data2[4] << 32;
    do {
    } while (0); /* fallthrough */
  case 4:
    h ^= (uint64_t)data2[3] << 24;
    do {
    } while (0); /* fallthrough */
  case 3:
    h ^= (uint64_t)data2[2] << 16;
    do {
    } while (0); /* fallthrough */
  case 2:
    h ^= (uint64_t)data2[1] << 8;
    do {
    } while (0); /* fallthrough */
  case 1:
    h ^= (uint64_t)data2[0];
    h *= m;
  };

  h ^= h >> r;
  h *= m;
  h ^= h >> r;

  return h;
}

__attribute__((always_inline)) static inline uint32_t fast_reduce(uint32_t hash, uint32_t n)
{
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}

inline void check_iteration_validity(QF* qf, uint64_t* hashes, uint64_t nkeys)
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
  for (uint64_t i = 0; i < nkeys; i++) {
    if (qf_point_query(qf, hashes[i], QF_KEY_IS_HASH | QF_NO_LOCK) == 0) {
      printf("Point query %lu failed!\n", i);
      abort();
    }
  }

  for (uint64_t i = 1; i < nkeys; i++) {
    uint64_t k = (hashes[i] + hashes[i - 1]) >> 1;
    if (k == hashes[i] || k == hashes[i - 1])
      continue;
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

static inline uint64_t memento_hash(uint64_t x, uint64_t n_slots, uint64_t quotient_bits, uint64_t remainder_bits, uint64_t memento_bits, uint64_t seed)
{
  const uint64_t quotient_mask = (1ULL << quotient_bits) - 1;
  const uint64_t memento_mask = (1ULL << memento_bits) - 1;
  const uint64_t hash_mask = (1ULL << (quotient_bits + remainder_bits)) - 1;
  auto y = x >> memento_bits;
  uint64_t hash = MurmurHash64A(((void*)&y), sizeof(y), seed) & hash_mask;
  const uint64_t address = fast_reduce((hash & quotient_mask) << (32 - quotient_bits),
      n_slots);
  hash = (hash >> quotient_bits) | (address << remainder_bits);
  return (hash << memento_bits) | (x & memento_mask);
}

template <typename t_itr, typename... Args>
inline QF* init_qf(const t_itr begin, const t_itr end, bool load_keys, const double bpk, Args... args)
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
  std::cerr << "key_size=" << key_size << " fingerprint_size=" << fingerprint_size << " memento_bits=" << memento_bits << std::endl;

  QF* qf = (QF*)malloc(sizeof(QF));
  qf_malloc(qf, n_slots, key_size, memento_bits, QF_HASH_DEFAULT, seed);
  // qf_set_auto_resize(qf, true);

  if (!load_keys) return qf;

  start_timer(build_time);

  auto key_hashes = std::vector<uint64_t>(n_items);
  std::transform(begin, end, key_hashes.begin(), [&](auto x) {
    uint64_t hash = arqf_hash(qf, x);
    uint64_t memento_mask  = (1ULL << (qf->metadata->value_bits)) - 1;
    hash = (hash << qf->metadata->value_bits) | (x & memento_mask);
    uint64_t hash_mask  = (1ULL << (qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) - 1;
    return hash & (hash_mask);
  });

#if ARQF_BULK_LOAD
  /*
     * The following code uses the Boost library to sort the elements in a single thread, via spreadsort function.
     * This function is faster than std::sort and exploits the fact that the size of the maximum hash is bounded
     * via hybrid radix sort.
     */
  uint64_t nkeys = key_hashes.size();
  boost::sort::spreadsort::spreadsort(key_hashes.begin(), key_hashes.end());
  int retcode = qf_bulk_load(qf, &key_hashes[0], key_hashes.size());
  if (retcode < 0) {
    std::cerr << "Failed to initialize iterator" << std::endl;
    abort();
  }
#else
  for (int i = 0; i < nkeys; i++) {
    qf_insert_memento(qf, key_hashes[i], QF_KEY_IS_HASH);
  }
#endif
  stop_timer(build_time);
  boost::sort::spreadsort::spreadsort(key_hashes.begin(), key_hashes.end());
  check_iteration_validity(qf, &key_hashes[0], nkeys);
  return qf;
}

template <typename value_type>
inline bool insert_qf(QF* qf, const value_type value)
{
  uint64_t fingerprint;
  return qf_insert_memento(qf, value, 0, &fingerprint);
}

template <typename value_type>
inline bool adapt_qf(QF* qf, const value_type left, const value_type right)
{
  return false;
}

inline void add_metadata(QF* f)
{
  test_out.add_measure("q_bits", f->metadata->quotient_bits);
  test_out.add_measure("r_bits", f->metadata->key_remainder_bits);
  test_out.add_measure("m_bits", f->metadata->value_bits);
  test_out.add_measure("n_slots", f->metadata->xnslots);
  test_out.add_measure("noccupied_slots", f->metadata->noccupied_slots);
  test_out.add_measure("n_successful_adapts", f->metadata->n_successful_adapts);
  test_out.add_measure("n_failed_adapt_no_space", f->metadata->n_failed_adapt_no_space);
  test_out.add_measure("n_failed_adapt_no_bits", f->metadata->n_failed_adapt_no_bits);
}

template <typename value_type>
inline bool query_qf(QF* qf, const value_type left, const value_type right)
{
  int result;
  if (left == right) {
    result = qf_point_query(qf, left, QF_NO_LOCK);
  } else {
    result = qf_range_query(qf, left, right, QF_NO_LOCK);
  }
  return result;
}

inline size_t size_qf(QF* f)
{
  return qf_get_total_size_in_bytes(f);
}

int main(int argc, char const* argv[])
{
  auto parser = init_parser("bench-qf");

  try {
    parser.parse_args(argc, argv);
  } catch (const std::runtime_error& err) {
    std::cerr << err.what() << std::endl;
    std::cerr << parser;
    std::exit(1);
  }
  auto [keys, queries, arg] = read_parser_arguments(parser);
  std::cout << keys.size() << " " << queries.size() << std::endl;
  auto test_type = parser.get<std::string>("--test-type");

  if (test_type == "adaptivity_inmem") {
    auto [keys, queries, arg] = read_parser_arguments(parser);
    experiment_adaptivity(
        pass_fun(init_qf),
        pass_ref(query_qf),
        pass_ref(adapt_qf),
        pass_ref(size_qf),
        pass_ref(add_metadata),
        arg, keys, queries, queries);
  } else if (test_type == "adaptivity_disk") {
    std::string db_home = parser.get<std::string>("keys");
    db_home += "_wtdb";
    auto [keys, queries, arg] = read_parser_arguments(parser);
    experiment_adaptivity_disk(
        pass_fun(init_qf),
        pass_ref(query_qf),
        pass_ref(adapt_qf),
        pass_ref(size_qf),
        pass_ref(add_metadata),
        arg, db_home, keys, queries, queries);
  } else if (test_type == "adaptivity_mixed") {
    std::string wt_home = "mixed_workload_wt";
    if (std::filesystem::exists(wt_home))
        std::filesystem::remove_all(wt_home);
    std::filesystem::create_directory(wt_home);
    experiment_adaptivity_mixed(
        pass_fun(init_qf),
        pass_ref(insert_qf),
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
    std::cerr << "Specify which type of test to run with --test_type" << std::endl;
    abort();
  }
  print_test();
  return 0;
}
