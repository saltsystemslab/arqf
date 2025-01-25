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

#pragma once

#include <chrono>
#include <cstdint>
#include <iostream>
#include <argparse/argparse.hpp>
#include <vector>
#include "bench_utils.hpp"
#include "splinterdb/platform_linux/public_platform.h"

static uint64_t optimizer_hack = 0;
const int default_key_len = 8, default_val_len = 504;
uint64_t key_len, val_len;
uint64_t default_buffer_pool_size_mb = 64;
uint64_t buffer_pool_size_mb = 0;
float adversarial_rate = 0.1;
bool just_expanded = false;
bool requires_full_db_scan = false;
uint64_t expansion = 0;

static inline void fetch_range_from_db(WT_CURSOR *cursor, SimpleBigInt &l, SimpleBigInt &r)
{
    error_check(cursor->reset(cursor));
    cursor->set_key(cursor, (char *) l.num);
    error_check(cursor->bound(cursor, "action=set,bound=lower,inclusive=true"));
    cursor->set_key(cursor, (char *) r.num);
    error_check(cursor->bound(cursor, "action=set,bound=upper,inclusive=true"));

    uint32_t x = 1;
    while ((cursor->next(cursor)) == 0) {
        x ^= 1;
    }
    optimizer_hack += x;
}

static inline std::vector<uint64_t> get_dataset_from_db(WT_CURSOR *cursor)
{
    error_check(cursor->reset(cursor));
    std::vector<uint64_t> res;
    while ((cursor->next(cursor)) == 0) {
        const char *key;
        error_check(cursor->get_key(cursor, &key));
        res.push_back(*reinterpret_cast<const uint64_t *>(key));
    }
    std::cerr << "[+] reconstruction set size: " << res.size() << std::endl;
    return res;
}

static inline InputKeys<uint64_t> fetch_dataset_from_db(WT_CURSOR *cursor)
{
    uint8_t key_buf[sizeof(uint64_t) + 1];
    InputKeys<uint64_t> res;
    error_check(cursor->reset(cursor));
    while ((cursor->next(cursor)) == 0) {
        error_check(cursor->get_key(cursor, key_buf));
        res.push_back(*reinterpret_cast<uint64_t *>(key_buf));
    }
    return res;
}

static inline void fetch_successor_range_from_db(WT_CURSOR *cursor, SimpleBigInt &l)
{
    error_check(cursor->reset(cursor));
    cursor->set_key(cursor, (char *) l.num);
    error_check(cursor->bound(cursor, "action=set,bound=lower,inclusive=true"));

    uint64_t count = 10;
    uint32_t x = 1;
    while ((cursor->next(cursor)) == 0 && count > 0) {
        x ^= 1;
        count--;
    }
    optimizer_hack += x;
}


inline std::set<uint64_t> *init_inmem_db(double db_cache_size) {
  std::set<uint64_t> *s = new std::set<uint64_t>();
  return s;
}
template <typename value_type>
inline void insert_inmem_db(std::set<uint64_t> *s, const value_type key)
{
  s->insert(key);
}
template <typename value_type>
inline bool query_inmem_db(std::set<uint64_t> *s, const value_type left, const value_type right)
{
  auto it = s->lower_bound(left);
  if (it == s->end() || *it > right) {
    return false;
  }
  return true;
}

/**
 * This file contains a template class for running and measuring benchmarks of range filters.
 */
#define pass_fun(f) ([](auto... args){ return f(args...); })
#define pass_ref(fun) ([](auto& f, auto... args){ return fun(f, args...); })

auto t_start_expansion_time = timer::now();
auto t_end_expansion_time = timer::now();
auto t_duration_expansion_time = 0ULL;

auto t_start_wt_scan_time = timer::now();
auto t_end_wt_scan_time = timer::now();
auto t_duration_wt_scan_time = 0ULL;

#define start_timer(t) \
    auto t_start_##t = timer::now(); \

#define stop_timer(t) \
    auto t_end_##t = timer::now(); \
    test_out.add_measure(#t, std::chrono::duration_cast<std::chrono::nanoseconds>(t_end_##t - t_start_##t).count());

#define measure_timer(t) \
    auto t_end_##t = timer::now(); \
    auto t_duration_##t = std::chrono::duration_cast<std::chrono::nanoseconds>(t_end_##t - t_start_##t).count();

auto query_shuffle_s = 1380;
#define query_shuffle_seed query_shuffle_s++

auto test_out = TestOutput();

auto test_verbose = true;
bool print_csv = false;
bool print_json = false;
std::string csv_file = "";
std::string json_file = "";

template <typename InitFun, typename RangeFun, typename SizeFun, typename key_type, typename... Args>
void experiment(InitFun init_f, RangeFun range_f, SizeFun size_f, const double param, InputKeys<key_type> &keys, Workload<key_type> &queries, Args... args)
{
    auto f = init_f(keys.begin(), keys.end(), param, args...);

    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ns, starting queries" << std::endl;
    auto fp = 0, fn = 0;
    start_timer(query_time);
    for (auto q : queries)
    {
        const auto [left, right, original_result] = q;

        bool query_result = range_f(f, left, right);
        if (query_result && !original_result) {
            fp++;
        }
        else if (!query_result && original_result)
        {
            std::cerr << "[!] alert, found false negative!" << std::endl;
            fn++;
        }
    }
    stop_timer(query_time);

    auto size = size_f(f);
    test_out.add_measure("size", size);
    test_out.add_measure("bpk", TO_BPK(size, keys.size()));
    test_out.add_measure("fpr", ((double)fp / queries.size()));
    test_out.add_measure("false_neg", fn);
    test_out.add_measure("n_keys", keys.size());
    test_out.add_measure("n_queries", queries.size());
    test_out.add_measure("false_positives", fp);
    metadata_f(f, test_out);
    std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
}

template <typename InitFun, typename RangeFun, typename AdaptFun, typename SizeFun, typename MetadataFun, typename key_type, typename... Args>
void experiment_adaptivity(
    InitFun init_f, 
    RangeFun range_f, 
    AdaptFun adapt_f, 
    SizeFun size_f, 
    MetadataFun metadata_f, 
    const double param, 
    InputKeys<key_type> &keys, 
    Workload<key_type> &queries, 
    Args... args)
{
    auto f = init_f(keys.begin(), keys.end(), param, args...);

    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ns, starting queries" << std::endl;
    auto fp = 0, fn = 0, fa = 0;
    std::map<uint64_t, uint64_t> fp_count;
    start_timer(query_time);
    for (auto q : queries)
    {
        const auto [left, right, original_result] = q;

        bool query_result = range_f(f, left, right);
        if (query_result && !original_result) {
            if (!adapt_f(f, left, right)) {
              fa++;
            }
#if DEBUG
            else {
              query_result = range_f(f, left, right);
              if (query_result) {
                std::cerr << "[!] alert, adapting " <<left<<" "<<right<<" failed!" << std::endl;
              }
            }
#endif
            fp_count[left]++;
            fp++;
        }
        else if (!query_result && original_result)
        {
            std::cerr << "[!] alert, found false negative!" << std::endl;
            fn++;
        }
    }
    stop_timer(query_time);

    auto size = size_f(f);
    test_out.add_measure("size", size);
    test_out.add_measure("bpk", TO_BPK(size, keys.size()));
    test_out.add_measure("fpr", ((double)fp / queries.size()));
    test_out.add_measure("false_neg", fn);
    test_out.add_measure("n_keys", keys.size());
    test_out.add_measure("n_queries", queries.size());
    test_out.add_measure("false_positives", fp);
    test_out.add_measure("num_fp_keys", fp_count.size());
    metadata_f(f);
    std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
}

const uint32_t expansion_count = 8;

template <typename InitFun, typename InsertFun, typename RangeFun, typename AdaptFun, typename ShouldReconstructFun, typename SizeFun, typename FreeFun, typename MetadataFun, typename key_type, typename... Args>
void experiment_expandability(
    InitFun init_f, 
    InsertFun insert_f, 
    RangeFun range_f, 
    AdaptFun adapt_f, 
    ShouldReconstructFun should_reconstruct_f, 
    SizeFun size_f, 
    FreeFun free_f, 
    MetadataFun metadata_f, 
    const double param, 
    InputKeys<key_type> &keys, 
    Workload<key_type> &queries, 
    Args... args)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distr(1, (1ULL<<63)-1);

    // Begin loading DB.
    std::set<uint64_t> db;
    const uint64_t N = keys.size();
    const uint64_t n_queries = queries.size() / (expansion_count + 1);
    std::cout << "[+] n_queries=" << n_queries << std::endl;
    for (uint32_t i = 0; i < N >> expansion_count; i++) {
        db.insert(keys[i]);
    }

    auto f = init_f(keys.begin(), keys.begin() + (N >> expansion_count), param, args...);
    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;

    for (uint32_t i = N >> expansion_count; i < N; i++) {
        db.insert(keys[i]);
        insert_f(f, keys[i]);

        if (just_expanded && !should_reconstruct_f(f)) {
            requires_full_db_scan = false;
            // Memento Resized, but doesn't need to scan the DB yet.
        }
        if (should_reconstruct_f(f)) {
            requires_full_db_scan = true;
            std::cerr << "cannot expand, reconstructing instead" << std::endl;
            t_start_expansion_time = timer::now();
            free_f(f);
            f = init_f(db.begin(), db.end(), param, args...);
            t_end_expansion_time = timer::now();
            t_duration_expansion_time += std::chrono::duration_cast<std::chrono::nanoseconds>(t_end_expansion_time - t_start_expansion_time).count();
            std::cerr << "DONE WITH RECONSTRUCTION PROCESS --- current_dataset_size=" << i << " vs. N=" << N << " (expansion=" << expansion << ")" << std::endl;
            just_expanded = false;
        }

        if (just_expanded) {
            just_expanded = false;
            expansion++;
            std::cerr << "==== EXPANSION " << expansion <<" ======== "<<std::endl;
            std::string expansion_str = std::to_string(expansion);
            auto size = size_f(f);
            test_out.add_measure(std::string("expansion_trigger_key_") + expansion_str, i);
            test_out.add_measure(std::string("expansion_time_") + expansion_str, t_duration_expansion_time);
            test_out.add_measure(std::string("filter_size_") + expansion_str, size);
            test_out.add_measure(std::string("bpk_") + expansion_str, TO_BPK(size, i));
            test_out.add_measure(std::string("did_full_db_scan_") + expansion_str, std::to_string(requires_full_db_scan));
            test_out.add_measure(std::string("wt_scan_time_") + expansion_str, t_duration_wt_scan_time);
            metadata_f(f);
            test_out.print();

            t_duration_expansion_time = 0;
            t_duration_wt_scan_time = 0;

            start_timer(query_time);
            uint64_t fp = 0;
            uint64_t adapt_duration_ns = 0;
            uint64_t true_queries = 0;
            // for (uint64_t i = 0; i < queries.size(); i++) {
            for (uint64_t i = (expansion-1) * (queries.size()/8); i < (expansion * queries.size()/8); i++) {
                auto q = queries[i];
                const auto [l, r, orig] = q;
                uint64_t left = l;
                uint64_t right = r;
                bool original_result = orig;
                bool query_result = range_f(f, left, right);
                if (query_result) {
                    fp++;
                    if (db.lower_bound(left) != db.upper_bound(right)) {
                        true_queries++;
                    }
                    start_timer(adapt_qf);
                    adapt_f(f, left, right);
                    measure_timer(adapt_qf);
                    adapt_duration_ns += t_duration_adapt_qf;
                }
            }
            measure_timer(query_time);
            test_out.add_measure(std::string("query_time_") + expansion_str, t_duration_query_time);
            test_out.add_measure(std::string("false_positives_") + expansion_str, fp);
            test_out.add_measure(std::string("true_queries") + expansion_str, true_queries);
            // test_out.add_measure(std::string("n_queries_") + expansion_str, n_queries);
            // test_out.add_measure(std::string("fpr_") + expansion_str, static_cast<double>(fp) / queries.size());
            test_out.add_measure(std::string("n_queries_") + expansion_str, queries.size()/8);
            test_out.add_measure(std::string("fpr_") + expansion_str, static_cast<double>(fp) / (queries.size()/8));
            test_out.add_measure(std::string("adapt_duration_ns_") + expansion_str, adapt_duration_ns);
        }
    }

    metadata_f(f);
    std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
    std::cout << "[+] Optimizer hack" << optimizer_hack << std::endl;
}

int
print_cursor(WT_CURSOR *cursor)
{
        const char *desc, *pvalue;
        uint64_t value;
        int ret;
        while ((ret = cursor->next(cursor)) == 0 &&
            (ret = cursor->get_value(cursor, &desc, &pvalue, &value)) == 0)
                if (value != 0)
                        printf("%s=%s\n", desc, pvalue);
        return (ret == WT_NOTFOUND ? 0 : ret);
}
int 
print_database_stats(WT_SESSION *session)
{
        WT_CURSOR *cursor;
        int ret;
        if ((ret = session->open_cursor(session,
            "statistics:", NULL, NULL, &cursor)) != 0)
                return (ret);
        ret = print_cursor(cursor);
        ret = cursor->close(cursor);
        return (ret);
}


template <typename InitFun, typename RangeFun, typename AdaptFun, typename SizeFun, typename MetadataFun, typename key_type, typename... Args>
void experiment_adaptivity_disk(
    InitFun init_f, 
    RangeFun range_f, 
    AdaptFun adapt_f, 
    SizeFun size_f, 
    MetadataFun metadata_f, 
    const double param, 
    std::string wt_home,
    InputKeys<key_type> &keys, 
    Workload<key_type> &queries, 
    Args... args)
{
   	std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distr(1, (1ULL<<63)-1);

  // Begin loading DB.
    const uint32_t max_schema_len = 128;
    const uint32_t max_conn_config_len = 128;

    WT_CONNECTION *conn;
    WT_SESSION *session;
    WT_CURSOR *cursor;
    char table_schema[max_schema_len];
    char connection_config[max_conn_config_len];
    sprintf(table_schema, "key_format=%lds,value_format=%lds", key_len, val_len);
    sprintf(connection_config, "statistics=(all),direct_io=[data],cache_size=%ldMB", buffer_pool_size_mb);

    error_check(wiredtiger_open(wt_home.c_str(), NULL, connection_config, &conn));
    error_check(conn->open_session(conn, NULL, NULL, &session));
    error_check(session->create(session, "table:bm", table_schema));
    error_check(session->open_cursor(session, "table:bm", NULL, NULL, &cursor));

    SimpleBigInt big_int_k(key_len), big_int_v(val_len);
    SimpleBigInt big_int_l(key_len), big_int_r(key_len);
    
    std::cerr << "[+] WiredTiger loaded DB loaded. with config: " << std::string(connection_config) << std::endl;

    auto f = init_f(keys.begin(), keys.end(), param, args...);

    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;
    auto fp = 0, fn = 0, fa = 0;
    uint64_t num_db_fetches = 0;
    uint64_t num_adapts = 0;
    uint64_t fetch_from_db_duration_ns = 0;
    uint64_t adapt_duration_ns = 0;
    uint64_t query_index = 0;
    uint64_t overall_query_duration = 0;

    start_timer(warmup_time);
    std::vector<std::pair<uint64_t, uint64_t> > adversaries;
    std::vector<bool> adversary_result;
    uint64_t num_warmup_queries = queries.size() / 2;
    for (uint64_t i=0; i < num_warmup_queries; i++) {
      auto q = queries[i];
      const auto [left, right, original_result] = q;
      bool query_result = range_f(f, left, right);
      if (query_result) {
        big_int_l = left;
        big_int_r = right;

        start_timer(db_fetch);
        num_db_fetches++;
        fetch_range_from_db(cursor, big_int_l, big_int_r);
        measure_timer(db_fetch);
        fetch_from_db_duration_ns += t_duration_db_fetch;

        fp += !original_result;
        if (!original_result) {
          start_timer(adapt_qf);
          if (!adapt_f(f, left, right)) {
            fa++;
          }
          measure_timer(adapt_qf);
          adapt_duration_ns += t_duration_adapt_qf;
          adversaries.push_back(std::pair<uint64_t, uint64_t>(left, right));
          adversary_result.push_back(original_result);
        }
      } else if (!query_result && original_result) {
        std::cerr << "[!] alert, found false negative!" << std::endl;
        fn++;
      }
    }
    stop_timer(warmup_time);
    uint64_t num_adversarial_queries = 0;
    test_out.add_measure("adversary_set_size", adversaries.size());
    std::cout << "Finished warmup, collected "<< adversaries.size() << std::endl;

    uint64_t adversary_freq = queries.size();
    if (adversarial_rate != 0) {
      adversary_freq = 1.0 / adversarial_rate; 
    }
    uint64_t adversary_idx = 0;

    start_timer(query_time);
    for (uint64_t i=num_warmup_queries; i < queries.size(); i++) {
      auto q = queries[i];
      const auto [l, r, orig] = q;
      uint64_t left = l;
      uint64_t right = r;
      bool original_result = orig;

      if (i % adversary_freq == 0) {
        num_adversarial_queries++;
        left = adversaries[adversary_idx].first;
        right = adversaries[adversary_idx].second;
        original_result = adversary_result[adversary_idx]; 
        adversary_idx++;
        if (adversary_idx == adversaries.size())
          adversary_idx = 0;
      }

      bool query_result = range_f(f, left, right);
      if (query_result) {
        big_int_l = left;
        big_int_r = right;

        start_timer(db_fetch);
        num_db_fetches++;
        fetch_range_from_db(cursor, big_int_l, big_int_r);
        measure_timer(db_fetch);
        fetch_from_db_duration_ns += t_duration_db_fetch;

        fp += !original_result;
        if (!original_result) {
          start_timer(adapt_qf);
          if (!adapt_f(f, left, right)) {
            fa++;
          }
          measure_timer(adapt_qf);
          adapt_duration_ns += t_duration_adapt_qf;
          adversaries.push_back(std::pair<uint64_t, uint64_t>(left, right));
          adversary_result.push_back(original_result);
        }
      } else if (!query_result && original_result) {
        std::cerr << "[!] alert, found false negative!" << std::endl;
        fn++;
      }
      
    }
    stop_timer(query_time);

    auto size = size_f(f);
    test_out.add_measure("size", size);
    test_out.add_measure("bpk", TO_BPK(size, keys.size()));
    test_out.add_measure("fpr", ((double)fp / queries.size()));
    test_out.add_measure("false_neg", fn);
    test_out.add_measure("n_keys", keys.size());
    test_out.add_measure("n_queries", queries.size());
    test_out.add_measure("false_positives", fp);
    test_out.add_measure("num_db_fetch", num_db_fetches);
    test_out.add_measure("db_fetch_duration_ns", fetch_from_db_duration_ns);
    test_out.add_measure("adapt_duration_ns", adapt_duration_ns);
    test_out.add_measure("adversarial_rate", adversarial_rate);
    test_out.add_measure("num_adversarial_queries", num_adversarial_queries);
    metadata_f(f);
    std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
    std::cout << "[+] Optimizer hack" << optimizer_hack << std::endl;
}


template <typename InitFun, typename InsertFun, typename RangeFun, typename AdaptFun, typename ShouldReconstructFun, typename SizeFun, typename FreeFun, typename MetadataFun, typename key_type, typename... Args>
void experiment_expandability_disk(
    InitFun init_f, 
    InsertFun insert_f, 
    RangeFun range_f, 
    AdaptFun adapt_f, 
    ShouldReconstructFun should_reconstruct_f, 
    SizeFun size_f, 
    FreeFun free_f, 
    MetadataFun metadata_f, 
    const double param, 
    std::string wt_home,
    InputKeys<key_type> &keys, 
    Workload<key_type> &queries, 
    Args... args)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distr(1, (1ULL<<63)-1);

    // Begin loading DB.
    const uint32_t max_schema_len = 128;
    const uint32_t max_conn_config_len = 128;

    WT_CONNECTION *conn;
    WT_SESSION *session;
    WT_CURSOR *cursor;
    char table_schema[max_schema_len];
    char connection_config[max_conn_config_len];
    uint64_t current_buffer_pool_size_mb = std::max(((buffer_pool_size_mb << (20 - expansion_count + expansion))) >> 20, 2UL);
    sprintf(table_schema, "key_format=%lds,value_format=%lds", key_len, val_len);
    sprintf(connection_config, "create,statistics=(all),direct_io=[data],cache_size=%ldMB", current_buffer_pool_size_mb);

    if (std::filesystem::exists(wt_home))
        std::filesystem::remove_all(wt_home);
    std::filesystem::create_directory(wt_home);

    error_check(wiredtiger_open(wt_home.c_str(), NULL, connection_config, &conn));
    error_check(conn->open_session(conn, NULL, NULL, &session));
    error_check(session->create(session, "table:access", table_schema));
    error_check(session->open_cursor(session, "table:access", NULL, NULL, &cursor));
    std::cerr << "[+] WiredTiger loaded DB loaded. with config: " << std::string(connection_config) << std::endl;

    SimpleBigInt big_int_k(key_len), big_int_v(val_len);
    SimpleBigInt big_int_l(key_len), big_int_r(key_len);
    const uint64_t N = keys.size();
    const uint64_t n_queries = queries.size() / (expansion_count + 1);
    std::cout << "[+] n_queries=" << n_queries << std::endl;
    error_check(cursor->reset(cursor));
    for (uint32_t i = 0; i < N >> expansion_count; i++) {
        SimpleBigInt big_int_k(key_len), big_int_v(val_len);
        big_int_k = keys[i];
        big_int_v.randomize();
        insert_kv(cursor, reinterpret_cast<char *>(big_int_k.num), reinterpret_cast<char *>(big_int_v.num));
    }

    auto f = init_f(keys.begin(), keys.begin() + (N >> expansion_count), param, args...);
    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;

    for (uint32_t i = N >> expansion_count; i < N; i++) {
        SimpleBigInt big_int_k(key_len), big_int_v(val_len);
        big_int_k = keys[i];
        big_int_v.randomize();
        insert_kv(cursor, reinterpret_cast<char *>(big_int_k.num), reinterpret_cast<char *>(big_int_v.num));
        insert_f(f, keys[i]);

        if (just_expanded && !should_reconstruct_f(f)) {
            requires_full_db_scan = false;
            // Memento Resized, but doesn't need to scan the DB yet.
        }
        if (should_reconstruct_f(f)) {
            requires_full_db_scan = true;
            std::cerr << "cannot expand, reconstructing instead" << std::endl;
            t_start_expansion_time = timer::now();
            t_start_wt_scan_time = timer::now();
            auto reconstruction_keys = get_dataset_from_db(cursor);
            t_end_wt_scan_time = timer::now();
            t_duration_wt_scan_time += std::chrono::duration_cast<std::chrono::nanoseconds>(t_end_wt_scan_time - t_start_wt_scan_time).count();
            free_f(f);
            f = init_f(reconstruction_keys.begin(), reconstruction_keys.end(), param, args...);
            t_end_expansion_time = timer::now();
            t_duration_expansion_time += std::chrono::duration_cast<std::chrono::nanoseconds>(t_end_expansion_time - t_start_expansion_time).count();
            std::cerr << "DONE WITH RECONSTRUCTION PROCESS --- current_dataset_size=" << i << " vs. N=" << N << " (expansion=" << expansion << ")" << std::endl;
            just_expanded = false;
        }

        if (just_expanded) {
            just_expanded = false;
            expansion++;
            std::cerr << "==== EXPANSION " << expansion <<" ======== "<<std::endl;
            std::string expansion_str = std::to_string(expansion);
            auto size = size_f(f);
            test_out.add_measure(std::string("expansion_trigger_key_") + expansion_str, i);
            test_out.add_measure(std::string("expansion_time_") + expansion_str, t_duration_expansion_time);
            test_out.add_measure(std::string("wt_buffer_pool_size_mb_round_") + expansion_str, current_buffer_pool_size_mb);
            test_out.add_measure(std::string("filter_size_") + expansion_str, size);
            test_out.add_measure(std::string("bpk_") + expansion_str, TO_BPK(size, i));
            test_out.add_measure(std::string("did_full_db_scan_") + expansion_str, std::to_string(requires_full_db_scan));
            test_out.add_measure(std::string("wt_scan_time_") + expansion_str, t_duration_wt_scan_time);
            metadata_f(f);
            test_out.print();

            error_check(conn->close(conn, NULL)); /* Close all handles. */
            current_buffer_pool_size_mb = std::max(((buffer_pool_size_mb << (20 - expansion_count + expansion)) - size_f(f)) >> 20, 2UL);
            std::cout << "WELP first_part=" << (buffer_pool_size_mb << (20 - expansion_count + expansion)) << " size_f=" << size_f(f) << " vs. current_buffer_pool_size_mb=" << current_buffer_pool_size_mb << std::endl;
            sprintf(connection_config, "statistics=(all),direct_io=[data],cache_size=%ldMB", current_buffer_pool_size_mb);
            error_check(wiredtiger_open(wt_home.c_str(), NULL, connection_config, &conn));
            error_check(conn->open_session(conn, NULL, NULL, &session));
            error_check(session->open_cursor(session, "table:access", NULL, NULL, &cursor));
            error_check(cursor->reset(cursor));
            t_duration_expansion_time = 0;
            t_duration_wt_scan_time = 0;

            start_timer(query_time);
            uint64_t fp = 0;
            uint64_t adapt_duration_ns = 0;
            // for (uint64_t i = 0; i < queries.size(); i++) {
            for (uint64_t i = (expansion-1) * (queries.size()/8); i < (expansion * queries.size()/8); i++) {
                auto q = queries[i];
                const auto [l, r, orig] = q;
                uint64_t left = l;
                uint64_t right = r;
                bool original_result = orig;
                bool query_result = range_f(f, left, right);
                if (query_result) {
                    fp++;
                    start_timer(adapt_qf);
                    adapt_f(f, left, right);
                    measure_timer(adapt_qf);
                    adapt_duration_ns += t_duration_adapt_qf;
                }
            }
            measure_timer(query_time);
            test_out.add_measure(std::string("query_time_") + expansion_str, t_duration_query_time);
            test_out.add_measure(std::string("false_positives_") + expansion_str, fp);
            // test_out.add_measure(std::string("fpr_") + expansion_str, static_cast<double>(fp) / queries.size());
            // test_out.add_measure(std::string("n_queries_") + expansion_str, n_queries);
            test_out.add_measure(std::string("fpr_") + expansion_str, static_cast<double>(fp) / (queries.size()/8));
            test_out.add_measure(std::string("n_queries_") + expansion_str, queries.size()/8);
            test_out.add_measure(std::string("adapt_duration_ns_") + expansion_str, adapt_duration_ns);
        }
    }

// Disabling queries.
#if 0
        auto fp = 0, fn = 0, fa = 0;
        uint64_t num_db_fetches = 0;
        uint64_t num_adapts = 0;
        uint64_t fetch_from_db_duration_ns = 0;
        uint64_t adapt_duration_ns = 0;
        uint64_t query_index = 0;
        uint64_t overall_query_duration = 0;

        start_timer(warmup_time);
        std::vector<std::pair<uint64_t, uint64_t> > adversaries;
        std::vector<bool> adversary_result;
        uint64_t num_warmup_queries = queries.size() / 2;
        for (uint64_t i=0; i < num_warmup_queries; i++) {
            auto q = queries[i];
            const auto [left, right, original_result] = q;
            bool query_result = range_f(f, left, right);
            if (query_result) {
                big_int_l = left;
                big_int_r = right;

                start_timer(db_fetch);
                num_db_fetches++;
                fetch_range_from_db(cursor, big_int_l, big_int_r);
                measure_timer(db_fetch);
                fetch_from_db_duration_ns += t_duration_db_fetch;

                fp += !original_result;
                if (!original_result) {
                    start_timer(adapt_qf);
                    if (!adapt_f(f, left, right)) {
                        fa++;
                    }
                    measure_timer(adapt_qf);
                    adapt_duration_ns += t_duration_adapt_qf;
                    adversaries.push_back(std::pair<uint64_t, uint64_t>(left, right));
                    adversary_result.push_back(original_result);
                }
            } else if (!query_result && original_result) {
                std::cerr << "[!] alert, found false negative!" << std::endl;
                fn++;
            }
        }
        measure_timer(warmup_time);
        uint64_t num_adversarial_queries = 0;
        test_out.add_measure("adversary_set_size", adversaries.size());

        test_out.add_measure(std::string("warmup_time_") + expansion_str, t_duration_warmup_time);
        std::cout << "Finished warmup, collected "<< adversaries.size() << std::endl;

        uint64_t adversary_freq = queries.size();
        if (adversarial_rate != 0) {
            adversary_freq = 1.0 / adversarial_rate; 
        }
        uint64_t adversary_idx = 0;

        start_timer(query_time);
        for (uint64_t i = num_warmup_queries; i < queries.size(); i++) {
            auto q = queries[i];
            const auto [l, r, orig] = q;
            uint64_t left = l;
            uint64_t right = r;
            bool original_result = orig;

            if (i % adversary_freq == 0 && !adversaries.empty()) {
                num_adversarial_queries++;
                left = adversaries[adversary_idx].first;
                right = adversaries[adversary_idx].second;
                original_result = adversary_result[adversary_idx]; 
                adversary_idx++;
                if (adversary_idx == adversaries.size())
                    adversary_idx = 0;
            }

            bool query_result = range_f(f, left, right);
            if (query_result) {
                big_int_l = left;
                big_int_r = right;

                start_timer(db_fetch);
                num_db_fetches++;
                fetch_range_from_db(cursor, big_int_l, big_int_r);
                measure_timer(db_fetch);
                fetch_from_db_duration_ns += t_duration_db_fetch;

                fp += !original_result;
                if (!original_result) {
                    start_timer(adapt_qf);
                    if (!adapt_f(f, left, right)) {
                        fa++;
                    }
                    measure_timer(adapt_qf);
                    adapt_duration_ns += t_duration_adapt_qf;
                    adversaries.push_back(std::pair<uint64_t, uint64_t>(left, right));
                    adversary_result.push_back(original_result);
                }
            } else if (!query_result && original_result) {
                std::cerr << "[!] alert, found false negative!" << std::endl;
                fn++;
            }

            test_out.add_measure(std::string("db_fetch_duration_ns_") + expansion_str, fetch_from_db_duration_ns);
            test_out.add_measure(std::string("adapt_duration_ns_") + expansion_str, adapt_duration_ns);
        }
        measure_timer(query_time);
// Disabling queries.
#endif

        // test_out.add_measure(std::string("query_time_") + expansion_str, t_duration_query_time);
        // test_out.add_measure(std::string("false_positives_") + expansion_str, fp);
        // test_out.add_measure(std::string("fpr_") + expansion_str, static_cast<double>(fp) / queries.size());
        // test_out.add_measure(std::string("false_neg_") + expansion_str, fn);
        // test_out.add_measure(std::string("n_keys_") + expansion_str, current_dataset_size);
        // test_out.add_measure(std::string("n_queries_") + expansion_str, n_queries);
        // test_out.add_measure(std::string("num_db_fetch_") + expansion_str, num_db_fetches);
        // test_out.add_measure(std::string("db_fetch_duration_ns_") + expansion_str, fetch_from_db_duration_ns);
        // test_out.add_measure(std::string("adapt_duration_ns_") + expansion_str, adapt_duration_ns);
        // test_out.add_measure(std::string("adversarial_rate_") + expansion_str, adversarial_rate);
        // test_out.add_measure(std::string("num_adversarial_queries_") + expansion_str, num_adversarial_queries);
        // std::cerr << "WELP num_db_fetches=" << num_db_fetches << std::endl;
    metadata_f(f);
    std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
    std::cout << "[+] Optimizer hack" << optimizer_hack << std::endl;
    error_check(conn->close(conn, NULL)); /* Close all handles. */
}


argparse::ArgumentParser init_parser(const std::string &name)
{
    argparse::ArgumentParser parser(name);

    parser.add_argument("arg")
            .help("the main parameter of the ds (typically desired bpk o #suffix bits)")
            .scan<'g', double>();


    parser.add_argument("-w", "--workload")
            .help("pass the workload from file")
            .nargs(2, 3);

    parser.add_argument("-b", "--buffer_pool_size")
        .help("size of WiredTiger's buffer pool, in MB")
        .nargs(1)
        .required()
        .scan<'u', uint64_t>()
        .required()
        .default_value(64);

    parser.add_argument("-f", "--fpr_workload")
            .help("pass the fpr_workload (don't adapt, just calculate fpr every 1\% of queries) from this file")
            .nargs(2, 3);

    parser.add_argument("-k", "--keys")
            .help("pass the keys from file")
            .nargs(1);

    parser.add_argument("--csv")
            .help("prints the output in csv")
            .nargs(1);

    parser.add_argument("--json")
            .help("prints the intrabench measures in json")
            .nargs(1);

    parser.add_argument("--max-queries")
            .help("limits the maximum number of queries")
            .nargs(1)
            .scan<'i', int>();

    // TODO(chesetti): Is there a way to set and read default values?
    parser.add_argument("--test-type")
        .help("one of adaptivity_inmem, adaptivity_disk")
        .default_value("adaptivity_disk")
        .nargs(1);

    parser.add_argument("--key_len")
        .help("length of WiredTiger's keys, in bytes")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(static_cast<uint64_t>(default_key_len))
        .required();

    parser.add_argument("--val_len")
        .help("length of WiredTiger's values, in bytes")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(static_cast<uint64_t>(default_val_len))
        .required();

    parser.add_argument("--adversarial_rate")
        .help("Percentage of adversarial queries in workload (0 to 100)")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(static_cast<uint64_t>(0))
        .required();

    return parser;
}

std::tuple<InputKeys<uint64_t>, Workload<uint64_t>, double> read_parser_arguments(argparse::ArgumentParser &parser)
{
    auto arg = parser.get<double>("arg");

    auto keys_filename = parser.get<std::string>("keys");
    auto keys = (has_suffix(keys_filename, ".txt")) ? read_keys_from_file<uint64_t>(keys_filename)
                                                    : read_data_binary<uint64_t>(keys_filename);
    auto files = parser.get<std::vector<std::string>>("workload");

    auto test_type = parser.get<std::string>("--test-type");
    if (test_type == "adaptivity_disk" || test_type == "expandability_disk" || test_type=="expandability_inmem") {
      key_len = parser.get<uint64_t>("--key_len");
      val_len = parser.get<uint64_t>("--val_len");
      uint64_t adversarial_percent = parser.get<uint64_t>("--adversarial_rate");
      adversarial_rate = adversarial_percent / 100.0;
      buffer_pool_size_mb = parser.get<uint64_t>("--buffer_pool_size");
    }

    Workload<uint64_t> queries;
    if (has_suffix(files[0], ".txt"))
        exit(0);
    else
    {
        auto left_q = read_data_binary<uint64_t>(files[0], false);
        auto right_q = read_data_binary<uint64_t>(files[1], false);

        if (files.size() == 3)
        {
            auto res_q = read_data_binary<int>(files[2], false);

            for (auto i = 0; i < left_q.size(); i++)
                queries.emplace_back(left_q[i], right_q[i], res_q[i]);
        }
        else
            for (auto i = 0; i < left_q.size(); i++)
                queries.emplace_back(left_q[i], right_q[i], false);
    }

    if (keys.empty())
        throw std::runtime_error("error, keys file is empty.");
    if (queries.empty())
        throw std::runtime_error("error, queries file is empty.");

    if (auto max_queries = parser.present<int>("--max-queries"))
    {
        if (*max_queries < queries.size())
            queries.resize(*max_queries);
    }

    if (auto arg_csv = parser.present<std::string>("--csv"))
    {
        print_csv = true;
        csv_file = *arg_csv;
    }
    if (auto arg_json = parser.present<std::string>("--json"))
    {
        print_json = true;
        json_file = *arg_json;
    }

    std::mt19937 shuffle_gen(query_shuffle_seed);
    std::shuffle(queries.begin(), queries.end(), shuffle_gen);

    std::cout << "[+] nkeys=" << keys.size() << ", nqueries=" << queries.size() << std::endl;
    std::cout << "[+] keys and queries loaded, starting test." << std::endl;
    return std::make_tuple(keys, queries, arg);
}

void print_test()
{
    if (test_verbose)
        test_out.print();

    if (print_csv)
    {
        std::cout << "[+] writing results in " << csv_file << std::endl;
        std::filesystem::path path_csv(csv_file);
        std::string s = (!std::filesystem::exists(path_csv) || std::filesystem::is_empty(path_csv))
                ? test_out.to_csv(true) : test_out.to_csv(false);
        std::ofstream outFile(path_csv, std::ios::app);
        outFile << s;
        outFile.close();
    }
    if (print_json)
    {
        std::cout << "[+] writing intrabench_measures in " << json_file << std::endl;
        std::filesystem::path path_json(json_file);
        std::string s = test_out.intrabench_measures_to_json();
        std::ofstream outFile(path_json);
        outFile << s;
        outFile.close();
    }
}
