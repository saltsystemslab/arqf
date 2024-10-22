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

#include <iostream>
#include <argparse/argparse.hpp>
#include "bench_utils.hpp"

static uint64_t optimizer_hack = 0;
const int default_key_len = 8, default_val_len = 504;
uint64_t key_len, val_len;
uint64_t mixed_num_warmup_keys, mixed_num_read_queries, mixed_num_write_queries;
uint64_t default_buffer_pool_size_mb = 64;
uint64_t buffer_pool_size_mb = 0;
float adversarial_rate = 0.1;
double load_factor = 0.90;

static inline int fetch_range_from_db(WT_CURSOR *cursor, SimpleBigInt &l, SimpleBigInt &r)
{
    error_check(cursor->reset(cursor));
    cursor->set_key(cursor, (char *) l.num);
    error_check(cursor->bound(cursor, "action=set,bound=lower,inclusive=true"));
    cursor->set_key(cursor, (char *) r.num);
    error_check(cursor->bound(cursor, "action=set,bound=upper,inclusive=true"));

    uint32_t x = 0;
    while ((cursor->next(cursor)) == 0) {
        x++;
    }
    optimizer_hack += x;
    return x;
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

#define start_timer(t) \
    auto t_start_##t = timer::now(); \

#define stop_timer(t) \
    auto t_end_##t = timer::now(); \
    test_out.add_measure(#t, std::chrono::duration_cast<std::chrono::milliseconds>(t_end_##t - t_start_##t).count());

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
    auto f = init_f(keys.begin(), keys.end(), true, param, args...);

    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;
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
void experiment_fpr(
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
    auto f = init_f(keys.begin(), keys.end(), true, param, args...);

    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;
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

int
print_cursor(WT_CURSOR *cursor)
{
        const char *desc, *pvalue;
        uint64_t value;
        int ret;
        while ((ret = cursor->next(cursor)) == 0 &&
            (ret = cursor->get_value(cursor, &desc, &pvalue, &value)) == 0)
                if (value != 0) {
                  int key;
                  cursor->get_key(cursor, &key);
                  printf("key: %d %s=%s\n", key, desc, pvalue);
                }
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

int 
print_database_stat(WT_SESSION *session, int stat_id)
{
        const char *desc, *pvalue;
        uint64_t value;
        WT_CURSOR *cursor;
        int ret;
        if ((ret = session->open_cursor(session,
            "statistics:", NULL, NULL, &cursor)) != 0)
                return (ret);
        cursor->set_key(cursor, stat_id);
        if ((ret = cursor->search(cursor)) != 0) {
          return ret;
        }
        ret = cursor->get_value(cursor, &desc, &pvalue, &value);
        printf("%s=%s %lu\n", desc, pvalue, value);
        ret = cursor->close(cursor);

        return (ret);
}

uint64_t 
get_database_stat(WT_SESSION *session, int stat_id)
{
        const char *desc, *pvalue;
        uint64_t value;
        WT_CURSOR *cursor;
        int ret;
        if ((ret = session->open_cursor(session,
            "statistics:", NULL, NULL, &cursor)) != 0)
                return (ret);
        cursor->set_key(cursor, stat_id);
        if ((ret = cursor->search(cursor)) != 0) {
          return ret;
        }
        ret = cursor->get_value(cursor, &desc, &pvalue, &value);
        ret = cursor->close(cursor);
        return value;
}


// Adversarial Test.
template <typename InitFun, typename RangeFun, typename AdaptFun, typename SizeFun, typename MetadataFun, typename key_type, typename... Args>
void experiment_adversarial_workload(
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
    
    // print_database_stats(session);

    SimpleBigInt big_int_k(key_len), big_int_v(val_len);
    SimpleBigInt big_int_l(key_len), big_int_r(key_len);
    
    std::cerr << "[+] WiredTiger loaded DB loaded. with config: " << std::string(connection_config) << std::endl;

    auto f = init_f(keys.begin(), keys.end(), true, param, args...);

    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;
    auto fp = 0, fn = 0, fa = 0;
    auto fp_adversarial = 0;
    auto fp_query_set = 0;

    uint64_t num_db_fetches = 0;
    uint64_t num_adapts = 0;
    uint64_t fetch_from_db_duration_ns = 0;
    uint64_t adapt_duration_ns = 0;
    uint64_t query_index = 0;
    uint64_t overall_query_duration = 0;
    uint64_t true_queries = 0;

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
        int num_items = fetch_range_from_db(cursor, big_int_l, big_int_r);
        measure_timer(db_fetch);
        fetch_from_db_duration_ns += t_duration_db_fetch;

        fp += (num_items == 0);
        if (num_items != 0) {
          true_queries++;
        }
        if (num_items == 0) {
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
        if (i % adversary_freq == 0) {
          fp_adversarial++;
        } else {
          fp_query_set++;
        }
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
    test_out.add_measure("n_warmup_queries", num_warmup_queries);
    test_out.add_measure("n_queries", queries.size() - num_warmup_queries);
    test_out.add_measure("false_positives", fp);
    test_out.add_measure("false_positives_adversarial", fp_adversarial);
    test_out.add_measure("false_positives_query", fp_query_set);
    test_out.add_measure("num_db_fetch", num_db_fetches);
    test_out.add_measure("db_fetch_duration_ns", fetch_from_db_duration_ns);
    test_out.add_measure("adapt_duration_ns", adapt_duration_ns);
    test_out.add_measure("adversarial_rate", adversarial_rate);
    test_out.add_measure("num_adversarial_queries", num_adversarial_queries);
    test_out.add_measure("bytes_read", get_database_stat(session, WT_STAT_CONN_CACHE_BYTES_READ));
    test_out.add_measure("num_read_disk_ios", get_database_stat(session, WT_STAT_CONN_READ_IO));
    test_out.add_measure("true_queries", true_queries);
    test_out.add_measure("wt_buffer_pool_size_mb", buffer_pool_size_mb);
    metadata_f(f);
    std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
    std::cout << "[+] Optimizer hack" << optimizer_hack << std::endl;
}

template <
  typename InitFun, typename InsertFun, typename RangeFun, typename AdaptFun, typename SizeFun, 
  typename MetadataFun, typename key_type, typename... Args>
void experiment_mixed_workload(
    InitFun init_f, 
    InsertFun insert_f,
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
  if (keys.size() < mixed_num_warmup_keys + mixed_num_write_queries) {
    abort(); // Not enough keys to finish this test.
  }
  if (queries.size() < mixed_num_read_queries) {
    abort(); // Not enough keys to read.
  }

    uint64_t num_db_fetches = 0;
    uint64_t num_adapts = 0;
    uint64_t true_queries = 0;
    uint64_t fetch_from_db_duration_ns = 0;
    uint64_t adapt_duration_ns = 0;
  // Begin loading DB.
    const uint32_t max_schema_len = 128;
    const uint32_t max_conn_config_len = 128;

    auto fp = 0, fn = 0, fa = 0;
    WT_CONNECTION *conn;
    WT_SESSION *session;
    WT_CURSOR *cursor;
    char table_schema[max_schema_len];
    char connection_config[max_conn_config_len];
    sprintf(table_schema, "key_format=%lds,value_format=%lds", key_len, val_len);
    sprintf(connection_config, "create,statistics=(all),direct_io=[data],cache_size=%ldMB", buffer_pool_size_mb);

    if (std::filesystem::exists(wt_home))
        std::filesystem::remove_all(wt_home);
    std::filesystem::create_directory(wt_home);

    error_check(wiredtiger_open(wt_home.c_str(), NULL, connection_config, &conn));
    error_check(conn->open_session(conn, NULL, NULL, &session));
    error_check(session->create(session, "table:bm", table_schema));
    error_check(session->open_cursor(session, "table:bm", NULL, NULL, &cursor));

    // print_database_stats(session);
    start_timer(load_phase_time);
    auto f = init_f(keys.begin(), keys.end(), false, param, args...);

    SimpleBigInt big_int_k(key_len), big_int_v(val_len);
    SimpleBigInt big_int_l(key_len), big_int_r(key_len);
    for (uint64_t i=0; i < mixed_num_warmup_keys; i++) {
      big_int_k = keys[i];
      big_int_v.randomize();
      insert_kv(cursor, (char *) big_int_k.num, (char *) big_int_v.num);
      insert_f(f, keys[i]);
    }
    stop_timer(load_phase_time);

    std::cerr << "[+] WiredTiger loaded DB loaded. with config: " << std::string(connection_config) << std::endl;
    std::cerr << "[+] Done with warmup phase "<<std::endl;


    uint64_t total_ops = mixed_num_read_queries + mixed_num_write_queries;
    uint64_t read_ops_per_cycle = ((mixed_num_read_queries * 100 ) / total_ops);
    uint64_t write_ops_per_cycle = ((mixed_num_write_queries * 100) / total_ops);
    uint64_t num_cycles = total_ops / 100;
    uint64_t read_op_idx = 0;
    uint64_t write_op_idx = mixed_num_warmup_keys;

    start_timer(mixed_workload_time);
    for (uint64_t cycle = 0; cycle < num_cycles; cycle++) {
      for (uint64_t i=0; i < write_ops_per_cycle; i++) {
        big_int_k = keys[write_op_idx];
        big_int_v.randomize();
        insert_kv(cursor, (char *) big_int_k.num, (char *) big_int_v.num);
        insert_f(f, keys[write_op_idx]);
        write_op_idx++;
      }
      for (uint64_t i=0; i < read_ops_per_cycle; i++) {
        auto q = queries[read_op_idx];
        const auto [left, right, original_result] = q;
        bool query_result = range_f(f, left, right);
        if (query_result) {
          big_int_l = left;
          big_int_r = right;

          start_timer(db_fetch);
          num_db_fetches++;
          int num_items = fetch_range_from_db(cursor, big_int_l, big_int_r);
          measure_timer(db_fetch);
          fetch_from_db_duration_ns += t_duration_db_fetch;

          fp += (num_items == 0);
          if (num_items != 0) true_queries++;
          if (num_items == 0) {
            start_timer(adapt_qf);
            if (!adapt_f(f, left, right)) {
              fa++;
            }
            measure_timer(adapt_qf);
            adapt_duration_ns += t_duration_adapt_qf;
          }
        }
        read_op_idx++;
      }
    }
    stop_timer(mixed_workload_time);

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
    test_out.add_measure("bytes_read", get_database_stat(session, WT_STAT_CONN_CACHE_BYTES_READ));
    test_out.add_measure("num_read_disk_ios", get_database_stat(session, WT_STAT_CONN_READ_IO));
    test_out.add_measure("num_read_queries", read_op_idx);
    test_out.add_measure("num_write_queries", write_op_idx - mixed_num_warmup_keys);
    test_out.add_measure("true_queries", true_queries);
    test_out.add_measure("wt_buffer_pool_size_mb", buffer_pool_size_mb);
    metadata_f(f);
    std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
    std::cout << "[+] Optimizer hack" << optimizer_hack << std::endl;
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
        .help("one of adaptivity_inmem, adaptivity_disk, adaptivity_mixed")
        .default_value("adaptivity_disk")
        .nargs(1);

    parser.add_argument("--key_len")
        .help("length of WiredTiger's keys, in bytes")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(default_key_len)
        .required();

    parser.add_argument("--val_len")
        .help("length of WiredTiger's values, in bytes")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(default_val_len)
        .required();
    
    parser.add_argument("--mixed_num_warmup_keys")
        .help("Number of keys to fillup in warmup phase")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(0)
        .required();

    parser.add_argument("--mixed_num_reads")
        .help("Number of read_queries in mixed workload")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(0)
        .required();

    parser.add_argument("--mixed_num_writes")
        .help("Number of write_queries in mixed workload")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(0)
        .required();

    parser.add_argument("--adversarial_rate")
        .help("Percentage of adversarial queries in workload (0 to 100)")
        .nargs(1)
        .scan<'u', uint64_t>()
        .default_value(0)
        .required();

    parser.add_argument("--load_factor")
        .help("Load factor of filter (0 to 100)")
        .nargs(1)
        .scan<'u', uint64_t>();

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
    if (test_type == "adversarial") {
      key_len = parser.get<uint64_t>("--key_len");
      val_len = parser.get<uint64_t>("--val_len");
      uint64_t adversarial_percent = parser.get<uint64_t>("--adversarial_rate");
      adversarial_rate = adversarial_percent / 100.0;
      buffer_pool_size_mb = parser.get<uint64_t>("--buffer_pool_size");
    }
    if (test_type == "mixed") {
      key_len = parser.get<uint64_t>("--key_len");
      val_len = parser.get<uint64_t>("--val_len");
      mixed_num_warmup_keys = parser.get<uint64_t>("--mixed_num_warmup_keys");
      mixed_num_read_queries = parser.get<uint64_t>("--mixed_num_reads");
      mixed_num_write_queries = parser.get<uint64_t>("--mixed_num_writes");
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
    if (auto load_factor_flag = parser.present<uint64_t>("--load_factor"))
    {
        load_factor= (*load_factor_flag)/100.0;
    } else {
      load_factor = 0.90;
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
