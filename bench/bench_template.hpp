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

    std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;
    auto fp = 0, fn = 0, fa = 0;
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
    metadata_f(f);
    std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
}

template <
  typename DbInitFun, typename DbInsertFun, typename DbQueryFun,
  typename InitFun, typename RangeFun, typename AdaptFun, typename SizeFun, 
  typename key_type, typename... Args>
void experiment_adaptivity_fpr(
    DbInitFun db_init,
    DbInsertFun db_insert,
    DbQueryFun db_query,
    InitFun init_f,
    RangeFun range_f,
    AdaptFun adapt_f,
    SizeFun size_f,
    const double param,
    const double db_cache_size,
    InputKeys<key_type>& keys,
    Workload<key_type>& queries,
    Workload<key_type>& fpr_queries,
    Args... args)
{

  auto f = init_f(keys.begin(), keys.end(), param, args...);
  std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;
  auto db = db_init(db_cache_size);

  for (auto key : keys) {
    db_insert(db, key);
  }
  std::cout << "[+] Finished loading DB, starting queries " << std::endl;

  auto fp = 0, fn = 0;
  auto instant_fpr_freq = queries.size() / 100; // Computer instantaneous FPR every 1% of queries.
  for (uint64_t i=0; i < queries.size(); i++) {
    auto q = queries[i];
    const auto [left, right, original_result] = q;
    bool query_result = range_f(f, left, right);

    if (query_result) {
      bool actual_result = db_query(db, left, right);
      if (!actual_result) {
        fp++;
        adapt_f(f, left, right);
      }
    }
    // TODO: Check for false negatives.

    // Calculate instant false positive rate at this point.
    if (i % instant_fpr_freq == 0) {
      uint64_t false_positive_results = 0;
      uint64_t total_positive_results = 0;
      for (uint64_t j=0; j < fpr_queries.size(); j++) {
        auto fpr_query = fpr_queries[j];
        const auto [fpr_left, fpr_right, fpr_original_result] = q;
        bool fpr_query_result = range_f(f, left, right);
        if (fpr_query_result) {
          total_positive_results++;
        }
        if (!fpr_original_result && fpr_query_result) {
          false_positive_results++;
        }
        if (fpr_original_result && !fpr_query_result) {
          std::cerr << "[!] alert, found false negative!" << std::endl;
          fn++;
        }
      }
      if (total_positive_results == 0) {
        test_out.add_intrabench_measure("fpr", i, 0.0);
      } else {
        test_out.add_intrabench_measure("fpr", i, (1.0 * false_positive_results)/total_positive_results);
      }
    }
  }

  auto size = size_f(f);
  test_out.add_measure("size", size);
  test_out.add_measure("bpk", TO_BPK(size, keys.size()));
  test_out.add_measure("fpr", ((double)fp / queries.size()));
  test_out.add_measure("false_neg", fn);
  test_out.add_measure("n_keys", keys.size());
  test_out.add_measure("n_queries", queries.size());
  test_out.add_measure("false_positives", fp);
  std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
}

template <
  typename DbInitFun, typename DbInsertFun, typename DbQueryFun,
  typename InitFun, typename RangeFun, typename AdaptFun, typename SizeFun, 
  typename key_type, typename... Args>
void experiment_adversarial(
    DbInitFun db_init,
    DbInsertFun db_insert,
    DbQueryFun db_query,
    InitFun init_f,
    RangeFun range_f,
    AdaptFun adapt_f,
    SizeFun size_f,
    const double param,
    const double db_cache_size,
    InputKeys<key_type>& keys,
    Workload<key_type>& queries,
    Args... args)
{

  auto f = init_f(keys.begin(), keys.end(), param, args...);
  std::cout << "[+] data structure constructed in " << test_out["build_time"] << "ms, starting queries" << std::endl;

  auto db = db_init(db_cache_size);

  for (auto key : keys) {
    db_insert(db, key);
  }
  std::cout << "[+] Finished loading DB, starting queries " << std::endl;
  std::vector< std::pair<uint64_t, uint64_t> > adv_queries;


  auto fp = 0, fn = 0;
  start_timer(warmup_time);
  for (auto q : queries) {
    const auto [left, right, original_result] = q;
    bool query_result = range_f(f, left, right);
    if (query_result) {
      bool actual_result = db_query(db, left, right);
      if (!actual_result) {
        adv_queries.push_back(std::pair<uint64_t, uint64_t>(left, right));
        fp++;
        adapt_f(f, left, right);
      }
    }
    if (!query_result && original_result) {
      std::cerr << "[!] alert, found false negative!" << std::endl;
      fn++;
    }
  }
  stop_timer(warmup_time);

  std::cerr << "[+] collected " << adv_queries.size() << "adversarial queries"<< std::endl;
  uint64_t count = 0;

  start_timer(adv_query_time);
  uint64_t adv_freq = 5; // 5 percent of queries will be from adversarial set..
  uint64_t adv_i = 0;
  uint64_t adv_fp = 0;
  for (auto q : queries) {
    const auto [left, right, original_result] = q;

    bool query_result;
    if (count % 100 < adv_freq) {
      uint64_t adv_left = adv_queries[adv_i].first;
      uint64_t adv_right = adv_queries[adv_i].second;
      adv_i++;
      adv_i = adv_i % adv_queries.size();
      query_result = range_f(f, adv_left, adv_right);
    } else {
      query_result = range_f(f, left, right);
    }


    if (query_result) {
      bool actual_result = db_query(db, left, right);
      if (!actual_result) {
        adv_fp++;
      }
    }
    if (!query_result && original_result) {
      std::cerr << "[!] alert, found false negative!" << std::endl;
      fn++;
    }
    count++;
  }
  stop_timer(adv_query_time);



  auto size = size_f(f);
  test_out.add_measure("adversarial size", size);
  test_out.add_measure("size", size);
  test_out.add_measure("bpk", TO_BPK(size, keys.size()));
  test_out.add_measure("fpr", ((double)fp / queries.size()));
  test_out.add_measure("false_neg", fn);
  test_out.add_measure("n_keys", keys.size());
  test_out.add_measure("n_queries", queries.size());
  test_out.add_measure("false_positives", fp);
  test_out.add_measure("adversarial_fp", adv_fp);
  std::cout << "[+] test executed successfully, printing stats and closing." << std::endl;
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

    // TODO(chesetti): Is there a way to set what are allowed values?
    parser.add_argument("--test-type")
        .help("one of adaptivity, adversial")
        .default_value("adaptivity")
        .nargs(1);

    return parser;
}

std::tuple<InputKeys<uint64_t>, Workload<uint64_t>, double> read_parser_arguments(argparse::ArgumentParser &parser)
{
    auto arg = parser.get<double>("arg");

    auto keys_filename = parser.get<std::string>("keys");
    auto keys = (has_suffix(keys_filename, ".txt")) ? read_keys_from_file<uint64_t>(keys_filename)
                                                    : read_data_binary<uint64_t>(keys_filename);
    auto files = parser.get<std::vector<std::string>>("workload");

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

Workload<uint64_t> read_fpr_queries(argparse::ArgumentParser &parser) {
  Workload<uint64_t> queries;
  auto files = parser.get<std::vector<std::string>>("fpr_workload");
  auto left_q = read_data_binary<uint64_t>(files[0], false);
  auto right_q = read_data_binary<uint64_t>(files[1], false);
  if (files.size() == 3) {
    auto res_q = read_data_binary<int>(files[2], false);
    for (auto i = 0; i < left_q.size(); i++)
      queries.emplace_back(left_q[i], right_q[i], res_q[i]);
  } else
    for (auto i = 0; i < left_q.size(); i++)
      queries.emplace_back(left_q[i], right_q[i], false);
  return queries;
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
