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
#include <cassert>
#include <vector>
#include "zipf.h"

#include "bench_utils.hpp"
#include <argparse/argparse.hpp>

static const std::vector<std::string> kdist_names = {"kuniform", "knormal"};
static const std::vector<std::string> kdist_default = {"kuniform"};
static const std::vector<std::string> qdist_names = {"quniform", "qnormal", "qcorrelated", "qtrue", "qzipfian"};
static const std::vector<std::string> qdist_default = {"quniform", "qcorrelated"};

auto s = 10999;
#define seed s++
// std::random_device rd;
// #define seed rd()

bool save_binary = true;
bool allow_true_queries = false;
bool mixed_queries = false;

auto default_n_keys = 200'000'000;
auto default_n_queries = 10'000'000;
auto default_range_size = std::vector<int>{0, 5, 10}; /* {point queries, 2^{5}, 2^{10}}*/
auto default_corr_degree = 0.8;

InputKeys<uint64_t> keys_from_file = InputKeys<uint64_t>();

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60

inline uint64_t MurmurHash64A(const void * key, int len, unsigned int s)
{
	const uint64_t m = 0xc6a4a7935bd1e995;
	const int r = 47;

	uint64_t h = s ^ (len * m);

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

void save_keys(InputKeys<uint64_t> &keys, const std::string &file)
{
    if (save_binary) {
        write_to_binary_file(keys, file);
    }
    else {
        save_keys_to_file(keys, file + ".txt");
    }
}

void save_queries(Workload<uint64_t> &work, const std::string &l_keys, const std::string &r_keys = "", const std::string &res_keys = "")
{
    if (save_binary)
    {
        std::vector<uint64_t> left_q, right_q;
        std::vector<int> result_q;
        left_q.reserve(work.size());
        right_q.reserve(work.size());
        result_q.reserve(work.size());
        for (auto w : work)
        {
            auto [left, right, result] = w;
            left_q.push_back(left);
            right_q.push_back(right);
            result_q.push_back(result);
        }
        write_to_binary_file(left_q, l_keys);
        if (!r_keys.empty())
            write_to_binary_file(right_q, r_keys);

        write_to_binary_file(result_q, res_keys);
    }
    else
        save_workload_to_file(work, l_keys + ".txt", r_keys + ".txt");
}

/**
 * @brief Given a point and a range size, returns the range [point, point + range_size - 1]
 */
auto point_to_range = [](auto point, auto range_size) {
    return std::make_pair(point, (point + range_size) - 1);
};

void printProgress(double percentage) {
    static int last_percentage = 0;
    int val = (int) (percentage * 100);
    if (last_percentage == val)
        return;

    int lpad = (int) (percentage * PBWIDTH);
    int rpad = PBWIDTH - lpad;
    last_percentage = val;
    printf("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
    fflush(stdout);
}

bool create_dir_recursive(const std::string &dir_name) {
    std::error_code err;
    if (!std::filesystem::create_directories(dir_name, err)) {
        if (std::filesystem::exists(dir_name))
            return true; // the folder probably already existed

        std::cerr << "Failed to create [" << dir_name << "]" << std::endl;
        return false;
    }
    return true;
}

InputKeys<uint64_t> generate_keys_zipfian(uint64_t n_keys, double pow, uint64_t batch_size, uint64_t universe_size = UINT32_MAX - 1, uint64_t s = 0) {
  std::vector<uint64_t> keys_set;
  if (batch_size == 0) batch_size = n_keys;
  if (s == 0) s = time(NULL);
  uint64_t *zipfian = new uint64_t[batch_size];
  for (uint64_t i=0; i < n_keys; i = i+batch_size) {
    generate_random_keys(zipfian + i, universe_size, batch_size, 1.5);
    for (uint64_t j=0; j < batch_size; j++) {
      keys_set.push_back(MurmurHash64A(&zipfian[j], sizeof(zipfian[j]), s));
    }
  }
  return keys_set;
}

InputKeys<uint64_t> generate_keys_uniform(uint64_t n_keys, uint64_t max_key = UINT64_MAX - 1) {
    std::set<uint64_t> keys_set;

    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint64_t> distr_value(0, max_key);

    auto n_iterations = 0;
    while (keys_set.size() < n_keys) {
        if (++n_iterations >= 10 * n_keys)
            throw std::runtime_error("error: timeout for the input keys generation");

        auto key = distr_value(gen);
        keys_set.insert(key);
        printProgress(((double) keys_set.size()) / n_keys);
    }

    return {keys_set.begin(), keys_set.end()};
}

InputKeys<uint64_t> generate_keys_normal(uint64_t n_keys, long double sd) {
    std::set<uint64_t> keys_set;

    std::mt19937 gen(seed);
    auto nor_dist = std::normal_distribution<long double>(1ULL << (64 - 1), sd);

    auto n_iterations = 0;
    while (keys_set.size() < n_keys) {
        if (++n_iterations >= 10 * n_keys)
            throw std::runtime_error("error: timeout for the input keys generation");

        auto key = nor_dist(gen);
        keys_set.insert(key);
        printProgress(((double) keys_set.size()) / n_keys);
    }

    return {keys_set.begin(), keys_set.end()};
}

Workload<uint64_t> generate_true_queries(InputKeys<uint64_t> &keys,uint64_t n_queries, uint64_t range_size, bool mixed = false)
{
    std::set<uint64_t> chosen_points;

    std::mt19937 gen_random_keys(seed);
    std::uniform_int_distribution<uint64_t> rand_keys_distr(0, keys.size() - 1);

    std::mt19937 gen_random_offset(seed);
    std::uniform_int_distribution<uint64_t> rand_offset_distr(0, range_size - 1);

    while (chosen_points.size() != n_queries)
        chosen_points.insert(keys[rand_keys_distr(gen_random_keys)]);

    Workload<uint64_t> w;
    w.reserve(n_queries);

    std::mt19937 gen_range(seed);
    std::uniform_int_distribution<uint64_t> range_distr(1, range_size);

    for (auto point : chosen_points)
    {
        if (mixed)
        {
            auto r = static_cast<uint64_t>(range_distr(gen_range));
            std::uniform_int_distribution<uint64_t>::param_type d(0, r - 1);
            rand_offset_distr.param(d);
            auto [left, right] = point_to_range(point - rand_offset_distr(gen_random_offset), r);
            w.emplace_back(left, right, true);
        }
        else
        {
            auto [left, right] = point_to_range(point - rand_offset_distr(gen_random_offset), range_size);
            w.emplace_back(left, right, true);
        }

    }

    return w;
}


Workload<uint64_t> generate_synth_queries(const std::string& qdist, InputKeys<uint64_t> &keys,
                                          uint64_t n_queries, uint64_t min_range, uint64_t max_range,
                                          const double corr_degree, const long double stddev, const long zipf_batch_size=0,
                                          const uint64_t zipf_universe_size = UINT64_MAX) {
    std::set<std::tuple<uint64_t, uint64_t, bool>> unique_queries;
    std::vector<std::tuple<uint64_t, uint64_t, bool>> q; 

    std::vector<uint64_t> middle_points;

    if (qdist == "qnormal")
        middle_points = generate_keys_normal(10 * n_queries, stddev);
    else if (qdist == "quniform")
        middle_points = generate_keys_uniform(3 * n_queries);
    else if (qdist == "qzipfian") 
        middle_points = generate_keys_zipfian(n_queries, 1.5, zipf_batch_size, zipf_universe_size-1);
    else // qdist == "qcorrelated"
    {
        std::mt19937 g(seed);
        auto t = keys;
        std::shuffle(t.begin(), t.end(), g);
        auto i = 0;
        middle_points.reserve(n_queries);
        while (i < n_queries) {
            auto n = std::min<uint64_t>(keys.size(), n_queries - i);
            std::copy(t.begin() + i, t.begin() + i + n, middle_points.begin() + i);
            i += n;
        }
    }

    std::mt19937 gen_range(seed);
    std::uniform_int_distribution<uint64_t> range_distr(std::max(min_range, 1UL), max_range);

    std::mt19937 gen_corr(seed);
    std::uniform_int_distribution<uint64_t> corr_distr(1, (1UL << std::lround(30 * (1 - corr_degree))));

    std::mt19937 gen_pos_middle_points(seed);
    std::uniform_int_distribution<int> pos_distr(1, middle_points.size() - 1);
    auto n_iterations = 0;
    auto i = 0;
    while (q.size() < n_queries) {
        if (++n_iterations >= 100 * n_queries) {
            std::cout << std::endl
                      << "application seems stuck, saving "<<q.size() <<"queries. " << std::endl;
            break;
        }

        auto range_size = (min_range == max_range) ? min_range : static_cast<uint64_t>(range_distr(gen_range));

        uint64_t left, right;

        if (qdist == "quniform")
            std::tie(left, right) = point_to_range(middle_points[i++], range_size);
        else if (qdist == "qnormal")
            std::tie(left, right) = point_to_range(middle_points[pos_distr(gen_pos_middle_points)], range_size);
        else if (qdist == "qzipfian")
            std::tie(left, right) = point_to_range(middle_points[i++], range_size);
        else // qdist == qcorrelated
        {
            auto p = middle_points[q.size()] + corr_distr(gen_corr);
            std::tie(left, right) = point_to_range(p, range_size);
        }
        if (std::numeric_limits<uint64_t>::max() - left < range_size) {
            left = std::numeric_limits<uint64_t>::max() - range_size;
            std::cout<<"Query key skipped"<<std::endl;
            continue;
        }

        auto q_result = (range_size > 1) ? vector_range_query(keys, left, right) : vector_point_query(keys, left);
        // Don't discard true queries for zipfian distribution.
        if (!allow_true_queries && q_result && qdist != "qzipfian") {
            std::cout<<"Query key skipped"<<std::endl;
            continue;
        }

        if (qdist != "qzipfian") {
          uint64_t old_size = unique_queries.size();
          unique_queries.emplace(left, right, q_result);
          if (unique_queries.size() == old_size) {
            continue;
          }
        }

        q.push_back(std::make_tuple(left, right, q_result));
        printProgress(((double) q.size()) / n_queries);
    }

    Workload<uint64_t> q_out;
    q_out.reserve(q.size());
    for (auto i : q)
        q_out.push_back(i);
    std::mt19937 shuffle_gen(seed);
    std::shuffle(q_out.begin(), q_out.end(), shuffle_gen);
    return q_out;
}

Workload<uint64_t> generate_synth_queries(const std::string& qdist, InputKeys<uint64_t> &keys,
                                          uint64_t n_queries, uint64_t range_size,
                                          const double corr_degree, const long double stddev) {
    return generate_synth_queries(qdist, keys, n_queries, range_size, range_size, corr_degree, stddev);
}

void generate_synth_datasets(const std::vector<std::string> &kdist, const std::vector<std::string> &qdist,
                             uint64_t n_keys, uint64_t n_queries, uint64_t n_query_sets,
                             std::vector<int> range_size_list, const uint64_t zipf_universe_size = UINT64_MAX, 
                             const double corr_degree = 0.8, const long double stddev = (long double) UINT64_MAX * 0.1,
                             const long zipf_batch_size = 0) {
    std::vector<uint64_t> ranges(range_size_list.size());
    std::transform(range_size_list.begin(), range_size_list.end(), ranges.begin(), [](auto v) {
        return (1ULL << v);
    });

    std::cout << "[+] starting dataset generation" << std::endl;
    std::cout << "[+] n=" << n_keys << ", q=" << n_queries << std::endl;
    std::cout << "[+] kdist=";
    std::copy(kdist.begin(), kdist.end(), std::ostream_iterator<std::string>(std::cout, ","));
    std::cout << std::endl
              << "[+] qdist=";
    std::copy(qdist.begin(), qdist.end(), std::ostream_iterator<std::string>(std::cout, ","));
    std::cout << std::endl;
    std::cout << "[+] corr_degree=" << corr_degree << std::endl;


    for (const auto& k: kdist) {
        std::string root_path = "./" + k + "/";
        auto keys = (k == "kuniform") ? generate_keys_uniform(n_keys) : generate_keys_normal(n_keys, stddev);
        std::cout << std::endl
                  << "[+] generated `" << k << "` keys" << std::endl;
        for (uint64_t qset = 0; qset < n_query_sets; qset++) {
        for (const auto& q: qdist) {
            for (auto i = 0; i < ranges.size(); i++) {
                auto range_size = ranges[i];
                auto queries = (q == "qtrue") ? generate_true_queries(keys, n_queries, range_size) :
                  generate_synth_queries(q, keys, n_queries, range_size, range_size, corr_degree, stddev, zipf_batch_size, zipf_universe_size);
                std::cout << std::endl
                          << "[+] generated `" << q << "_" << range_size_list[i] << "` queries" << std::endl;

                std::string queries_path;
                if (n_query_sets == 0) {
                  queries_path = root_path + std::to_string(range_size_list[i]) + "_" + q + "/";
                } else {
                  queries_path = root_path + std::to_string(range_size_list[i]) + "_" + q + "_trial_" + std::to_string(qset) + "/";
                }
                if (!create_dir_recursive(queries_path))
                    throw std::runtime_error("error, impossible to create dir");

                save_queries(queries, queries_path + "left", queries_path + "right", queries_path + "result");
                std::cout << "[+] queries wrote at " << queries_path << std::endl;
            }

            if (mixed_queries)
            {
                auto range_size = ranges.back();
                auto range_size_min = 1;

                auto queries = (q == "qtrue") ? generate_true_queries(keys, n_queries, range_size, true) :
                               generate_synth_queries(q, keys, n_queries, range_size_min, range_size, corr_degree, stddev);

                auto queries_path = root_path + std::to_string(range_size_list.back()) + "M_" + q + "/"; /* mixed */
                if (!create_dir_recursive(queries_path))
                    throw std::runtime_error("error, impossible to create dir");

                if (allow_true_queries)
                    save_queries(queries, queries_path + "left", queries_path + "right", queries_path + "result");
                else
                    save_queries(queries, queries_path + "left", queries_path + "right");

                std::cout << std::endl << "[+] queries wrote at " << queries_path << std::endl;
            }
        }
        }

        save_keys(keys, root_path + "keys");
        std::cout << "[+] keys wrote at " << root_path << std::endl;
    }
}

std::pair<InputKeys<uint64_t>, std::vector<Workload<uint64_t>>>
generate_real_queries(std::vector<uint64_t> &data, uint64_t n_queries, std::vector<uint64_t> &range_list, bool remove_duplicates = true) {
    std::vector<std::pair<uint64_t, int>> candidates;

    std::vector<Workload<uint64_t>> queries_list((mixed_queries) ? range_list.size() + 1 : range_list.size());

    auto max_range_size = *std::max_element(range_list.begin(), range_list.end());

    for (size_t i = 0; i < data.size() - 1; i++) {
        if (data[i + 1] < data[i])
            throw std::runtime_error("error, sequence is not strictly increasing");
        if (remove_duplicates && data[i] == data[i + 1])
            data.erase(data.begin() + i);
        else if (max_range_size < data[i + 1] - data[i])
            candidates.emplace_back(data[i], i);

        // dst += (data[i + 1] - data[i]);
        printProgress((double) i / (data.size() - 2));
    }
    std::cout << std::endl;
    // long double avg = (long double) dst / (data.size() - 1);
    // std::cout << "dst: " << dst << ", avg: " << avg << std::endl;

    if (std::numeric_limits<uint64_t>::max() - data.back() > max_range_size)
        candidates.emplace_back(data.back(), data.size() - 1);

    if (candidates.size() < n_queries)
        throw std::runtime_error(
                "error, can build at most " + std::to_string(candidates.size()) + " over " + std::to_string(n_queries) +
                " queries");

    std::cout << "[+] found " << candidates.size() << " candidates.";

    std::mt19937 gen_shuffle(seed);
    std::shuffle(candidates.begin(), candidates.end(), gen_shuffle);

    auto indexes = std::vector<int>(n_queries);
    std::transform(candidates.begin(), candidates.begin() + n_queries, indexes.begin(),
                   [](const std::pair<uint64_t, int> &p) { return p.second; });
    std::sort(indexes.begin(), indexes.end());

    std::vector<uint64_t> keys;
    keys.reserve(data.size() - n_queries);
    auto it = indexes.begin();
    for (auto i = 0; i < data.size(); i++) {
        if (i != *it)
            keys.push_back(data[i]);
        else if (it != indexes.end())
            ++it;
    }

    if (!std::is_sorted(keys.begin(), keys.end()))
        throw std::runtime_error("unexpected error, keys are not sorted.");

    std::mt19937 gen_range(seed);
    std::uniform_int_distribution<uint64_t> range_distr(1, range_list.back());

    for (auto it = candidates.begin(); it < candidates.begin() + n_queries; ++it) {
        for (auto i = 0; i < range_list.size(); i++)
        {
            auto range_q = point_to_range(it->first, range_list[i]);
            if (range_q.first > range_q.second)
                throw std::runtime_error("unexpected error, queries are not sorted");
            queries_list[i].emplace_back(range_q.first, range_q.second, false);
        }

        if (mixed_queries)
        {
            auto range_size = static_cast<uint64_t>(range_distr(gen_range));
            auto range_q = point_to_range(it->first, range_size);
            queries_list[range_list.size()].emplace_back(range_q.first, range_q.second, false);
        }
    }

    return std::make_pair(keys, queries_list);
}

template <typename value_type = uint64_t>
void generate_real_dataset(const std::string& file, uint64_t n_queries, std::vector<int> range_size_list) {
    std::vector<uint64_t> ranges(range_size_list.size());
    std::transform(range_size_list.begin(), range_size_list.end(), ranges.begin(), [](auto v) {
        return (1ULL << v);
    });

    std::string base_filename = file.substr(file.find_last_of("/\\") + 1);
    std::string::size_type pos = base_filename.find('_');
    std::string dir_name = (pos != std::string::npos) ? base_filename.substr(0, pos) : base_filename;
    std::string root_path = "./" + dir_name + "/";
    auto temp_data = read_data_binary<value_type>(file);
    auto all_data = std::vector<uint64_t>(temp_data.begin(), temp_data.end());
    assert(all_data.size() > n_queries);

    std::cout << "[+] starting `" << dir_name << "` dataset generation" << std::endl;
    auto [keys, queries_list] = generate_real_queries(all_data, n_queries, ranges);
    std::cout << std::endl << "[+] full dataset generated" << std::endl;
    std::cout << "[+] nkeys=" << keys.size() << ", nqueries=" << queries_list[0].size() << std::endl;

    for (auto i = 0; i < ranges.size(); i++) {
        auto range_size = ranges[i];

        std::string queries_path = root_path + std::to_string(range_size_list[i]) + "/";
        if (!create_dir_recursive(queries_path))
            throw std::runtime_error("error, impossible to create dir");
        if (range_size == 1)
            save_queries(queries_list[i], queries_path + "point");
        else
            save_queries(queries_list[i], queries_path + "left", queries_path + "right");
        std::cout << "[+] queries wrote at " << queries_path << std::endl;
    }

    if (mixed_queries)
    {
        std::string queries_path = root_path + std::to_string(range_size_list.back()) + "M/";
        if (!create_dir_recursive(queries_path))
            throw std::runtime_error("error, impossible to create dir");

        save_queries(queries_list.back(), queries_path + "left", queries_path + "right");
        std::cout << "[+] queries wrote at " << queries_path << std::endl;
    }

    save_keys(keys, root_path + "keys");
    std::cout << "[+] keys wrote at " << root_path << std::endl;

}

int main(int argc, char const *argv[]) {
    argparse::ArgumentParser parser("workload_gen");

    parser.add_argument("--kdist")
            .nargs(argparse::nargs_pattern::at_least_one)
            .required()
            .default_value(kdist_default);

    parser.add_argument("--qdist")
            .nargs(argparse::nargs_pattern::at_least_one)
            .required()
            .default_value(qdist_default);

    parser.add_argument("--range-size")
            .help("List of the ranges to compute (as power of 2 and/or 0 for point queries)")
            .nargs(argparse::nargs_pattern::at_least_one)
            .required()
            .default_value(default_range_size)
            .scan<'d', int>();

    parser.add_argument("-n", "--n-keys")
            .help("the number of input keys")
            .required()
            .default_value(uint64_t(default_n_keys))
            .scan<'u', uint64_t>()
            .nargs(1);

    parser.add_argument("-t", "--n-query-sets")
            .help("the number of query-sets to generate")
            .required()
            .default_value(uint64_t(1))
            .scan<'u', uint64_t>()
            .nargs(1);

    parser.add_argument("-q", "--n-queries")
            .help("the number of queries")
            .nargs(1)
            .required()
            .default_value(uint64_t(default_n_queries))
            .scan<'u', uint64_t>();

    parser.add_argument("--binary-keys")
            .help("generates the queries from binary file")
            .nargs(argparse::nargs_pattern::at_least_one);

    parser.add_argument("--allow-true")
            .help("allows the generation of true queries in the workload (note, this will produce 3 files)")
            .implicit_value(true)
            .default_value(false);

    parser.add_argument("--mixed")
            .help("generates mixed range queries in the range [0, 2^last_range_size]")
            .implicit_value(true)
            .default_value(false);

    parser.add_argument("--corr-degree")
            .help("Correlation degree for correlated workloads")
            .required()
            .default_value(default_corr_degree)
            .scan<'g', double>();

    parser.add_argument("--zipf-batch-size")
            .help("Size of an independent zipf query size")
            .nargs(1)
            .default_value(uint64_t(0))
            .scan<'u', uint64_t>();

    parser.add_argument("-u", "--zipf-universe-size")
            .help("Number of elements in the universe")
            .required()
            .default_value(UINT64_MAX-1)
            .scan<'u', uint64_t>()
            .nargs(1);

    try {
        parser.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << parser;
        std::exit(1);
    }

    auto kdist = parser.get<std::vector<std::string>>("--kdist");
    auto qdist = parser.get<std::vector<std::string>>("--qdist");

    if (!std::all_of(kdist.cbegin(), kdist.cend(), [](const std::string& s) {
        return (std::find(kdist_names.begin(), kdist_names.end(), s) != kdist_names.end());
    }))
        throw std::runtime_error("error, kdist unknown");

    if (!std::all_of(qdist.cbegin(), qdist.cend(), [](const std::string& s) {
        return (std::find(qdist_names.begin(), qdist_names.end(), s) != qdist_names.end());
    }))
        throw std::runtime_error("error, qdist unknown");

    auto n_keys = parser.get<uint64_t>("-n");
    auto n_queries = parser.get<uint64_t>("-q");
    auto ranges_int = parser.get<std::vector<int>>("--range-size");
    auto corr_degree = parser.get<double>("--corr-degree");
    auto zipf_batch_size = parser.get<uint64_t>("--zipf-batch-size");
    auto zipf_universe_size = parser.get<uint64_t>("--zipf-universe-size");
    auto n_query_sets = parser.get<uint64_t>("--n-query-sets");

    allow_true_queries = parser.get<bool>("--allow-true");
    mixed_queries = parser.get<bool>("--mixed");

    assert((n_keys > 0) && (n_queries > 0));
    assert(!kdist.empty());
    assert(!qdist.empty());

    if (auto file_list = parser.present<std::vector<std::string>>("--binary-keys"))
    {
        for (const auto &file : *file_list)
        {
            if (file.find("uint32") != std::string::npos)
                generate_real_dataset<uint32_t>(file, n_queries, ranges_int);
            else
                generate_real_dataset(file, n_queries, ranges_int);
        }

    }
    else
        generate_synth_datasets(kdist, qdist, n_keys, n_queries, n_query_sets, ranges_int, zipf_universe_size, corr_degree, zipf_batch_size);

    return 0;
}
