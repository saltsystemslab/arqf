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
#include <map>
#include <set>
#include <string>
#include <algorithm>
#include <iterator>
#include <random>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <wiredtiger.h>
#include "bigint.hpp"

/**
 * This file contains some utility functions and data structures used in the benchmarks.
 */
#define TO_MB(x) (x / (1024.0 * 1024.0))
#define TO_BPK(x, n) ((double)(x * 8) / n)

std::string uint64ToString(uint64_t key) {
    uint64_t endian_swapped_key = __builtin_bswap64(key);
    return std::string(reinterpret_cast<const char *>(&endian_swapped_key), 8);
}

uint64_t stringToUint64(const std::string &str_key) {
    uint64_t int_key = 0;
    memcpy(reinterpret_cast<char *>(&int_key), str_key.data(), 8);
    return __builtin_bswap64(int_key);
}

bool has_suffix(const std::string &str, const std::string &suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

using timer = std::chrono::high_resolution_clock;

template<typename KeyType>
using Workload = std::vector<std::tuple<KeyType, KeyType, bool>>;

template<typename KeyType>
using InputKeys = std::vector<KeyType>;

template<typename KeyType>
bool vector_range_query(const InputKeys<KeyType> &k, const KeyType left, const KeyType right) {
    auto lower = std::lower_bound(k.begin(), k.end(), left);
    // if true than the range is found in the original data
    bool is_found_query = !((lower == k.end()) || (*lower > right));
    return is_found_query;
}

template<typename KeyType>
bool vector_point_query(const InputKeys<KeyType> &k, const KeyType x) {
    auto lower = std::lower_bound(k.begin(), k.end(), x);
    if (lower == k.end())
        return false;
    return *lower == x;
}

template<typename KeyType>
std::vector<KeyType> read_data_binary(const std::string &filename, bool check_sorted=false) {
    std::vector<KeyType> data;

    try {
        std::fstream in(filename, std::ios::in | std::ios::binary);
        in.exceptions(std::ios::failbit | std::ios::badbit);
        KeyType size;
        in.read((char *) &size, sizeof(KeyType));
        data.resize(size);
        in.read((char *) data.data(), size * sizeof(KeyType));
    }
    catch (std::ios_base::failure &e) {
        std::cerr << "Could not read the file. " << e.what() << std::endl;
        exit(1);
    }
    if (check_sorted && !std::is_sorted(data.begin(), data.end())) {
        std::cerr << "Input data must be sorted." << std::endl;
        std::cerr << "Read: [";
        std::copy(data.begin(), std::min(data.end(), data.begin() + 10), std::ostream_iterator<KeyType>(std::cerr, ", "));
        std::cout << "...]." << std::endl;
        exit(1);
    }

    return data;
}

template<typename KeyType>
void write_to_binary_file(const KeyType &data, const std::string &path, bool write_size = true) {
    using value_type = typename KeyType::value_type;
    std::ofstream file(path, std::ios::out | std::ofstream::binary);
    if (write_size) {
        auto s = data.size();
        file.write(reinterpret_cast<const char *>(&s), sizeof(value_type));
    }
    file.write(reinterpret_cast<const char *>(data.data()), data.size() * sizeof(value_type));
}

template<typename KeyType>
static InputKeys<KeyType> read_keys_from_file(const std::string &f, uint64_t n_keys = UINT64_MAX) {
    std::ifstream k_file;
    k_file.open(f);
    if (k_file.fail())
        throw std::runtime_error("error, keys file not found");

    std::vector<KeyType> values;
    KeyType line;
    while (k_file >> line && n_keys-- > 0)
        values.push_back(line);

    k_file.close();

    auto ik = InputKeys<KeyType>(values.begin(), values.end());
    return ik;
}

template<typename KeyType>
static void save_workload_to_file(Workload<KeyType> &work, const std::string &l_keys, const std::string &r_keys = "") {
    std::ofstream outFile_l(l_keys, std::ios::trunc);
    if (r_keys.empty()) {
        for (const auto &e: work) {
            outFile_l << std::get<0>(e) << "\n";
        }
    } else {
        std::ofstream outFile_r(r_keys, std::ios::trunc);

        for (const auto &e: work) {
            outFile_l << std::get<0>(e) << "\n";
            outFile_r << std::get<1>(e) << "\n";
        }
        outFile_r.close();
    }
    outFile_l.close();
}

static inline void error_check(int ret)
{
  if (ret != 0) {
    std::cerr << "WiredTiger Error: " << wiredtiger_strerror(ret) << std::endl;
    exit(ret);
  }
}

static inline void insert_kv(WT_CURSOR* cursor, char* key, char* value)
{
  cursor->set_key(cursor, key);
  cursor->set_value(cursor, value);
  error_check(cursor->insert(cursor));
}

template<typename KeyType>
static void save_keys_to_file(InputKeys<KeyType> &keys, const std::string &file) {
    std::ofstream outFile(file, std::ios::trunc);

    for (const auto &e: keys) {
        outFile << e << "\n";
    }

    outFile.close();
}

template<typename KeyType>
static void save_keys_to_db(InputKeys<KeyType> &keys, const std::string &file) {

    std::cout<<"Writing Keys" << std::endl;
    std::string wt_home = file + "_wtdb";
    const uint32_t key_len = 8;
    const uint32_t val_len = 512;
    const uint32_t max_schema_len = 128;
    const uint32_t max_conn_config_len = 128;

    if (std::filesystem::exists(wt_home))
        std::filesystem::remove_all(wt_home);
    std::filesystem::create_directory(wt_home);

    WT_CONNECTION *conn;
    WT_SESSION *session;
    WT_CURSOR *cursor;
    char table_schema[max_schema_len];
    char connection_config[max_conn_config_len];

    sprintf(table_schema, "key_format=%lds,value_format=%lds", key_len, val_len);
    sprintf(connection_config, "create");

    error_check(wiredtiger_open(wt_home.c_str(), NULL, connection_config, &conn));
    error_check(conn->open_session(conn, NULL, NULL, &session));
    error_check(session->create(session, "table:bm", table_schema));
    error_check(session->open_cursor(session, "table:bm", NULL, NULL, &cursor));

    SimpleBigInt big_int_k(key_len), big_int_v(val_len);
    for (auto k : keys) {
      big_int_k = k;
      big_int_v.randomize();
      insert_kv(cursor, (char *) big_int_k.num, (char *) big_int_v.num);
    }
    error_check(conn->close(conn, NULL));
}

template<typename KeyType>
static Workload<KeyType> read_workload_from_file(const std::string &l_keys, const std::string &r_keys) {
    std::ifstream left_file, right_file;
    left_file.open(l_keys), right_file.open(r_keys);
    if (left_file.fail() || right_file.fail())
        throw std::runtime_error("error, queries file not found.");

    Workload<KeyType> work;

    KeyType lq, rq;
    while ((left_file >> lq) && (right_file >> rq)) {
        if (lq > rq)
            throw std::runtime_error("error, queries ranges are not ordered");
        work.push_back(std::make_pair(lq, rq));
    }
    left_file.close();
    right_file.close();

    return work;
}

template<typename KeyType>
static Workload<KeyType>
read_workload_from_file(const std::string &l_keys, KeyType max_range, InputKeys<KeyType> &keys) {
    std::ifstream left_file;
    left_file.open(l_keys);

    Workload<KeyType> work;

    KeyType line_left, line_right;
    while (left_file >> line_left) {
        // work.insert(std::make_tuple(line_left, line_left + max_range, keys.query(line_left, line_left + max_range)));
        work.push_back(std::make_pair(line_left, line_left + max_range));
    }
    left_file.close();

    return work;
}

class TestOutput {
    std::map<std::string, std::string> test_values;
    std::map<std::string, std::vector< std::pair<double, double> > > intrabench_values;

public:
    template<typename TestValueType>
    inline void add_measure(const std::string &key, TestValueType value) {
        auto str = std::to_string(value);
        if (key == "fpr" && str == "0.000000")
            str = "0.000001";

        test_values[key] = str;
    }

    inline void add_measure(const std::string &key, const std::string &value) {
        test_values[key] = value;
    }

    inline void add_intrabench_measure(const std::string &key, const double x, const double y) {
        intrabench_values[key].push_back(std::pair<double, double>(x, y));
    }

    inline void print() const {
        for (auto t: test_values) {
            std::cout << t.first << ": " << t.second << std::endl;
        }
    }

    auto operator[](const std::string &key) {
        return test_values[key];
    }

    std::string to_csv(bool print_header = true) {
        std::string s = "";

        if (print_header) {
            for (auto it = test_values.begin(); it != test_values.end(); ++it) {
                if (it != test_values.begin())
                    s += ",";
                s += (*it).first;
            }
            s += '\n';
        }

        for (auto it = test_values.begin(); it != test_values.end(); ++it) {
            if (it != test_values.begin())
                s += ",";
            s += (*it).second;
        }
        s += '\n';

        return s;
    }

    std::string intrabench_measures_to_json() {
        int measure_count = 0;
        std::string s = "{\n";
        for (auto it = intrabench_values.begin(); it != intrabench_values.end(); ++it) {
          if (measure_count) {
            s = s +",\n";
          }
          s = s + "\"" + it->first + "\": [\n";
          int point_count = 0;
          for (auto point : it->second) {
            if (point_count) s = s + ",\n";
            double x = point.first;
            double y = point.second;
            s = s + "{\"x\": ";
            s = s + std::to_string(x);
            s = s + ", \"y\": "; 
            s = s + std::to_string(y);
            s = s + "}";
            point_count++;
          }
          measure_count++;
          s = s + "]";
        }
        s = s + "}\n";
        return s;
    }
};
